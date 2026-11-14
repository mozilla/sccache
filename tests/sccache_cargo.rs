//! System tests for compiling Rust code with cargo.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/

pub mod helpers;

use anyhow::{Context, Result, bail};
use helpers::{CARGO, CRATE_DIR, cargo_clean, stop_sccache};

use assert_cmd::prelude::*;
use fs_err as fs;
use helpers::{SCCACHE_BIN, SccacheTest};
use predicates::prelude::*;
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::Command;

#[macro_use]
extern crate log;

#[test]
#[serial]
fn test_rust_cargo_check() -> Result<()> {
    test_rust_cargo_cmd("check", SccacheTest::new(None)?)
}

#[test]
#[serial]
fn test_rust_cargo_check_readonly() -> Result<()> {
    test_rust_cargo_cmd_readonly("check", SccacheTest::new(None)?)
}

#[test]
#[serial]
fn test_rust_cargo_build() -> Result<()> {
    test_rust_cargo_cmd("build", SccacheTest::new(None)?)
}

#[test]
#[serial]
fn test_rust_cargo_build_readonly() -> Result<()> {
    test_rust_cargo_cmd_readonly("build", SccacheTest::new(None)?)
}

#[test]
#[serial]
#[cfg(unix)]
fn test_run_log_no_perm() -> Result<()> {
    trace!("sccache with log");
    stop_sccache()?;
    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("gcc")
        .env("SCCACHE_ERROR_LOG", "/no-perm.log") // Should not work
        .env("SCCACHE_LOG", "debug");

    cmd.assert().failure().stderr(predicate::str::contains(
        "Cannot open/write log file '/no-perm.log'",
    ));
    Ok(())
}

#[test]
#[serial]
fn test_run_log() -> Result<()> {
    trace!("sccache with log");
    stop_sccache()?;

    let tempdir = tempfile::Builder::new()
        .prefix("sccache_test_rust_cargo")
        .tempdir()
        .context("Failed to create tempdir")?;
    let tmppath = tempdir.path().join("perm.log");
    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--start-server")
        .env("SCCACHE_ERROR_LOG", &tmppath) // Should not work
        .env("SCCACHE_LOG", "debug");

    cmd.assert().success();
    stop_sccache()?;
    assert!(Path::new(&tmppath).is_file());
    Ok(())
}

/// This test checks that changing an environment variable reference by env! is detected by
/// sccache, causes a rebuild and is correctly printed to stdout.
#[test]
#[serial]
fn test_rust_cargo_run_with_env_dep_parsing() -> Result<()> {
    test_rust_cargo_env_dep(SccacheTest::new(None)?)
}

#[cfg(feature = "unstable")]
#[test]
#[serial]
fn test_rust_cargo_check_nightly() -> Result<()> {
    use std::ffi::OsString;

    test_rust_cargo_cmd(
        "check",
        SccacheTest::new(Some(&[(
            "RUSTFLAGS",
            OsString::from("-Cprofile-generate=."),
        )]))?,
    )
}

#[cfg(feature = "unstable")]
#[test]
#[serial]
fn test_rust_cargo_check_nightly_readonly() -> Result<()> {
    use std::ffi::OsString;

    test_rust_cargo_cmd_readonly(
        "check",
        SccacheTest::new(Some(&[(
            "RUSTFLAGS",
            OsString::from("-Cprofile-generate=."),
        )]))?,
    )
}

#[cfg(feature = "unstable")]
#[test]
#[serial]
fn test_rust_cargo_build_nightly() -> Result<()> {
    use std::ffi::OsString;

    test_rust_cargo_cmd(
        "build",
        SccacheTest::new(Some(&[(
            "RUSTFLAGS",
            OsString::from("-Cprofile-generate=."),
        )]))?,
    )
}

#[cfg(feature = "unstable")]
#[test]
#[serial]
fn test_rust_cargo_build_nightly_readonly() -> Result<()> {
    use std::ffi::OsString;

    test_rust_cargo_cmd_readonly(
        "build",
        SccacheTest::new(Some(&[(
            "RUSTFLAGS",
            OsString::from("-Cprofile-generate=."),
        )]))?,
    )
}

/// Test that building a simple Rust crate with cargo using sccache results in a cache hit
/// when built a second time and a cache miss, when the environment variable referenced via
/// env! is changed.
fn test_rust_cargo_cmd(cmd: &str, test_info: SccacheTest) -> Result<()> {
    // `cargo clean` first, just to be sure there's no leftover build objects.
    cargo_clean(&test_info)?;

    // Now build the crate with cargo.
    Command::new(CARGO.as_os_str())
        .args([cmd, "--color=never"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8().not())?
        .try_success()?;
    // Clean it so we can build it again.
    cargo_clean(&test_info)?;
    Command::new(CARGO.as_os_str())
        .args([cmd, "--color=always"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8())?
        .try_success()?;

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(
                r#""cache_hits":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_success()?;

    Ok(())
}

fn restart_sccache(
    test_info: &SccacheTest,
    additional_envs: Option<Vec<(String, String)>>,
) -> Result<()> {
    let cache_dir = test_info.tempdir.path().join("cache");

    stop_sccache()?;

    trace!("sccache --start-server");

    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--start-server");
    cmd.env("SCCACHE_DIR", &cache_dir);

    if let Some(additional_envs) = additional_envs {
        cmd.envs(additional_envs);
    }

    cmd.assert()
        .try_success()
        .context("Failed to start sccache server")?;

    Ok(())
}

/// Test that building a simple Rust crate with cargo using sccache results in the following behaviors (for three different runs):
/// - In read-only mode, a cache miss.
/// - In read-write mode, a cache miss.
/// - In read-only mode, a cache hit.
///
/// The environment variable for read/write mode is added by this function.
fn test_rust_cargo_cmd_readonly(cmd: &str, test_info: SccacheTest) -> Result<()> {
    // `cargo clean` first, just to be sure there's no leftover build objects.
    cargo_clean(&test_info)?;

    // The cache must be put into read-only mode, and that can only be configured
    // when the server starts up, so we need to restart it.
    restart_sccache(
        &test_info,
        Some(vec![("SCCACHE_LOCAL_RW_MODE".into(), "READ_ONLY".into())]),
    )?;

    // Now build the crate with cargo.
    Command::new(CARGO.as_os_str())
        .args([cmd, "--color=never"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8().not())?
        .try_success()?;

    // Stats reset on server restart, so this needs to be run for each build.
    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(r#""cache_hits":{"counts":{},"adv_counts":{}}"#).from_utf8(),
        )?
        .try_stdout(
            predicates::str::contains(
                r#""cache_misses":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_success()?;

    cargo_clean(&test_info)?;
    restart_sccache(
        &test_info,
        Some(vec![("SCCACHE_LOCAL_RW_MODE".into(), "READ_WRITE".into())]),
    )?;
    Command::new(CARGO.as_os_str())
        .args([cmd, "--color=always"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8())?
        .try_success()?;

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(r#""cache_hits":{"counts":{},"adv_counts":{}}"#).from_utf8(),
        )?
        .try_stdout(
            predicates::str::contains(
                r#""cache_misses":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_success()?;

    cargo_clean(&test_info)?;
    restart_sccache(
        &test_info,
        Some(vec![("SCCACHE_LOCAL_RW_MODE".into(), "READ_ONLY".into())]),
    )?;
    Command::new(CARGO.as_os_str())
        .args([cmd, "--color=always"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8())?
        .try_success()?;

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(
                r#""cache_hits":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_stdout(
            predicates::str::contains(r#""cache_misses":{"counts":{},"adv_counts":{}}"#)
                .from_utf8(),
        )?
        .try_success()?;

    Ok(())
}

fn test_rust_cargo_env_dep(test_info: SccacheTest) -> Result<()> {
    cargo_clean(&test_info)?;
    // Now build the crate with cargo.
    Command::new(CARGO.as_os_str())
        .args(["run", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8().not())?
        .try_stdout(predicates::str::contains("Env var: 1"))?
        .try_success()?;
    // Clean it so we can build it again.
    cargo_clean(&test_info)?;

    Command::new(CARGO.as_os_str())
        .args(["run", "--color=always"])
        .envs(test_info.env.iter().cloned())
        .env("TEST_ENV_VAR", "OTHER_VALUE")
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8())?
        .try_stdout(predicates::str::contains("Env var: OTHER_VALUE"))?
        .try_success()?;

    // Now get the stats and ensure that we had one cache hit for the second build.
    // The test crate has one dependency (itoa) so there are two separate compilations, but only
    // itoa should be cached (due to the changed environment variable).
    test_info
        .show_stats()?
        .try_stdout(predicates::str::contains(r#""cache_hits":{"counts":{"Rust":1}"#).from_utf8())?
        .try_success()?;

    drop(test_info);
    Ok(())
}

/// Test that building a simple Rust crate with cargo using sccache in read-only mode with an empty cache results in
/// a cache miss that is produced by the readonly storage wrapper (and does not attempt to write to the underlying cache).
#[test]
#[serial]
fn test_rust_cargo_cmd_readonly_preemtive_block() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    // `cargo clean` first, just to be sure there's no leftover build objects.
    cargo_clean(&test_info)?;

    let sccache_log = test_info.tempdir.path().join("sccache.log");

    stop_sccache()?;

    restart_sccache(
        &test_info,
        Some(vec![
            ("SCCACHE_LOCAL_RW_MODE".into(), "READ_ONLY".into()),
            ("SCCACHE_LOG".into(), "trace".into()),
            (
                "SCCACHE_ERROR_LOG".into(),
                sccache_log.to_str().unwrap().into(),
            ),
        ]),
    )?;

    // Now build the crate with cargo.
    // Assert that our cache miss is due to the readonly storage wrapper, not due to the underlying disk cache.
    Command::new(CARGO.as_os_str())
        .args(["build", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8().not())?
        .try_success()?;

    let log_contents = fs::read_to_string(sccache_log)?;
    assert!(
        predicates::str::contains("server has setup with ReadOnly").eval(log_contents.as_str())
    );
    assert!(
        predicates::str::contains("Error executing cache write: Cannot write to read-only storage")
            .eval(log_contents.as_str())
    );
    assert!(
        predicates::str::contains("DiskCache::finish_put")
            .not()
            .eval(log_contents.as_str())
    );

    // Stats reset on server restart, so this needs to be run for each build.
    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(r#""cache_hits":{"counts":{},"adv_counts":{}}"#).from_utf8(),
        )?
        .try_stdout(
            predicates::str::contains(
                r#""cache_misses":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_success()?;
    Ok(())
}

/// Copy the test crate to `name` under the test tempdir
/// and build it there with its own target directory.
///
/// Returns the checkout's target directory.
fn build_checkout(test_info: &SccacheTest, name: &str) -> Result<PathBuf> {
    let checkout = test_info.tempdir.path().join(name);
    fs::create_dir_all(checkout.join("src"))?;
    for file in ["Cargo.toml", "Cargo.lock", "src/lib.rs", "src/bin.rs"] {
        fs::copy(CRATE_DIR.join(file), checkout.join(file))?;
    }
    cargo_build(test_info, &checkout)
}

/// Build the crate in `checkout` with its own target directory.
///
/// Returns the checkout's target directory.
fn cargo_build(test_info: &SccacheTest, checkout: &Path) -> Result<PathBuf> {
    let target_dir = checkout.join("target");
    Command::new(CARGO.as_os_str())
        // `--target-dir` rather than `CARGO_TARGET_DIR`,
        // since cargo forwards `CARGO_*` to rustc and sccache hashes them.
        .args(["build", "--color=never", "--target-dir"])
        .arg(&target_dir)
        .envs(test_info.env.iter().cloned())
        .current_dir(checkout)
        .assert()
        .try_success()?;
    Ok(target_dir)
}

/// Read the dep-info file cargo keeps for the crate `name` under `target_dir`.
fn read_dep_info(target_dir: &Path, name: &str) -> Result<String> {
    /// Search rather than assume `target/debug/deps`,
    /// since cargo changed the build-dir layout in rust-lang/cargo#15010.
    fn collect(dir: &Path, prefix: &str, found: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                collect(&path, prefix, found)?;
            } else if path.extension().is_some_and(|e| e == "d")
                && path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(prefix))
            {
                found.push(path);
            }
        }
        Ok(())
    }

    let mut found = Vec::new();
    collect(target_dir, &format!("{name}-"), &mut found)?;
    found.sort();

    // One profile and no `--target`, so the crate is built exactly once.
    match found.as_slice() {
        [dep_info] => Ok(fs::read_to_string(dep_info)?),
        [] => bail!("no {name} dep-info file under {}", target_dir.display()),
        _ => bail!(
            "several {name} dep-info files under {}: {found:?}",
            target_dir.display()
        ),
    }
}

/// The same dependency built from two checkouts, the second one being a cache hit.
/// Whose paths does the second checkout's dep-info name? (mozilla/sccache#984)
#[test]
#[serial]
fn test_rust_cargo_dep_info_from_other_checkout() -> Result<()> {
    let test_info = SccacheTest::new(None)?;

    let target_a = build_checkout(&test_info, "a")?;
    let target_b = build_checkout(&test_info, "b")?;

    // Only `itoa` is shared;
    // the crate's own lib and bin are keyed on their differing cwd.
    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(
                r#""cache_hits":{"counts":{"Rust":1},"adv_counts":{"rust":1}}"#,
            )
            .from_utf8(),
        )?
        .try_success()?;

    let dep_info = read_dep_info(&target_b, "itoa")?;
    assert!(
        !dep_info.contains(target_a.to_str().unwrap()),
        "dep-info names checkout a:\n{dep_info}"
    );
    assert!(
        dep_info.contains(target_b.to_str().unwrap()),
        "dep-info does not name checkout b:\n{dep_info}"
    );
    Ok(())
}

/// Write a crate to `checkout` whose path dependency includes build script output,
/// so the checkout's path reaches both crates' keys through the cwd,
/// `CARGO_MANIFEST_DIR` and the dependency's `OUT_DIR` env-dep.
fn write_out_dir_crate(checkout: &Path) -> Result<()> {
    let package = |name: &str| {
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
    };
    fs::create_dir_all(checkout.join("src"))?;
    fs::create_dir_all(checkout.join("dep/src"))?;
    fs::write(
        checkout.join("Cargo.toml"),
        package("out-dir-test") + "\n[dependencies]\ndep = { path = \"dep\" }\n",
    )?;
    fs::write(
        checkout.join("src/lib.rs"),
        "pub fn answer() -> u32 { dep::ANSWER }\n",
    )?;
    fs::write(checkout.join("dep/Cargo.toml"), package("dep"))?;
    fs::write(
        checkout.join("dep/build.rs"),
        r#"fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("answer.rs"), "pub const ANSWER: u32 = 42;").unwrap();
}
"#,
    )?;
    fs::write(
        checkout.join("dep/src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/answer.rs\"));\n",
    )?;
    Ok(())
}

/// The test's tempdir by its real path, which is how cargo names it in `CARGO_MANIFEST_DIR`
/// and `[env]` paths; on macOS the tempdir is under a symlink to /private.
fn real_tempdir(test_info: &SccacheTest) -> Result<PathBuf> {
    let path = test_info.tempdir.path();
    if cfg!(unix) {
        Ok(fs::canonicalize(path)?)
    } else {
        Ok(path.to_owned())
    }
}

/// A crate and its path dependency, built from two checkouts listed in `SCCACHE_BASEDIRS`,
/// hit in the second one, whose dep-info still names its own files.
#[test]
#[serial]
fn test_rust_cargo_basedirs_other_checkout() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    let tempdir = real_tempdir(&test_info)?;
    let [a, b] = ["a", "b"].map(|name| tempdir.join(name));
    let basedirs = std::env::join_paths([&a, &b])?.into_string().unwrap();
    restart_sccache(
        &test_info,
        Some(vec![("SCCACHE_BASEDIRS".into(), basedirs)]),
    )?;

    write_out_dir_crate(&a)?;
    cargo_build(&test_info, &a)?;
    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--zero-stats")
        .assert()
        .try_success()?;
    write_out_dir_crate(&b)?;
    let target_b = cargo_build(&test_info, &b)?;

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(
                r#""cache_hits":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_stdout(
            predicates::str::contains(r#""cache_misses":{"counts":{},"adv_counts":{}}"#)
                .from_utf8(),
        )?
        .try_success()?;

    let dep_info = read_dep_info(&target_b, "dep")?;
    assert!(
        !dep_info.contains(a.to_str().unwrap()),
        "dep-info names checkout a:\n{dep_info}"
    );
    assert!(
        dep_info.contains(b.to_str().unwrap()),
        "dep-info does not name checkout b:\n{dep_info}"
    );

    Ok(())
}

/// Test that without `SCCACHE_ALLOW_INCREMENTAL`, enabling cargo's incremental
/// compilation still makes sccache refuse to run.
#[test]
#[serial]
fn test_rust_cargo_incremental_refused_by_default() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    // Clean before setting the env var below: the refusal fires on any rustc
    // invocation, including the `rustc -vV` probe `cargo clean` makes.
    cargo_clean(&test_info)?;

    Command::new(CARGO.as_os_str())
        .args(["build", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .env("CARGO_INCREMENTAL", "1")
        // Explicitly off, so the default is still tested on a machine that opted
        // in globally (`.env_remove` cannot undo cargo's `[env]` table).
        .env("SCCACHE_ALLOW_INCREMENTAL", "0")
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("incremental compilation is prohibited").from_utf8())?
        .try_failure()?;

    Ok(())
}

/// Test that with `SCCACHE_ALLOW_INCREMENTAL` an incremental build succeeds and
/// splits per invocation: the workspace crates cargo hands `-C incremental=`
/// bypass the cache, while its registry dependencies keep hitting it.
#[test]
#[serial]
fn test_rust_cargo_incremental_allowed_deps_cached() -> Result<()> {
    let test_info = SccacheTest::new(None)?;

    // Two incremental builds, each from a clean target.
    for _ in 0..2 {
        cargo_clean(&test_info)?;
        Command::new(CARGO.as_os_str())
            .args(["build", "--color=never"])
            .envs(test_info.env.iter().cloned())
            .env("CARGO_INCREMENTAL", "1")
            .env("SCCACHE_ALLOW_INCREMENTAL", "1")
            .current_dir(CRATE_DIR.as_os_str())
            .assert()
            .try_success()?;
    }

    // The workspace lib really went through rustc's incremental machinery.
    let incremental_dir = test_info.tempdir.path().join("cargo/debug/incremental");
    let has_mylib_session = std::fs::read_dir(&incremental_dir)?
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("mylib"));
    assert!(
        has_mylib_session,
        "expected an incremental session dir for `mylib` in {incremental_dir:?}"
    );

    test_info
        .show_stats()?
        // itoa: one miss (first build), one hit (second build).
        .try_stdout(predicates::str::contains(r#""cache_hits":{"counts":{"Rust":1}"#).from_utf8())?
        .try_stdout(
            predicates::str::contains(
                r#""cache_misses":{"counts":{"Rust":1},"adv_counts":{"rust":1}}"#,
            )
            .from_utf8(),
        )?
        // The workspace lib bypassed the cache in both builds. `mybin` is rejected
        // on `--crate-type bin` first, which cargo passes ahead of the flag.
        .try_stdout(predicates::str::contains(r#""incremental":2"#).from_utf8())?
        .try_success()?;

    Ok(())
}

/// Test that a crate using a proc-macro hits the cache when the proc-macro was built into a
/// different target directory. On macOS the linker writes the proc-macro dylib's own path into
/// it, so hashing the whole file gave every target directory its own key.
#[test]
#[serial]
fn test_rust_cargo_proc_macro_in_another_target_dir() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    let root = test_info.tempdir.path();
    let src = root.join("src");
    fs::create_dir_all(src.join("pm/src"))?;
    fs::create_dir_all(src.join("user/src"))?;
    fs::write(
        src.join("Cargo.toml"),
        r#"[workspace]
        members = ["pm", "user"]
        resolver = "2"
        "#,
    )?;
    fs::write(
        src.join("pm/Cargo.toml"),
        r#"[package]
        name = "pm"
        version = "0.1.0"
        edition = "2021"
        [lib]
        proc-macro = true
        "#,
    )?;
    fs::write(
        src.join("pm/src/lib.rs"),
        r#"use proc_macro::TokenStream;
        #[proc_macro]
        pub fn answer(_: TokenStream) -> TokenStream {
            "42".parse().unwrap()
        }
        "#,
    )?;
    fs::write(
        src.join("user/Cargo.toml"),
        r#"[package]
        name = "user"
        version = "0.1.0"
        edition = "2021"
        [dependencies]
        pm = { path = "../pm" }
        "#,
    )?;
    fs::write(
        src.join("user/src/lib.rs"),
        "pub fn answer() -> u32 { pm::answer!() }\n",
    )?;

    // The target directory goes on the command line, because sccache hashes every `CARGO_*`
    // variable and an exported CARGO_TARGET_DIR would itself make the keys differ.
    let env = test_info
        .env
        .iter()
        .filter(|(var, _)| *var != "CARGO_TARGET_DIR")
        .cloned()
        .collect::<Vec<_>>();
    for target_dir in ["t1", "target-two"] {
        Command::new(CARGO.as_os_str())
            .args(["build", "--color=never", "--target-dir"])
            .arg(root.join(target_dir))
            .envs(env.iter().cloned())
            .current_dir(&src)
            .assert()
            .try_success()?;
    }

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(
                r#""cache_hits":{"counts":{"Rust":1},"adv_counts":{"rust":1}}"#,
            )
            .from_utf8(),
        )?
        .try_success()?;
    Ok(())
}

#[test]
#[serial]
fn test_rust_cargo_basedirs_per_build() -> Result<()> {
    test_rust_cargo_basedirs_per_build_mode(&[])
}

#[test]
#[serial]
fn test_rust_cargo_basedirs_per_build_client_side() -> Result<()> {
    test_rust_cargo_basedirs_per_build_mode(&[("SCCACHE_CLIENT_SIDE", "1".into())])
}

/// Two checkouts that each name their own root in `SCCACHE_BASEDIRS`
/// through cargo's `[env]`, with a server started without basedirs:
/// the second checkout hits.
fn test_rust_cargo_basedirs_per_build_mode(
    envs: &[(&'static str, std::ffi::OsString)],
) -> Result<()> {
    let test_info = SccacheTest::new(Some(envs))?;
    let tempdir = real_tempdir(&test_info)?;
    let [a, b] = ["a", "b"].map(|name| tempdir.join(name));
    for checkout in [&a, &b] {
        write_out_dir_crate(checkout)?;
        fs::create_dir_all(checkout.join(".cargo"))?;
        fs::write(
            checkout.join(".cargo/config.toml"),
            "[env]\nSCCACHE_BASEDIRS = { value = \"\", relative = true }\n",
        )?;
    }

    cargo_build(&test_info, &a)?;
    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--zero-stats")
        .assert()
        .try_success()?;
    cargo_build(&test_info, &b)?;

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(
                r#""cache_hits":{"counts":{"Rust":2},"adv_counts":{"rust":2}}"#,
            )
            .from_utf8(),
        )?
        .try_stdout(
            predicates::str::contains(r#""cache_misses":{"counts":{},"adv_counts":{}}"#)
                .from_utf8(),
        )?
        .try_success()?;
    Ok(())
}
