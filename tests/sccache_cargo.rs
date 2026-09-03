//! System tests for compiling Rust code with cargo.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/

pub mod helpers;

use anyhow::{Context, Result};
use helpers::{CARGO, CRATE_DIR, cargo_clean, stop_sccache};

use assert_cmd::prelude::*;
use fs_err as fs;
use helpers::{SCCACHE_BIN, SccacheTest};
use predicates::prelude::*;
use serial_test::serial;
use std::ffi::{OsStr, OsString};
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
fn test_rust_cargo_build_across_basedirs() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    let first = test_info.tempdir.path().join("first");
    let second = test_info.tempdir.path().join("second");

    for root in [&first, &second] {
        write_basedirs_crate(root, "basedirs-test", 42)?;
        fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"{}\", basedirs_test::MANIFEST); }\n",
        )?;
    }
    let first = fs::canonicalize(first)?;
    let second = fs::canonicalize(second)?;

    stop_sccache()?;
    let config_path = test_info.tempdir.path().join("config");
    write_basedirs_config(&config_path, &[first.clone(), second.clone()])?;
    restart_sccache(
        &test_info,
        Some(vec![
            ("SCCACHE_CONF".into(), config_path.as_os_str().to_owned()),
            // The public launcher and daemon must both ignore this stale value.
            ("SCCACHE_BASEDIRS".into(), "relative/startup-value".into()),
        ]),
    )?;

    for root in [&first, &second] {
        cargo_build(&test_info, root, None, false)?;
    }

    let stdout = Command::new(CARGO.as_os_str())
        .args(["run", "--quiet", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .env("CARGO_TARGET_DIR", second.join("target"))
        .current_dir(&second)
        .assert()
        .try_success()?
        .get_output()
        .stdout
        .clone();
    let stdout =
        std::str::from_utf8(&stdout).context("cached Cargo binary output was not UTF-8")?;
    let reported = PathBuf::from(stdout.trim_end_matches(&['\r', '\n'][..]));
    let reported = fs::canonicalize(&reported)
        .with_context(|| format!("failed to canonicalize reported path {reported:?}"))?;
    assert_eq!(reported, first);

    write_basedirs_crate(&second, "basedirs-test", 43)?;
    cargo_build(&test_info, &second, None, false)?;

    test_info
        .show_stats()?
        .try_stdout(predicates::str::contains(r#""cache_hits":{"counts":{"Rust":1}"#).from_utf8())?
        .try_stdout(
            predicates::str::contains(r#""cache_misses":{"counts":{"Rust":2}"#).from_utf8(),
        )?
        .try_success()?;

    Ok(())
}

#[test]
#[serial]
fn test_request_basedirs_reuse_one_daemon() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    let roots = ["first", "second", "empty", "override"]
        .into_iter()
        .map(|name| test_info.tempdir.path().join(name))
        .collect::<Vec<_>>();

    for root in &roots {
        write_basedirs_crate(root, "request-basedirs-test", 42)?;
    }
    let roots = roots
        .into_iter()
        .map(fs::canonicalize)
        .collect::<std::io::Result<Vec<_>>>()?;
    let config_path = test_info.tempdir.path().join("config");
    write_basedirs_config(&config_path, &roots)?;
    restart_sccache(
        &test_info,
        Some(vec![(
            "SCCACHE_CONF".into(),
            config_path.as_os_str().to_owned(),
        )]),
    )?;

    let unrelated = fs::canonicalize(CRATE_DIR.as_os_str())?;
    for (client_side, answer) in [(false, 42), (true, 7)] {
        if client_side {
            // Force Cargo to invoke rustc again without restarting the daemon.
            for root in &roots {
                write_basedirs_crate(root, "request-basedirs-test", answer)?;
            }
        }
        zero_sccache_stats()?;

        // Normal mode sends each root with its request. Client-side mode omits
        // the override here and gets the file fallback through the daemon handshake.
        let first_basedir = (!client_side).then_some(roots[0].as_os_str());
        let second_basedir = (!client_side).then_some(roots[1].as_os_str());
        cargo_build(&test_info, &roots[0], first_basedir, client_side)?;
        cargo_build(&test_info, &roots[1], second_basedir, client_side)?;

        // Both roots are in the file fallback. An empty or nonmatching request
        // override must replace that fallback, so these are misses rather than hits.
        cargo_build(&test_info, &roots[2], Some(OsStr::new("")), client_side)?;
        cargo_build(
            &test_info,
            &roots[3],
            Some(unrelated.as_os_str()),
            client_side,
        )?;

        test_info
            .show_stats()?
            .try_stdout(
                predicates::str::contains(r#""cache_hits":{"counts":{"Rust":1}"#).from_utf8(),
            )?
            .try_stdout(
                predicates::str::contains(r#""cache_misses":{"counts":{"Rust":3}"#).from_utf8(),
            )?
            .try_stdout(predicate::function(|output: &[u8]| {
                serde_json::from_slice::<serde_json::Value>(output)
                    .ok()
                    .and_then(|stats| stats["basedirs"].as_array().map(Vec::len))
                    == Some(4)
            }))?
            .try_success()?;
    }

    Ok(())
}

#[test]
#[serial]
fn test_show_stats_without_daemon_uses_file_basedirs() -> Result<()> {
    #[cfg(target_os = "windows")]
    let (configured, expected) = ("C:/configured/fallback", "c:/configured/fallback/");
    #[cfg(not(target_os = "windows"))]
    let (configured, expected) = ("/configured/fallback", "/configured/fallback/");

    let tempdir = tempfile::Builder::new()
        .prefix("sccache_test_show_stats_basedirs")
        .tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir)?;
    let config_path = tempdir.path().join("config");
    fs::write(&config_path, format!("basedirs = [{configured:?}]\n"))?;

    stop_sccache()?;
    Command::new(SCCACHE_BIN.as_os_str())
        .args(["--show-stats", "--stats-format=json"])
        .env("SCCACHE_DIR", &cache_dir)
        .env("SCCACHE_CONF", &config_path)
        .env("SCCACHE_BASEDIRS", "relative/request-value")
        .assert()
        .try_stdout(predicates::str::contains(format!(r#""basedirs":["{expected}"]"#)).from_utf8())?
        .try_success()?;

    Ok(())
}

#[test]
#[serial]
fn test_concurrent_request_basedirs_do_not_leak() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    let first_a = test_info.tempdir.path().join("first-a");
    let second_a = test_info.tempdir.path().join("second-a");
    let first_b = test_info.tempdir.path().join("first-b");
    let second_b = test_info.tempdir.path().join("second-b");

    for root in [&first_a, &second_a] {
        write_basedirs_crate(root, "concurrent-basedirs-a", 42)?;
    }
    for root in [&first_b, &second_b] {
        write_basedirs_crate(root, "concurrent-basedirs-b", 7)?;
    }
    let first_a = fs::canonicalize(first_a)?;
    let second_a = fs::canonicalize(second_a)?;
    let first_b = fs::canonicalize(first_b)?;
    let second_b = fs::canonicalize(second_b)?;

    cargo_build(&test_info, &first_a, Some(first_a.as_os_str()), false)?;
    cargo_build(&test_info, &first_b, Some(first_b.as_os_str()), false)?;
    zero_sccache_stats()?;

    let mut build_a =
        cargo_build_command(&test_info, &second_a, Some(second_a.as_os_str()), false).spawn()?;
    let mut build_b =
        cargo_build_command(&test_info, &second_b, Some(second_b.as_os_str()), false).spawn()?;
    assert!(build_a.wait()?.success());
    assert!(build_b.wait()?.success());

    test_info
        .show_stats()?
        .try_stdout(predicates::str::contains(r#""cache_hits":{"counts":{"Rust":2}"#).from_utf8())?
        .try_stdout(predicates::str::contains(r#""cache_misses":{"counts":{}"#).from_utf8())?
        .try_success()?;

    Ok(())
}

fn write_basedirs_crate(root: &Path, name: &str, answer: u32) -> Result<()> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
    )?;
    fs::write(
        root.join("src/lib.rs"),
        format!(
            "pub const MANIFEST: &str = env!(\"CARGO_MANIFEST_DIR\");\npub fn answer() -> u32 {{ {answer} }}\n"
        ),
    )?;
    Ok(())
}

fn write_basedirs_config(config_path: &Path, basedirs: &[PathBuf]) -> Result<()> {
    let basedirs = basedirs
        .iter()
        .map(|path| format!("{:?}", path.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(config_path, format!("basedirs = [{basedirs}]\n"))?;
    Ok(())
}

fn zero_sccache_stats() -> Result<()> {
    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--zero-stats")
        .assert()
        .try_success()?;
    Ok(())
}

fn cargo_build_command(
    test_info: &SccacheTest,
    root: &Path,
    basedirs: Option<&OsStr>,
    client_side: bool,
) -> Command {
    let mut command = Command::new(CARGO.as_os_str());
    command
        .args(["build", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env_remove("SCCACHE_BASEDIRS")
        .env_remove("SCCACHE_CLIENT_SIDE")
        .current_dir(root);
    if let Some(basedirs) = basedirs {
        command.env("SCCACHE_BASEDIRS", basedirs);
    }
    if client_side {
        command.env("SCCACHE_CLIENT_SIDE", "1");
    }
    command
}

fn cargo_build(
    test_info: &SccacheTest,
    root: &Path,
    basedirs: Option<&OsStr>,
    client_side: bool,
) -> Result<()> {
    cargo_build_command(test_info, root, basedirs, client_side)
        .assert()
        .try_success()?;
    Ok(())
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
    additional_envs: Option<Vec<(OsString, OsString)>>,
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
