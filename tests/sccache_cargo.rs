//! System tests for compiling Rust code with cargo.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/

extern crate assert_cmd;
extern crate chrono;
extern crate env_logger;
extern crate escargot;
#[cfg(not(target_os="macos"))]
#[macro_use]
extern crate log;
extern crate predicates;
extern crate tempdir;

/// Test that building a simple Rust crate with cargo using sccache results in a cache hit
/// when built a second time.
#[test]
#[cfg(not(target_os="macos"))] // test currently fails on macos
fn test_rust_cargo() {
    test_rust_cargo_cmd("check");
    test_rust_cargo_cmd("build");
}

#[cfg(not(target_os="macos"))] // test currently fails on macos
fn test_rust_cargo_cmd(cmd: &str) {
    use std::env;
    use std::io::Write;
    use std::fs;
    use std::path::Path;
    use assert_cmd::prelude::*;
    use chrono::Local;
    use escargot::CargoBuild;
    use predicates::prelude::*;
    use std::process::{Command, Stdio};
    use tempdir::TempDir;

    fn sccache_command() -> Command {
        CargoBuild::new()
            .bin("sccache")
            .current_release()
            .current_target()
            .run()
            .unwrap()
            .command()
    }

    fn stop() {
        trace!("sccache --stop-server");
        drop(sccache_command()
            .arg("--stop-server")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status());
    }

    drop(env_logger::Builder::new()
         .format(|f, record| {
             write!(
                 f,
                 "{} [{}] - {}",
                 Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                 record.level(),
                 record.args()
             )
         })
        .parse(&env::var("RUST_LOG").unwrap_or_default())
        .try_init());
    let cargo = env!("CARGO");
    debug!("cargo: {}", cargo);
    #[allow(deprecated)]
    let sccache = assert_cmd::cargo::main_binary_path().unwrap();
    debug!("sccache: {:?}", sccache);
    let crate_dir = Path::new(file!()).parent().unwrap().join("test-crate");
    // Ensure there's no existing sccache server running.
    stop();
    // Create a temp directory to use for the disk cache.
    let tempdir = TempDir::new("sccache_test_rust_cargo").unwrap();
    let cache_dir = tempdir.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    let cargo_dir = tempdir.path().join("cargo");
    fs::create_dir(&cargo_dir).unwrap();
    // Start a new sccache server.
    trace!("sccache --start-server");
    sccache_command()
        .arg("--start-server")
        .env("SCCACHE_DIR", &cache_dir)
        .assert()
        .success();
    // `cargo clean` first, just to be sure there's no leftover build objects.
    let envs = vec![("RUSTC_WRAPPER", &sccache),
                    ("CARGO_TARGET_DIR", &cargo_dir)];
    Command::new(&cargo)
        .args(&["clean"])
        .envs(envs.iter().map(|v| *v))
        .current_dir(&crate_dir)
        .assert()
        .success();
    // Now build the crate with cargo.
    Command::new(&cargo)
        .args(&[cmd, "--color=never"])
        .envs(envs.iter().map(|v| *v))
        .current_dir(&crate_dir)
        .assert()
        .stderr(predicates::str::contains("\x1b[").from_utf8().not())
        .success();
    // Clean it so we can build it again.
    Command::new(&cargo)
        .args(&["clean"])
        .envs(envs.iter().map(|v| *v))
        .current_dir(&crate_dir)
        .assert()
        .success();
    Command::new(&cargo)
        .args(&[cmd, "--color=always"])
        .envs(envs.iter().map(|v| *v))
        .current_dir(&crate_dir)
        .assert()
        .stderr(predicates::str::contains("\x1b[").from_utf8())
        .success();
    // Now get the stats and ensure that we had a cache hit for the second build.
    // Ideally we'd check the stats more usefully here--the test crate has one dependency (itoa)
    // so there are two separate compilations, but cargo will build the test crate with
    // incremental compilation enabled, so sccache will not cache it.
    trace!("sccache --show-stats");
    sccache_command()
        .args(&["--show-stats", "--stats-format=json"])
        .assert()
        .stdout(predicates::str::contains(r#""cache_hits":1"#).from_utf8())
        .success();
    stop();
}
