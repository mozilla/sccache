//! System tests for compiling Rust code with cargo.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/

#![deny(rust_2018_idioms)]

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
#[macro_use]
extern crate log;

/// Test that building a simple Rust crate with cargo using sccache results in a cache hit
/// when built a second time.
#[test]
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn test_rust_cargo() {
    test_rust_cargo_cmd("check");
    test_rust_cargo_cmd("build");
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn test_rust_cargo_cmd(cmd: &str) {
    use assert_cmd::prelude::*;
    use chrono::Local;
    use predicates::prelude::*;
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn sccache_command() -> Command {
        Command::new(assert_cmd::cargo::cargo_bin("sccache"))
    }

    fn stop() {
        trace!("sccache --stop-server");
        drop(
            sccache_command()
                .arg("--stop-server")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        );
    }

    let _ = env_logger::Builder::new()
        .format(|f, record| {
            write!(
                f,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .parse_env("RUST_LOG")
        .try_init();

    let cargo = env!("CARGO");
    debug!("cargo: {}", cargo);
    let sccache = assert_cmd::cargo::cargo_bin("sccache");
    debug!("sccache: {:?}", sccache);
    let crate_dir = Path::new(file!()).parent().unwrap().join("test-crate");
    // Ensure there's no existing sccache server running.
    stop();
    // Create a temp directory to use for the disk cache.
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_test_rust_cargo")
        .tempdir()
        .unwrap();
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
    let envs = vec![
        ("RUSTC_WRAPPER", &sccache),
        ("CARGO_TARGET_DIR", &cargo_dir),
    ];
    Command::new(&cargo)
        .args(&["clean"])
        .envs(envs.iter().copied())
        .current_dir(&crate_dir)
        .assert()
        .success();
    // Now build the crate with cargo.
    Command::new(&cargo)
        .args(&[cmd, "--color=never"])
        .envs(envs.iter().copied())
        .current_dir(&crate_dir)
        .assert()
        .stderr(predicates::str::contains("\x1b[").from_utf8().not())
        .success();
    // Clean it so we can build it again.
    Command::new(&cargo)
        .args(&["clean"])
        .envs(envs.iter().copied())
        .current_dir(&crate_dir)
        .assert()
        .success();
    Command::new(&cargo)
        .args(&[cmd, "--color=always"])
        .envs(envs.iter().copied())
        .current_dir(&crate_dir)
        .assert()
        .stderr(predicates::str::contains("\x1b[").from_utf8())
        .success();
    // Now get the stats and ensure that we had a cache hit for the second build.
    // Ideally we'd check the stats more usefully here--the test crate has one dependency (itoa)
    // so there are two separate compilations, but cargo will build the test crate with
    // incremental compilation enabled, so sccache will not cache it.
    trace!("sccache --show-stats");
    let child = sccache_command()
        .args(&["--show-stats", "--stats-format=json"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Launching process must work. Q.E.D.");

    let output = child
        .wait_with_output()
        .expect("Reading stdout in test always works. Q.E.D.");
    let output = String::from_utf8_lossy(&output.stdout);

    use std::str::FromStr;

    let re = regex::Regex::new(r#""cache_hits":\{"counts":\{"Rust":\s*([0-9]+)\s*\}\}"#)
        .expect("Provided regex is good. Q.E.D.");
    let captures = re
        .captures(&output)
        .expect("Must have a capture for provided regex. Q.E.D.");
    assert_eq!(captures.len(), 2); // the full string and the actual first group
    let mut iter = captures.iter();
    let _ = iter.next();
    let m = iter
        .next()
        .expect("Must have a number for cached rust compiles. Q.E.D.")
        .unwrap();
    let cached_rust_compilations = usize::from_str(m.as_str()).unwrap();
    assert!(cached_rust_compilations >= 1);

    stop();
}
