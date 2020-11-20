//! System tests for compiling Rust code with cargo.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/

#![deny(rust_2018_idioms)]
#![allow(dead_code, unused_imports)]

mod harness;

use crate::harness::get_stats;

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
#[macro_use]
extern crate log;

use std::io::Write;

/// Test that building a simple Rust crate with cargo using sccache results in a cache hit
/// when built a second time.
#[test]
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn test_rust_cargo() {
    let _ = env_logger::Builder::new()
        .format(|f, record| {
            writeln!(
                f,
                "{} [{}] - {}",
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .is_test(true)
        .filter_level(log::LevelFilter::Trace)
        .try_init();

    trace!("cargo check");
    test_rust_cargo_cmd("check");

    trace!("cargo build");
    test_rust_cargo_cmd("build");
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn test_rust_cargo_cmd(cmd: &str) {
    use assert_cmd::prelude::*;
    use predicates::prelude::*;
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn sccache_command() -> Command {
        Command::new(assert_cmd::cargo::cargo_bin(env!("CARGO_PKG_NAME")))
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
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .parse_env("RUST_LOG")
        .try_init();

    let cargo = env!("CARGO");
    debug!("cargo: {}", cargo);
    let sccache = assert_cmd::cargo::cargo_bin(env!("CARGO_PKG_NAME"));
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
    get_stats(|info: sccache::server::ServerInfo| {
        assert_eq!(dbg!(dbg!(info.stats).cache_hits).get("Rust"), Some(&1));
    });

    stop();
}
