//! Tests for sccache args.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/
pub mod helpers;

use anyhow::Result;
use assert_cmd::prelude::*;
use helpers::{SCCACHE_BIN, stop_sccache};
use predicates::prelude::*;
use serial_test::serial;
use std::process::Command;

#[macro_use]
extern crate log;

#[cfg(unix)]
fn command_with_server_start_failure() -> Result<(tempfile::TempDir, Command)> {
    let tempdir = tempfile::tempdir()?;
    let config = tempdir.path().join("config");
    std::fs::write(&config, "")?;

    let mut command = Command::new(SCCACHE_BIN.as_os_str());
    command
        .args(["rustc", "--version"])
        .current_dir(tempdir.path())
        .env("SCCACHE_CONF", config)
        .env("SCCACHE_DIR", tempdir.path().join("cache"))
        .env_remove("SCCACHE_IGNORE_SERVER_IO_ERROR")
        // Force server start to fail with an overlong unix domain socket.
        .env("SCCACHE_SERVER_UDS", "x".repeat(4096));

    Ok((tempdir, command))
}

#[cfg(unix)]
#[test]
#[serial]
fn test_server_start_failure_falls_back() -> Result<()> {
    let (_tempdir, mut command) = command_with_server_start_failure()?;

    command
        .env("SCCACHE_IGNORE_SERVER_IO_ERROR", "1")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("rustc "))
        .stderr(predicate::str::contains("compiling locally instead"));

    Ok(())
}

#[cfg(unix)]
#[test]
#[serial]
fn test_server_start_failure_errors() -> Result<()> {
    let (_tempdir, mut command) = command_with_server_start_failure()?;

    command
        .assert()
        .failure()
        .stderr(predicate::str::contains("sccache: error"));

    Ok(())
}

#[test]
#[serial]
#[cfg(feature = "gcs")]
fn test_gcp_arg_check() -> Result<()> {
    trace!("sccache with log");
    stop_sccache()?;

    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--start-server")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_GCS_KEY_PATH", "foo.json");

    cmd.assert().failure().stderr(predicate::str::contains(
        "If setting GCS credentials, SCCACHE_GCS_BUCKET",
    ));

    stop_sccache()?;

    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--start-server")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_GCS_OAUTH_URL", "http://127.0.0.1");

    cmd.assert().failure().stderr(predicate::str::contains(
        "If setting GCS credentials, SCCACHE_GCS_BUCKET",
    ));

    stop_sccache()?;
    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--start-server")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_GCS_BUCKET", "b")
        .env("SCCACHE_GCS_CREDENTIALS_URL", "not_valid_url//127.0.0.1")
        .env("SCCACHE_GCS_KEY_PATH", "foo.json");

    // This is just a warning
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("gcs credential url is invalid"));

    Ok(())
}

#[test]
#[serial]
#[cfg(feature = "s3")]
fn test_s3_invalid_args() -> Result<()> {
    stop_sccache()?;

    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--start-server")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_BUCKET", "test")
        .env("SCCACHE_REGION", "us-east-1")
        .env("AWS_ACCESS_KEY_ID", "invalid_ak")
        .env("AWS_SECRET_ACCESS_KEY", "invalid_sk");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("cache storage failed to read"));

    Ok(())
}
