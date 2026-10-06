//! Tests for sccache args.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/
pub mod helpers;

use anyhow::Result;
use assert_cmd::prelude::*;
use fs_err as fs;
use helpers::{SCCACHE_BIN, stop_sccache};
use predicates::prelude::*;
use serial_test::serial;
use std::path::Path;
use std::process::Command;

#[macro_use]
extern crate log;

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

/// An empty entry file reads as a valid, empty entry.
fn write_empty_preprocessor_entry(cache_dir: &Path) -> Result<String> {
    let entries_dir = cache_dir.join("preprocessor");
    fs::create_dir_all(&entries_dir)?;
    let entry = entries_dir.join("entry");
    fs::write(&entry, b"")?;
    Ok(format!(
        "Showing preprocessor entry file {}",
        entry.display()
    ))
}

fn debug_preprocessor_cache_cmd(tempdir: &Path) -> Command {
    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    // Keep any user config out, and on Linux point the default cache dir
    // somewhere empty.
    cmd.arg("--debug-preprocessor-cache")
        .env_remove("SCCACHE_DIR")
        .env("SCCACHE_CONF", tempdir.join("missing-config"))
        .env("XDG_CACHE_HOME", tempdir.join("xdg-cache"));
    cmd
}

#[test]
#[serial]
fn test_debug_preprocessor_cache_uses_sccache_dir() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    let expected = write_empty_preprocessor_entry(&cache_dir)?;

    debug_preprocessor_cache_cmd(tempdir.path())
        .env("SCCACHE_DIR", &cache_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains(expected));

    Ok(())
}

#[test]
#[serial]
fn test_debug_preprocessor_cache_uses_config_disk_dir() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let cache_dir = tempdir.path().join("cache");
    let expected = write_empty_preprocessor_entry(&cache_dir)?;
    let config = tempdir.path().join("config");
    // TOML literal string, so Windows backslashes are not escapes.
    fs::write(
        &config,
        format!("[cache.disk]\ndir = '{}'\n", cache_dir.display()),
    )?;

    debug_preprocessor_cache_cmd(tempdir.path())
        .env("SCCACHE_CONF", &config)
        .assert()
        .success()
        .stdout(predicate::str::contains(expected));

    Ok(())
}
