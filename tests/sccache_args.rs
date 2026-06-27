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

/// Running the sccache binary under a name that is not `sccache` and is not a
/// real compiler on PATH must NOT make sccache wrap itself (which used to recurse
/// forever via the `<compiler> -vV` detection probe). It should warn and behave
/// as a normal sccache invocation instead. The test timeout guards the old hang.
#[cfg(unix)]
#[test]
fn test_masquerade_as_self_warns_instead_of_recursing() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir()?;
    // A name that is not `sccache` and (almost certainly) not on PATH.
    let masquerade = tmp.path().join("notacompiler");
    std::fs::copy(SCCACHE_BIN.as_os_str(), &masquerade)?;
    std::fs::set_permissions(&masquerade, std::fs::Permissions::from_mode(0o755))?;

    let mut cmd = Command::new(&masquerade);
    cmd.arg("--version").env("SCCACHE_LOG", "warn");
    cmd.assert()
        .success()
        // It ran as sccache (printed the version) ...
        .stdout(predicate::str::contains("sccache"))
        // ... after warning that the name resolved back to sccache itself.
        .stderr(predicate::str::contains("resolves to sccache itself"));

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
