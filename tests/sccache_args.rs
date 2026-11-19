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

/// `sccache --dtlto` with the given job file, kept away from any user config
/// and cache.
fn dtlto_cmd(tempdir: &Path, jobs: &str) -> Result<Command> {
    let jobs_file = tempdir.join("jobs.json");
    fs::write(&jobs_file, jobs)?;
    let mut cmd = Command::new(SCCACHE_BIN.as_os_str());
    cmd.arg("--dtlto")
        .arg(jobs_file)
        .env("SCCACHE_CONF", tempdir.join("missing-config"))
        .env("SCCACHE_DIR", tempdir.join("cache"))
        .current_dir(tempdir);
    Ok(cmd)
}

#[test]
#[serial]
fn test_dtlto_bad_jobs() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    dtlto_cmd(tempdir.path(), "not json")?
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read DTLTO jobs"));
    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--dtlto")
        .arg(tempdir.path().join("missing.json"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read DTLTO jobs"));
    dtlto_cmd(tempdir.path(), r#"{"common": {"args": []}, "jobs": []}"#)?
        .assert()
        .failure()
        .stderr(predicate::str::contains("no compiler in DTLTO jobs"));
    dtlto_cmd(
        tempdir.path(),
        r#"{"common": {"args": ["cc"]}, "jobs": []}"#,
    )?
    .env("SCCACHE_DTLTO_JOBS", "0")
    .assert()
    .failure()
    .stderr(predicate::str::contains("SCCACHE_DTLTO_JOBS=0"));
    Ok(())
}

/// A `cc` that sccache accepts, since it detects and preprocesses through the
/// real one, but that exits with 7 when it compiles `fail.c`.
#[cfg(unix)]
fn failing_cc(dir: &Path) -> Result<Option<std::path::PathBuf>> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(cc) = which::which("cc") else {
        warn!("No cc found, skipping test");
        return Ok(None);
    };
    let wrapper = dir.join("bin").join("cc");
    fs::create_dir_all(dir.join("bin"))?;
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -E \"*) ;; *\" fail.c \"*) exit 7 ;; esac\nexec '{}' \"$@\"\n",
            cc.display()
        ),
    )?;
    fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))?;
    Ok(Some(wrapper))
}

/// The `(hits, misses)` of C/C++ compilations since the stats were zeroed.
fn c_cache_stats() -> Result<(u64, u64)> {
    let output = Command::new(SCCACHE_BIN.as_os_str())
        .args(["--show-stats", "--stats-format=json"])
        .output()?;
    let stats: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let count = |what: &str| {
        stats["stats"][what]["counts"]["C/C++"]
            .as_u64()
            .unwrap_or(0)
    };
    Ok((count("cache_hits"), count("cache_misses")))
}

/// A failing job fails the command with its exit code, and no job after it
/// starts.
#[test]
#[serial]
#[cfg(unix)]
fn test_dtlto_failing_job_stops_the_queue() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let dir = tempdir.path();
    let Some(cc) = failing_cc(dir)? else {
        return Ok(());
    };
    fs::write(dir.join("good.c"), "int good;\n")?;
    fs::write(dir.join("fail.c"), "int fail;\n")?;
    let jobs = |first: &str| {
        serde_json::json!({
            "common": {"args": [cc, "-c"]},
            "jobs": [
                {"args": [first, "-o", "first.o"]},
                {"args": ["good.c", "-o", "second.o"]},
                {"args": ["good.c", "-o", "third.o"]},
            ],
        })
        .to_string()
    };
    let later_jobs_ran = || dir.join("second.o").exists() || dir.join("third.o").exists();

    stop_sccache()?;
    dtlto_cmd(dir, &jobs("good.c"))?
        .env("SCCACHE_DTLTO_JOBS", "1")
        .assert()
        .success();
    assert!(dir.join("second.o").exists() && dir.join("third.o").exists());
    fs::remove_file(dir.join("second.o"))?;
    fs::remove_file(dir.join("third.o"))?;

    dtlto_cmd(dir, &jobs("fail.c"))?
        .env("SCCACHE_DTLTO_JOBS", "1")
        .assert()
        .code(7);
    assert!(!later_jobs_ran());
    stop_sccache()?;
    Ok(())
}

/// The files a job lists in `inputs` after its module and index (the modules
/// it imports from), and the common inputs, are part of the cache key.
#[test]
#[serial]
#[cfg(unix)]
fn test_dtlto_inputs_are_hashed() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let dir = tempdir.path();
    let Some(cc) = failing_cc(dir)? else {
        return Ok(());
    };
    fs::write(dir.join("good.c"), "int good;\n")?;
    fs::write(dir.join("imported"), "1")?;
    fs::write(dir.join("profile"), "1")?;
    let jobs = serde_json::json!({
        "common": {"args": [cc, "-c"], "inputs": ["profile"]},
        "jobs": [{
            "args": ["good.c", "-o", "good.o"],
            "inputs": ["good.c", "good.c", "imported"],
        }],
    })
    .to_string();
    let run = |expected: (u64, u64)| -> Result<()> {
        Command::new(SCCACHE_BIN.as_os_str())
            .arg("--zero-stats")
            .assert()
            .success();
        dtlto_cmd(dir, &jobs)?.assert().success();
        assert_eq!(expected, c_cache_stats()?);
        Ok(())
    };

    stop_sccache()?;
    dtlto_cmd(dir, &jobs)?.assert().success();
    run((1, 0))?;
    fs::write(dir.join("imported"), "2")?;
    run((0, 1))?;
    fs::write(dir.join("profile"), "2")?;
    run((0, 1))?;
    run((1, 0))?;
    fs::remove_file(dir.join("imported"))?;
    dtlto_cmd(dir, &jobs)?
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to hash the inputs"));
    stop_sccache()?;
    Ok(())
}

/// An empty entry file reads as a valid, empty entry.
fn write_empty_preprocessor_entry(cache_dir: &Path) -> Result<String> {
    let entries_dir = cache_dir.join("preprocessor");
    fs::create_dir_all(&entries_dir)?;
    let entry = entries_dir.join("entry");
    fs::write(&entry, b"")?;
    let expected = format!("Showing preprocessor entry file {}", entry.display());
    Ok(expected)
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

#[test]
fn test_clap_output_and_exit_codes() {
    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")))
        .stderr("");

    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));

    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--no-such-option")
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains("--no-such-option"));
}
