pub mod helpers;

use std::ffi::OsString;
use std::process::Command;

use anyhow::Result;
use assert_cmd::assert::OutputAssertExt;
use helpers::{CARGO, CRATE_DIR, SccacheTest, cargo_clean};
use predicates::{boolean::PredicateBooleanExt, str::PredicateStrExt};
use serial_test::serial;

/// These tests check server-side "Cache hits rate" stats, so client-side
/// compilation must be disabled to ensure compilations go through the server.
fn server_side_envs() -> Vec<(&'static str, OsString)> {
    vec![("SCCACHE_CLIENT_SIDE_COMPILE", OsString::from("0"))]
}

#[test]
#[serial]
fn test_cache_hit_rate() -> Result<()> {
    let test_info = SccacheTest::new(Some(&server_side_envs()))?;

    Command::new(CARGO.as_os_str())
        .args(["build", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8().not())?
        .try_success()?;

    test_info
        .show_text_stats(false)?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate\s+0\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate \(Rust\)\s+0\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_success()?;

    // Clean it so we can build it again.
    cargo_clean(&test_info)?;

    Command::new(CARGO.as_os_str())
        .args(["run", "--color=always"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8())?
        .try_success()?;

    test_info
        .show_text_stats(false)?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate\s+50\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate \(Rust\)\s+50\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_success()?;

    Ok(())
}

#[test]
#[serial]
fn test_adv_cache_hit_rate() -> Result<()> {
    let test_info = SccacheTest::new(Some(&server_side_envs()))?;

    Command::new(CARGO.as_os_str())
        .args(["build", "--color=never"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8().not())?
        .try_success()?;

    test_info
        .show_text_stats(true)?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate\s+0\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate \(rust\)\s+0\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_success()?;

    cargo_clean(&test_info)?;

    Command::new(CARGO.as_os_str())
        .args(["run", "--color=always"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_stderr(predicates::str::contains("\x1b[").from_utf8())?
        .try_success()?;

    test_info
        .show_text_stats(true)?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate\s+50\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_stdout(
            predicates::str::is_match(r"Cache hits rate \(rust\)\s+50\.00\s%")
                .unwrap()
                .from_utf8(),
        )?
        .try_success()?;

    Ok(())
}
