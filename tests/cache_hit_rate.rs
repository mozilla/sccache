pub mod helpers;

use std::process::Command;

use anyhow::Result;
use assert_cmd::assert::OutputAssertExt;
use helpers::{cargo_clean, SccacheTest, CARGO, CRATE_DIR};
use predicates::{boolean::PredicateBooleanExt, str::PredicateStrExt};
use serial_test::serial;

#[test]
#[serial]
fn test_cache_hit_rate() -> Result<()> {
    let test_info = SccacheTest::new(None)?;

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
    let test_info = SccacheTest::new(None)?;

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
