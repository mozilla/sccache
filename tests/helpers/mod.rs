use anyhow::{Context, Result};
use assert_cmd::assert::OutputAssertExt;
use chrono::Local;
use fs_err as fs;
use log::trace;
use once_cell::sync::Lazy;
use std::convert::Infallible;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub static CRATE_DIR: Lazy<PathBuf> =
    Lazy::new(|| Path::new(file!()).parent().unwrap().join("../test-crate"));
pub static CARGO: Lazy<OsString> = Lazy::new(|| std::env::var_os("CARGO").unwrap());
pub static SCCACHE_BIN: Lazy<PathBuf> = Lazy::new(|| assert_cmd::cargo::cargo_bin("sccache"));
/// Ensures the logger is only initialized once. Panics if initialization fails.
static LOGGER: Lazy<Result<(), Infallible>> = Lazy::new(|| {
    env_logger::Builder::new()
        .format(|f, record| {
            writeln!(
                f,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .parse_env("RUST_LOG")
        .init();
    Ok(())
});

/// Used as a test setup fixture. The drop implementation cleans up after a _successful_ test.
/// We catch the panic to ensure that the drop runs and the TempDir is cleaned up.
pub struct SccacheTest<'a> {
    /// Tempdir used for Sccache cache and cargo output. It is kept in the struct only to have the
    /// destructor run when SccacheTest goes out of scope, but is never used otherwise.
    #[allow(dead_code)]
    pub tempdir: tempfile::TempDir,
    pub env: Vec<(&'a str, std::ffi::OsString)>,
}

impl SccacheTest<'_> {
    pub fn new(additional_envs: Option<&[(&'static str, std::ffi::OsString)]>) -> Result<Self> {
        assert!(LOGGER.is_ok());

        // Create a temp directory to use for the disk cache.
        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test_rust_cargo")
            .tempdir()
            .context("Failed to create tempdir")?;
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir)?;
        let cargo_dir = tempdir.path().join("cargo");
        fs::create_dir(&cargo_dir)?;

        // Ensure there's no existing sccache server running.
        stop_sccache()?;

        trace!("sccache --start-server");

        Command::new(SCCACHE_BIN.as_os_str())
            .arg("--start-server")
            .env("SCCACHE_DIR", &cache_dir)
            .assert()
            .try_success()
            .context("Failed to start sccache server")?;

        let mut env = vec![
            ("CARGO_TARGET_DIR", cargo_dir.as_os_str().to_owned()),
            ("RUSTC_WRAPPER", SCCACHE_BIN.as_os_str().to_owned()),
            // Explicitly disable incremental compilation because sccache is unable to cache it at
            // the time of writing.
            ("CARGO_INCREMENTAL", OsString::from("0")),
            ("TEST_ENV_VAR", OsString::from("1")),
        ];

        if let Some(vec) = additional_envs {
            env.extend_from_slice(vec);
        }

        Ok(SccacheTest {
            tempdir,
            env: env.to_owned(),
        })
    }

    /// Show the statistics for sccache. This will be called at the end of a test and making this
    /// an associated function will ensure that the struct lives until the end of the test.
    pub fn show_stats(&self) -> assert_cmd::assert::AssertResult {
        trace!("sccache --show-stats");

        Command::new(SCCACHE_BIN.as_os_str())
            .args(["--show-stats", "--stats-format=json"])
            .assert()
            .try_success()
    }

    pub fn show_text_stats(&self, advanced: bool) -> assert_cmd::assert::AssertResult {
        let cmd = if advanced {
            "--show-adv-stats"
        } else {
            "--show-stats"
        };

        trace!("sccache {cmd}");

        Command::new(SCCACHE_BIN.as_os_str())
            .args([cmd, "--stats-format=text"])
            .assert()
            .try_success()
    }
}

impl Drop for SccacheTest<'_> {
    fn drop(&mut self) {
        stop_sccache().expect("Stopping Sccache server failed");
    }
}

pub fn stop_sccache() -> Result<()> {
    trace!("sccache --stop-server");

    Command::new(SCCACHE_BIN.as_os_str())
        .arg("--stop-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to stop sccache server")?;
    Ok(())
}

pub fn cargo_clean(test_info: &SccacheTest) -> Result<()> {
    Command::new(CARGO.as_os_str())
        .args(["clean"])
        .envs(test_info.env.iter().cloned())
        .current_dir(CRATE_DIR.as_os_str())
        .assert()
        .try_success()?;
    Ok(())
}
