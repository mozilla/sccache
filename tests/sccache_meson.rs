//! System tests for compiling Rust code the way meson invokes rustc.
//!
//! Any copyright is dedicated to the Public Domain.
//! http://creativecommons.org/publicdomain/zero/1.0/

pub mod helpers;

use anyhow::Result;
use assert_cmd::prelude::*;
use fs_err as fs;
use helpers::{SCCACHE_BIN, SccacheTest};
use predicates::prelude::*;
use std::process::Command;

/// One `--emit` per output, each with its own path, and no `--out-dir`.
#[test]
fn test_rust_meson_style_emit() -> Result<()> {
    let test_info = SccacheTest::new(None)?;
    let build_dir = test_info.tempdir.path().join("meson");
    fs::create_dir_all(build_dir.join("foo.p"))?;
    fs::write(build_dir.join("lib.rs"), "pub fn f() -> u32 { 1 }\n")?;

    for _ in 0..2 {
        for output in ["libfoo.rlib", "foo.p/foo.d"] {
            let _ = fs::remove_file(build_dir.join(output));
        }
        Command::new(SCCACHE_BIN.as_os_str())
            .args([
                "rustc",
                "--crate-type",
                "rlib",
                "--crate-name",
                "foo",
                "--emit",
                "dep-info=foo.p/foo.d",
                "--emit",
                "link=libfoo.rlib",
                "lib.rs",
            ])
            .current_dir(&build_dir)
            .assert()
            .try_success()?;
        assert!(build_dir.join("libfoo.rlib").exists());
        let dep_info = fs::read_to_string(build_dir.join("foo.p/foo.d"))?;
        assert!(dep_info.starts_with("foo.p/foo.d: lib.rs\n"), "{dep_info}");
        assert!(dep_info.contains("\nlibfoo.rlib: lib.rs\n"), "{dep_info}");
    }

    test_info
        .show_stats()?
        .try_stdout(
            predicates::str::contains(r#""cache_hits":{"counts":{"Rust":1}"#)
                .and(predicates::str::contains(
                    r#""cache_misses":{"counts":{"Rust":1}"#,
                ))
                .from_utf8(),
        )?
        .try_success()?;
    Ok(())
}
