#[allow(dead_code, unused_imports)]
mod harness;

use assert_cmd::prelude::*;
use harness::ModuleCache;
use std::{fs, process::Command};
use test_case::test_case;

#[test_case(false)]
#[test_case(true)]
fn module_directory_and_header_output(direct: bool) {
    let Ok(clang) = which::which("clang++") else {
        eprintln!("clang++ unavailable; skipping modules test");
        return;
    };
    let cache = ModuleCache::new(direct);
    let cwd = cache.dir.path();
    fs::create_dir(cwd.join("modules")).unwrap();
    fs::write(
        cwd.join("m.cppm"),
        "export module m;\nexport inline constexpr int answer = 11;\n",
    )
    .unwrap();
    Command::new(&clang)
        .current_dir(cwd)
        .args([
            "-std=c++20",
            "--precompile",
            "m.cppm",
            "-o",
            "modules/m.pcm",
        ])
        .assert()
        .success();
    fs::write(
        cwd.join("use.cpp"),
        "import m;\nstatic_assert(answer == 11);\n",
    )
    .unwrap();
    let consumer = [
        "-std=c++20",
        "-c",
        "-fprebuilt-module-path=modules",
        "use.cpp",
        "-o",
        "use.o",
    ];
    cache
        .command()
        .arg(&clang)
        .args(consumer)
        .assert()
        .success();
    cache
        .command()
        .arg(&clang)
        .args(consumer)
        .assert()
        .success();
    assert_eq!(cache.stats().stats.cache_hits.all(), 1);
    fs::rename(cwd.join("modules/m.pcm"), cwd.join("modules/other.pcm")).unwrap();
    cache
        .command()
        .arg(&clang)
        .args(consumer)
        .assert()
        .failure();
    assert_eq!(cache.stats().stats.cache_hits.all(), 1);

    fs::write(cwd.join("header.hpp"), "#define ANSWER 22\n").unwrap();
    let header = ["-std=c++20", "-c", "-fmodule-header", "header.hpp"];
    cache.command().arg(&clang).args(header).assert().success();
    assert!(cwd.join("header.pcm").is_file());
    assert!(!cwd.join("header.o").exists());
    cache
        .command()
        .arg(&clang)
        .args(header)
        .args(["-o", "explicit.pcm"])
        .assert()
        .success();
    fs::remove_file(cwd.join("explicit.pcm")).unwrap();
    cache
        .command()
        .arg(&clang)
        .args(header)
        .args(["-o", "explicit.pcm"])
        .assert()
        .success();
    assert!(cwd.join("explicit.pcm").is_file());
    assert_eq!(cache.stats().stats.cache_hits.all(), 2);
}
