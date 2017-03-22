// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code, unused_imports)]

use client::connect_with_retry;
use commands::{
    DEFAULT_PORT,
    request_stats,
};
use env_logger;
use log::LogLevel::Trace;
use protocol::CacheStat;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr,OsString};
use std::fs;
use std::io::{
    self,
    Write,
};
use std::path::{Path,PathBuf};
use std::process::{
    Command,
    Output,
    Stdio,
};
use tempdir::TempDir;
use test::utils::*;
use which::which_in;


// Test GCC + clang on non-OS X platforms.
#[cfg(all(unix, not(target_os="macos")))]
const COMPILERS: &'static [&'static str] = &["gcc", "clang"];

// OS X ships a `gcc` that's just a clang wrapper, so only test clang there.
#[cfg(target_os="macos")]
const COMPILERS: &'static [&'static str] = &["clang"];

// Test MSVC when targeting MSVC.
#[cfg(target_env="msvc")]
const COMPILERS: &'static[&'static str] = &["cl.exe"];

//TODO: could test gcc when targeting mingw.

fn do_run<T: AsRef<OsStr>>(exe: &Path, args: &[T], cwd: &Path) -> Output {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    trace!("do_run: {:?}", cmd);
    cmd.spawn()
        .unwrap_or_else(|e| { panic!("failed to execute child: {}", e) })
        .wait_with_output()
        .unwrap()
}

fn run<T: AsRef<OsStr>>(exe: &Path, args: &[T], cwd: &Path) -> bool {
    let output = do_run(exe, args, cwd);
    if output.status.success() {
        true
    } else {
        let va = args.iter().map(|a| a.as_ref().to_str().unwrap()).collect::<Vec<_>>();
        println!("Process `{:?} {}` failed:", exe, va.join(" "));
        print!("stdout: `");
        io::stdout().write(&output.stdout).unwrap();
        println!("`");
        print!("stderr: `");
        io::stdout().write(&output.stderr).unwrap();
        println!("`");
        false
    }
}

macro_rules! vec_from {
    ( $t:ty, $( $x:expr ),* ) => {
        vec!($( Into::<$t>::into(&$x), )*)
    };
}

fn compile_cmdline<T: AsRef<OsStr>>(compiler: &str, exe: T, input: &str, output: &str) -> Vec<OsString> {
    match compiler {
        "gcc" | "clang" => vec_from!(OsString, exe.as_ref(), "-c", input, "-o", output),
        "cl.exe" => vec_from!(OsString, exe, "-c", input, format!("-Fo{}", output)),
        _ => panic!("Unsupported compiler: {}", compiler),
    }
}

fn print_stats(stats: &HashMap<String, CacheStat>) {
    for (k, v) in stats.iter() {
        trace!("  {}: {:?}", k, v);
    }
}

fn run_sccache_command_test<T: AsRef<OsStr>>(sccache: &Path, compiler: &str, exe: T, tempdir: &Path) {
    // Ensure there's no existing sccache server running.
    trace!("stop server");
    do_run(sccache, &["--stop-server"], tempdir);
    // Create a subdir for the cache.
    let cache = tempdir.join("cache");
    fs::create_dir_all(&cache).unwrap();
    // Start a server.
    trace!("start server");
    // Don't run this with run() because on Windows `wait_with_output`
    // will hang because the internal server process is not detached.
    assert!(Command::new(sccache)
            .arg("--start-server")
            .current_dir(tempdir)
            .env("SCCACHE_DIR", &cache)
            .status()
            .unwrap()
            .success());
    trace!("run_sccache_command_test: {}", compiler);
    // Compile a source file.
    let original_source_file = Path::new(file!()).parent().unwrap().join("test.c");
    // Copy the source file into the tempdir so we can compile with relative paths, since the commandline winds up in the hash key.
    let source_file = tempdir.join("test.c");
    trace!("fs::copy({:?}, {:?})", original_source_file, source_file);
    fs::copy(&original_source_file, &source_file).unwrap();
    let out_file = tempdir.join("test.o");
    let input = source_file.file_name().unwrap().to_str().unwrap();
    let output = out_file.file_name().unwrap().to_str().unwrap();
    trace!("compile");
    assert_eq!(true, run(sccache, &compile_cmdline(compiler, exe.as_ref(), &input, &output), tempdir));
    assert_eq!(true, fs::metadata(&out_file).and_then(|m| Ok(m.len() > 0)).unwrap());
    trace!("connect");
    let conn = connect_with_retry(DEFAULT_PORT).unwrap();
    trace!("request stats");
    let stats = cache_stats_map(request_stats(conn).unwrap());
    if log_enabled!(Trace) {
        trace!("stats:");
        print_stats(&stats);
    }
    assert_eq!(&CacheStat::Count(1), stats.get("Compile requests").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Compile requests executed").unwrap());
    assert_eq!(&CacheStat::Count(0), stats.get("Cache hits").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Cache misses").unwrap());
    trace!("compile");
    fs::remove_file(&out_file).unwrap();
    assert_eq!(true, run(sccache, &compile_cmdline(compiler, exe.as_ref(), &input, &output), tempdir));
    assert_eq!(true, fs::metadata(&out_file).and_then(|m| Ok(m.len() > 0)).unwrap());
    trace!("connect");
    let conn = connect_with_retry(DEFAULT_PORT).unwrap();
    trace!("request stats");
    let stats = cache_stats_map(request_stats(conn).unwrap());
    if log_enabled!(Trace) {
        trace!("stats:");
        print_stats(&stats);
    }
    assert_eq!(&CacheStat::Count(2), stats.get("Compile requests").unwrap());
    assert_eq!(&CacheStat::Count(2), stats.get("Compile requests executed").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Cache hits").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Cache misses").unwrap());
    trace!("stop server");
    assert_eq!(true, run(sccache, &["--stop-server"], tempdir));
}

#[cfg(any(unix, target_env="msvc"))]
fn find_compilers() -> Vec<(&'static str, OsString)> {
    let cwd = env::current_dir().unwrap();
    COMPILERS.iter()
        .filter_map(|c| {
            match which_in(c, env::var_os("PATH"), &cwd) {
                Ok(full_path) => match full_path.canonicalize() {
                    Ok(full_path_canon) => Some((*c, full_path_canon.into_os_string())),
                    Err(_) => None,
                },
                Err(_) => None,
            }
        })
        .collect::<Vec<_>>()
}

#[test]
#[cfg(any(unix, target_env="msvc"))]
fn test_sccache_command() {
    match env_logger::init() {
        Ok(_) => {},
        Err(_) => {},
    }
    let tempdir = TempDir::new("sccache_system_test").unwrap();
    let sccache = find_sccache_binary();
    let compilers = find_compilers();
    if compilers.is_empty() {
        assert!(true, "No compilers found, skipping test");
    } else {
        for (compiler, path) in compilers {
            run_sccache_command_test(&sccache, compiler, path, tempdir.path())
        }
    }
}
