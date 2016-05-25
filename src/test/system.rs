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
    which,
};
use env_logger;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{
    self,
    Write,
};
use std::path::Path;
use std::process::{
    Command,
    Output,
    Stdio,
};
use tempdir::TempDir;
use test::utils::*;

#[cfg(unix)]
const COMPILER : &'static str = "gcc";

#[cfg(target_env="msvc")]
const COMPILER : &'static str = "cl.exe";

fn do_run<T: AsRef<OsStr>>(exe: &Path, args: &[T]) -> Output {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    trace!("do_run: {:?}", cmd);
    cmd.spawn()
        .unwrap_or_else(|e| { panic!("failed to execute child: {}", e) })
        .wait_with_output()
        .unwrap()
}

fn run<T: AsRef<OsStr>>(exe: &Path, args: &[T]) -> bool {
    let output = do_run(exe, args);
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

fn compile_cmdline(compiler: &str, exe: &str, input: &Path, output: &Path) -> Vec<String> {
    match compiler {
        "gcc" => vec!(exe.to_owned(), "-c".to_owned(), input.to_str().unwrap().to_owned(), "-o".to_owned(), output.to_str().unwrap().to_owned()),
        "cl.exe" => vec!(exe.to_owned(), "-c".to_owned(), input.to_str().unwrap().to_owned(), format!("-Fo{}", output.to_str().unwrap())),
        _ => panic!("Unsupported compiler: {}", compiler),
    }
}


#[allow(dead_code)]
fn run_sccache_command_test(sccache: &Path, compiler: &str, exe: &str, tempdir: &Path) {
    // Ensure there's no existing sccache server running.
    trace!("stop server");
    do_run(sccache, &["--stop-server"]);
    // Start a server.
    trace!("start server");
    // Don't run this with run() because on Windows `wait_with_output`
    // will hang because the internal server process is not detached.
    assert!(Command::new(sccache)
            .arg("--start-server")
            .status()
            .unwrap()
            .success());
    // Compile a source file.
    let source_file = Path::new(file!()).parent().unwrap().join("test.c");
    let out_file = tempdir.join("test.o");
    trace!("compile");
    assert_eq!(true, run(sccache, &compile_cmdline(compiler, exe, &source_file, &out_file)));
    trace!("connect");
    let conn = connect_with_retry(DEFAULT_PORT).unwrap();
    trace!("request stats");
    let stats = cache_stats_map(request_stats(conn).unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Compile requests").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Compile requests executed").unwrap());
    assert_eq!(&CacheStat::Count(0), stats.get("Cache hits").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Cache misses").unwrap());
    trace!("compile");
    assert_eq!(true, run(sccache, &compile_cmdline(compiler, exe, &source_file, &out_file)));
    trace!("connect");
    let conn = connect_with_retry(DEFAULT_PORT).unwrap();
    trace!("request stats");
    let stats = cache_stats_map(request_stats(conn).unwrap());
    assert_eq!(&CacheStat::Count(2), stats.get("Compile requests").unwrap());
    assert_eq!(&CacheStat::Count(2), stats.get("Compile requests executed").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Cache hits").unwrap());
    assert_eq!(&CacheStat::Count(1), stats.get("Cache misses").unwrap());
    trace!("stop server");
    assert_eq!(true, run(sccache, &["--stop-server"]));
}

// Don't run this on OS X until we actually support clang.
#[test]
#[cfg(all(not(target_os="macos"), any(unix, target_env="msvc")))]
fn test_sccache_command() {
    match env_logger::init() {
        Ok(_) => {},
        Err(_) => {},
    }
    let tempdir = TempDir::new("sccache_system_test").unwrap();
    let sccache = env::current_exe().unwrap().parent().unwrap().join("sccache");
    match fs::metadata(&sccache) {
        Ok(_) => {},
        Err(_) => panic!("Error: sccache binary not found at `{:?}. Do you need to run `cargo build`?", sccache),
    }
    match which(COMPILER, env::var("PATH").ok(), &env::current_dir().unwrap()) {
        Some(c) => run_sccache_command_test(&sccache, COMPILER, &c, tempdir.path()),
        None => {
            assert!(true, "No `{}` compiler found, skipping test", COMPILER);
        }
    }
}
