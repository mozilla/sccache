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

use client::connect_with_retry;
use commands::{
    DEFAULT_PORT,
    request_stats,
    which,
};
use std::env;
use std::ffi::OsStr;
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

#[cfg(target_os="linux")]
const COMPILER : &'static str = "gcc";

fn do_run<T: AsRef<OsStr>>(exe: &Path, args: &[T]) -> Output {
    Command::new(exe)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
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


#[allow(dead_code)]
fn run_sccache_command_test(sccache: &Path, compiler: &str, tempdir: &Path) {
    // Ensure there's no existing sccache server running.
    do_run(sccache, &["--stop-server"]);
    // Start a server.
    assert_eq!(true, run(sccache, &["--start-server"]));
    // Compile a source file.
    let source_file = Path::new(file!()).parent().unwrap().join("test.c");
    let out_file = tempdir.join("test.o");
    assert_eq!(true, run(sccache, &[compiler, "-c", source_file.to_str().unwrap(), "-o", out_file.to_str().unwrap()]));
    let conn = connect_with_retry(DEFAULT_PORT).unwrap();
    let _stats = request_stats(conn);
    //TODO: check stats: should be 1 cache miss.
    assert_eq!(true, run(sccache, &[compiler, "-c", source_file.to_str().unwrap(), "-o", out_file.to_str().unwrap()]));
    let conn = connect_with_retry(DEFAULT_PORT).unwrap();
    let _stats = request_stats(conn);
    //TODO: check stats: should be 1 cache hit, 1 cache miss.
    assert_eq!(true, run(sccache, &["--stop-server"]));
}

#[test]
#[cfg(target_os="linux")]
fn test_sccache_command() {
    let tempdir = TempDir::new("sccache_system_test").unwrap();
    let sccache = env::current_exe().unwrap().parent().unwrap().join("sccache");
    match which(COMPILER, env::var("PATH").ok(), &env::current_dir().unwrap()) {
        Some(c) => run_sccache_command_test(&sccache, &c, tempdir.path()),
        None => {
            assert!(true, "No `{}` compiler found, skipping test", COMPILER);
        }
    }
}
