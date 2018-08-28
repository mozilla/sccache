// System tests for compiling C code.
//
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

extern crate assert_cmd;
extern crate cc;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate predicates;
extern crate sccache;
extern crate serde_json;
extern crate tempdir;
extern crate which;

use assert_cmd::prelude::*;
use log::Level::Trace;
use predicates::prelude::*;
use sccache::server::ServerInfo;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr,OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path,PathBuf};
use std::process::{
    Command,
    Output,
    Stdio,
};
use std::str;
use tempdir::TempDir;
use which::which_in;

#[derive(Clone)]
struct Compiler {
    pub name: &'static str,
    pub exe: OsString,
    pub env_vars: Vec<(OsString, OsString)>,
}

// Test GCC + clang on non-OS X platforms.
#[cfg(all(unix, not(target_os="macos")))]
const COMPILERS: &'static [&'static str] = &["gcc", "clang"];

// OS X ships a `gcc` that's just a clang wrapper, so only test clang there.
#[cfg(target_os="macos")]
const COMPILERS: &'static [&'static str] = &["clang"];

//TODO: could test gcc when targeting mingw.

fn stop() {
    trace!("sccache --stop-server");
    drop(Command::main_binary().unwrap()
         .arg("--stop-server")
         .stdout(Stdio::null())
         .stderr(Stdio::null())
         .status());
}

fn zero_stats() {
    trace!("sccache --zero-stats");
    drop(Command::main_binary().unwrap()
         .arg("--zero-stats")
         .stdout(Stdio::null())
         .stderr(Stdio::null())
         .status());
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

fn get_stats<F: 'static + Fn(ServerInfo)>(f: F) {
    Command::main_binary().unwrap()
        .args(&["--show-stats", "--stats-format=json"])
        .assert()
        .success()
        .stdout(predicate::function(move |output: &[u8]| {
            let s = str::from_utf8(output).expect("Output not UTF-8");
            f(serde_json::from_str(s).expect("Failed to parse JSON stats"));
            true
        }));
}

fn write_source(path: &Path, filename: &str, contents: &str) {
    let p = path.join(filename);
    let mut f = File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

const INPUT: &'static str = "test.c";
const INPUT_ERR: &'static str = "test_err.c";
const OUTPUT: &'static str = "test.o";

fn test_basic_compile(compiler: Compiler, tempdir: &Path) {
    let Compiler { name, exe, env_vars } = compiler;
    trace!("run_sccache_command_test: {}", name);
    // Compile a source file.
    // Copy the source files into the tempdir so we can compile with relative paths, since the commandline winds up in the hash key.
    for f in &[INPUT, INPUT_ERR] {
        let original_source_file = Path::new(file!()).parent().unwrap().join(f);
        let source_file = tempdir.join(f);
        trace!("fs::copy({:?}, {:?})", original_source_file, source_file);
        fs::copy(&original_source_file, &source_file).unwrap();
    }

    let out_file = tempdir.join("test.o");
    trace!("compile");
    Command::main_binary().unwrap()
        .args(&compile_cmdline(name, &exe, INPUT, OUTPUT))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert_eq!(true, fs::metadata(&out_file).and_then(|m| Ok(m.len() > 0)).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits);
        assert_eq!(1, info.stats.cache_misses);
    });
    trace!("compile");
    fs::remove_file(&out_file).unwrap();
    Command::main_binary().unwrap()
        .args(&compile_cmdline(name, &exe, INPUT, OUTPUT))
        .current_dir(tempdir)
.envs(env_vars.clone())
        .assert()
        .success();
    assert_eq!(true, fs::metadata(&out_file).and_then(|m| Ok(m.len() > 0)).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits);
        assert_eq!(1, info.stats.cache_misses);
    });
}

fn test_msvc_deps(compiler: Compiler, tempdir: &Path) {
    let Compiler { name, exe, env_vars } = compiler;
    // Check that -deps works.
    trace!("compile with -deps");
    let mut args = compile_cmdline(name, &exe, INPUT, OUTPUT);
    args.push("-depstest.d".into());
    Command::main_binary().unwrap()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    // Check the contents
    let mut f = File::open(tempdir.join("test.d")).expect("Failed to open dep file");
    let mut buf = String::new();
    // read_to_string should be safe because we're supplying all the filenames here,
    // and there are no absolute paths.
    f.read_to_string(&mut buf).expect("Failed to read dep file");
    let lines: Vec<_> = buf.lines().map(|l| l.trim_right()).collect();
    let expected = format!("{output}: {input}\n{input}:\n", output=OUTPUT, input=INPUT);
    let expected_lines: Vec<_> = expected.lines().collect();
    assert_eq!(lines, expected_lines);
}

fn test_gcc_mp_werror(compiler: Compiler, tempdir: &Path) {
    let Compiler { name, exe, env_vars } = compiler;
    trace!("test -MP with -Werror");
    let mut args = compile_cmdline(name, &exe, INPUT_ERR, OUTPUT);
    args.extend(vec_from!(OsString, "-MD", "-MP", "-MF", "foo.pp", "-Werror"));
    // This should fail, but the error should be from the #error!
    Command::main_binary().unwrap()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "to generate dependencies you must specify either -M or -MM").from_utf8().not());
}

fn test_gcc_fprofile_generate_source_changes(compiler: Compiler, tempdir: &Path) {
    let Compiler { name, exe, env_vars } = compiler;
    trace!("test -fprofile-generate with different source inputs");
    zero_stats();
    const SRC: &str = "source.c";
    write_source(&tempdir, SRC, "/*line 1*/
#ifndef UNDEFINED
/*unused line 1*/
#endif

int main(int argc, char** argv) {
  return 0;
}
");
    let mut args = compile_cmdline(name, &exe, SRC, OUTPUT);
    args.extend(vec_from!(OsString, "-fprofile-generate"));
    trace!("compile source.c (1)");
    Command::main_binary().unwrap()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(0, info.stats.cache_hits);
        assert_eq!(1, info.stats.cache_misses);
    });
    // Compile the same source again to ensure we can get a cache hit.
    trace!("compile source.c (2)");
    Command::main_binary().unwrap()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.cache_hits);
        assert_eq!(1, info.stats.cache_misses);
    });
    // Now write out a slightly different source file that will preprocess to the same thing,
    // modulo line numbers. This should not be a cache hit because line numbers are important
    // with -fprofile-generate.
    write_source(&tempdir, SRC, "/*line 1*/
#ifndef UNDEFINED
/*unused line 1*/
/*unused line 2*/
#endif

int main(int argc, char** argv) {
  return 0;
}
");
    trace!("compile source.c (3)");
    Command::main_binary().unwrap()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.cache_hits);
        assert_eq!(2, info.stats.cache_misses);
    });
}

fn run_sccache_command_tests(compiler: Compiler, tempdir: &Path) {
    test_basic_compile(compiler.clone(), tempdir);
    if compiler.name == "cl.exe" {
        test_msvc_deps(compiler.clone(), tempdir);
    }
    if compiler.name == "gcc" {
        test_gcc_mp_werror(compiler.clone(), tempdir);
        test_gcc_fprofile_generate_source_changes(compiler.clone(), tempdir);
    }
}

#[cfg(unix)]
fn find_compilers() -> Vec<Compiler> {
    let cwd = env::current_dir().unwrap();
    COMPILERS.iter()
        .filter_map(|c| {
            match which_in(c, env::var_os("PATH"), &cwd) {
                Ok(full_path) => match full_path.canonicalize() {
                    Ok(full_path_canon) => Some(Compiler {
                        name: *c,
                        exe: full_path_canon.into_os_string(),
                        env_vars: vec![],
                    }),
                    Err(_) => None,
                },
                Err(_) => None,
            }
        })
        .collect::<Vec<_>>()
}

#[cfg(target_env="msvc")]
fn find_compilers() -> Vec<Compiler> {
    let tool = cc::Build::new()
        .opt_level(1)
        .host("x86_64-pc-windows-msvc")
        .target("x86_64-pc-windows-msvc")
        .debug(false)
        .get_compiler();
    vec![
        Compiler {
            name: "cl.exe",
            exe: tool.path().as_os_str().to_os_string(),
            env_vars: tool.env().to_vec(),
        },
    ]
}

#[test]
#[cfg(any(unix, target_env="msvc"))]
fn test_sccache_command() {
    match env_logger::try_init() {
        Ok(_) => {},
        Err(_) => {},
    }
    let tempdir = TempDir::new("sccache_system_test").unwrap();
    let compilers = find_compilers();
    if compilers.is_empty() {
        warn!("No compilers found, skipping test");
    } else {
        // Ensure there's no existing sccache server running.
        stop();
        // Create a subdir for the cache.
        let cache = tempdir.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        // Start a server.
        trace!("start server");
        // Don't run this with run() because on Windows `wait_with_output`
        // will hang because the internal server process is not detached.
        Command::main_binary().unwrap()
            .arg("--start-server")
            .env("SCCACHE_DIR", &cache)
            .status()
            .unwrap()
            .success();
        for compiler in compilers {
            run_sccache_command_tests(compiler, tempdir.path());
            zero_stats();
        }
        stop();
    }
}
