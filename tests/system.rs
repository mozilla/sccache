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

#![deny(rust_2018_idioms)]
#![allow(dead_code, unused_imports)]

#[macro_use]
extern crate log;
use crate::harness::{
    get_stats, sccache_client_cfg, sccache_command, start_local_daemon, stop_local_daemon,
    write_json_cfg, write_source, zero_stats,
};
use assert_cmd::prelude::*;
use fs::File;
use fs_err as fs;
use log::Level::Trace;
use predicates::prelude::*;
use regex::Regex;
use serial_test::serial;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, format};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str;
use std::time::{Duration, SystemTime};
use test_case::test_case;
use which::{which, which_in};

mod harness;

#[derive(Clone)]
struct Compiler {
    pub name: &'static str,
    pub exe: OsString,
    pub env_vars: Vec<(OsString, OsString)>,
}

// Test GCC + clang on non-OS X platforms.
#[cfg(all(unix, not(target_os = "macos")))]
const COMPILERS: &[&str] = &["gcc", "clang", "clang++", "nvc", "nvc++"];

// OS X ships a `gcc` that's just a clang wrapper, so only test clang there.
#[cfg(target_os = "macos")]
const COMPILERS: &[&str] = &["clang", "clang++"];

const CUDA_COMPILERS: &[&str] = &["nvcc", "clang++"];

fn adv_key_kind(lang: &str, compiler: &str) -> String {
    let language = lang.to_owned();
    match compiler {
        "clang" | "clang++" => language + " [clang]",
        "gcc" | "g++" => language + " [gcc]",
        "cl.exe" => language + " [msvc]",
        "nvc" | "nvc++" => language + " [nvhpc]",
        "nvcc" => language + " [nvcc]",
        _ => {
            trace!("Unknown compiler type: {}", compiler);
            language + "unknown"
        }
    }
}

//TODO: could test gcc when targeting mingw.

macro_rules! vec_from {
    ( $t:ty, $( $x:expr ),* ) => {
        vec!($( Into::<$t>::into(&$x), )*)
    };
}

// TODO: This will fail if gcc/clang is actually a ccache wrapper, as it is the
// default case on Fedora, e.g.
fn compile_cmdline<T: AsRef<OsStr>>(
    compiler: &str,
    exe: T,
    input: &str,
    output: &str,
    mut extra_args: Vec<OsString>,
) -> Vec<OsString> {
    let mut arg = match compiler {
        "gcc" | "clang" | "clang++" | "nvc" | "nvc++" | "nvcc" => {
            vec_from!(OsString, exe.as_ref(), "-c", input, "-o", output)
        }
        "cl.exe" => vec_from!(OsString, exe, "-c", input, format!("-Fo{}", output)),
        _ => panic!("Unsupported compiler: {}", compiler),
    };
    if !extra_args.is_empty() {
        arg.append(&mut extra_args)
    }
    arg
}

// TODO: This will fail if gcc/clang is actually a ccache wrapper, as it is the
// default case on Fedora, e.g.
fn compile_cuda_cmdline<T: AsRef<OsStr>>(
    compiler: &str,
    exe: T,
    input: &str,
    output: &str,
    mut extra_args: Vec<OsString>,
) -> Vec<OsString> {
    let mut arg = match compiler {
        "nvcc" => vec_from!(OsString, exe.as_ref(), "-c", input, "-o", output),
        "clang++" => {
            vec_from!(
                OsString,
                exe,
                "-c",
                input,
                "--cuda-gpu-arch=sm_50",
                format!("-Fo{}", output)
            )
        }
        _ => panic!("Unsupported compiler: {}", compiler),
    };
    if !extra_args.is_empty() {
        arg.append(&mut extra_args)
    }
    arg
}

// TODO: This will fail if gcc/clang is actually a ccache wrapper, as it is the
// default case on Fedora, e.g.
//
// archs is a list of GPU architectures to compile for.
fn compile_hip_cmdline<T: AsRef<OsStr>>(
    compiler: &str,
    exe: T,
    input: &str,
    output: &str,
    archs: &Vec<String>,
    mut extra_args: Vec<OsString>,
) -> Vec<OsString> {
    let mut arg = match compiler {
        "clang" => {
            vec_from!(OsString, exe, "-x", "hip", "-c", input, "-o", output)
        }
        _ => panic!("Unsupported compiler: \"{}\"", compiler),
    };
    for arch in archs {
        arg.push(format!("--offload-arch={}", arch).into());
    }
    if !extra_args.is_empty() {
        arg.append(&mut extra_args)
    }
    arg
}

const INPUT: &str = "test.c";
const INPUT_CLANG_MULTICALL: &str = "test_clang_multicall.c";
const INPUT_WITH_WHITESPACE: &str = "test_whitespace.c";
const INPUT_WITH_WHITESPACE_ALT: &str = "test_whitespace_alt.c";
const INPUT_ERR: &str = "test_err.c";
const INPUT_MACRO_EXPANSION: &str = "test_macro_expansion.c";
const INPUT_WITH_DEFINE: &str = "test_with_define.c";
const INPUT_FOR_CUDA_A: &str = "test_a.cu";
const INPUT_FOR_CUDA_B: &str = "test_b.cu";
const INPUT_FOR_CUDA_C: &str = "test_c.cu";
const INPUT_FOR_HIP_A: &str = "test_a.hip";
const INPUT_FOR_HIP_B: &str = "test_b.hip";
const INPUT_FOR_HIP_C: &str = "test_c.hip";
const OUTPUT: &str = "test.o";

// Copy the source files into the tempdir so we can compile with relative paths, since the commandline winds up in the hash key.
fn copy_to_tempdir(inputs: &[&str], tempdir: &Path) {
    for f in inputs {
        let original_source_file = Path::new(file!()).parent().unwrap().join(f);
        let source_file = tempdir.join(f);
        trace!("fs::copy({:?}, {:?})", original_source_file, source_file);
        fs::copy(&original_source_file, &source_file).unwrap();
        // Preprocessor cache will not cache files that are too recent.
        // Certain OS/FS combinations have a slow resolution (up to 2s for NFS),
        // leading to flaky tests.
        // We set the times for the new file to 10 seconds ago, to be safe.
        let new_time =
            filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(10));
        filetime::set_file_times(source_file, new_time, new_time).unwrap();
    }
}

fn test_basic_compile(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("run_sccache_command_test: {}", name);
    // Compile a source file.
    copy_to_tempdir(&[INPUT, INPUT_ERR], tempdir);

    let out_file = tempdir.join(OUTPUT);
    trace!("compile");
    sccache_command()
        .args(&compile_cmdline(name, &exe, INPUT, OUTPUT, Vec::new()))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_misses.get("C/C++").unwrap());
        let adv_key = adv_key_kind("c", compiler.name);
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_key).unwrap());
    });
    trace!("compile");
    fs::remove_file(&out_file).unwrap();
    sccache_command()
        .args(&compile_cmdline(name, &exe, INPUT, OUTPUT, Vec::new()))
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("C/C++").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("C/C++").unwrap());
        let adv_key = adv_key_kind("c", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_key).unwrap());
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_key).unwrap());
    });
}

fn test_noncacheable_stats(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("test_noncacheable_stats: {}", name);
    copy_to_tempdir(&[INPUT], tempdir);

    trace!("compile");
    sccache_command()
        .arg(&exe)
        .arg("-E")
        .arg(INPUT)
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(0, info.stats.requests_executed);
        assert_eq!(1, info.stats.not_cached.len());
        assert_eq!(Some(&1), info.stats.not_cached.get("-E"));
    });
}

fn test_msvc_deps(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    // Check that -deps works.
    trace!("compile with /sourceDependencies");
    let mut args = compile_cmdline(name, exe, INPUT, OUTPUT, Vec::new());
    args.push("/sourceDependenciestest.o.json".into());
    sccache_command()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    // Check the contents
    let f = File::open(tempdir.join("test.o.json")).expect("Failed to open dep file");
    // MSVC deps files are JSON, which we can validate properties of, but will be
    // subtly different on different systems (Windows SDK version, for example)
    let deps: serde_json::Value = serde_json::from_reader(f).expect("Failed to read dep file");
    let source = deps["Data"]["Source"].as_str().expect("No source found");
    let source = Path::new(source).file_name().expect("No source file name");
    assert_eq!(source, INPUT);

    let includes = deps["Data"]["Includes"]
        .as_array()
        .expect("No includes found");
    assert_ne!(includes.len(), 0);
}

fn test_msvc_responsefile(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name: _,
        exe,
        env_vars,
    } = compiler;

    let out_file = tempdir.join(OUTPUT);
    let cmd_file_name = "test_msvc.rsp";
    {
        let mut file = File::create(tempdir.join(cmd_file_name)).unwrap();
        let content = format!("-c {INPUT} -Fo{OUTPUT}");
        file.write_all(content.as_bytes()).unwrap();
    }

    let args = vec_from!(OsString, exe, &format!("@{cmd_file_name}"));
    sccache_command()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();

    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    fs::remove_file(&out_file).unwrap();
}

fn test_gcc_mp_werror(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("test -MP with -Werror");
    let mut args = compile_cmdline(name, exe, INPUT_ERR, OUTPUT, Vec::new());
    args.extend(vec_from!(
        OsString, "-MD", "-MP", "-MF", "foo.pp", "-Werror"
    ));
    // This should fail, but the error should be from the #error!
    sccache_command()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .failure()
        .stderr(
            predicates::str::contains("to generate dependencies you must specify either -M or -MM")
                .from_utf8()
                .not(),
        );
}

fn test_gcc_fprofile_generate_source_changes(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("test -fprofile-generate with different source inputs");
    zero_stats();
    const SRC: &str = "source.c";
    write_source(
        tempdir,
        SRC,
        "/*line 1*/
#ifndef UNDEFINED
/*unused line 1*/
#endif

int main(int argc, char** argv) {
  return 0;
}
",
    );
    let mut args = compile_cmdline(name, exe, SRC, OUTPUT, Vec::new());
    args.extend(vec_from!(OsString, "-fprofile-generate"));
    trace!("compile source.c (1)");
    sccache_command()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_misses.get("C/C++").unwrap());
    });
    // Compile the same source again to ensure we can get a cache hit.
    trace!("compile source.c (2)");
    sccache_command()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("C/C++").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("C/C++").unwrap());
    });
    // Now write out a slightly different source file that will preprocess to the same thing,
    // modulo line numbers. This should not be a cache hit because line numbers are important
    // with -fprofile-generate.
    write_source(
        tempdir,
        SRC,
        "/*line 1*/
#ifndef UNDEFINED
/*unused line 1*/
/*unused line 2*/
#endif

int main(int argc, char** argv) {
  return 0;
}
",
    );
    trace!("compile source.c (3)");
    sccache_command()
        .args(&args)
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("C/C++").unwrap());
        assert_eq!(&2, info.stats.cache_misses.get("C/C++").unwrap());
    });
}

fn test_gcc_clang_no_warnings_from_macro_expansion(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("test_gcc_clang_no_warnings_from_macro_expansion: {}", name);
    // Compile a source file.
    copy_to_tempdir(&[INPUT_MACRO_EXPANSION], tempdir);

    trace!("compile");
    sccache_command()
        .args(
            [
                &compile_cmdline(name, exe, INPUT_MACRO_EXPANSION, OUTPUT, Vec::new())[..],
                &vec_from!(OsString, "-Wunreachable-code")[..],
            ]
            .concat(),
        )
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success()
        .stderr(predicates::str::contains("warning:").from_utf8().not());
}

fn test_compile_with_define(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("test_compile_with_define: {}", name);
    // Compile a source file.
    copy_to_tempdir(&[INPUT_WITH_DEFINE], tempdir);

    trace!("compile");
    sccache_command()
        .args(
            [
                &compile_cmdline(name, exe, INPUT_WITH_DEFINE, OUTPUT, Vec::new())[..],
                &vec_from!(OsString, "-DSCCACHE_TEST_DEFINE")[..],
            ]
            .concat(),
        )
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success()
        .stderr(predicates::str::contains("warning:").from_utf8().not());
}

fn run_sccache_command_tests(compiler: Compiler, tempdir: &Path, preprocessor_cache_mode: bool) {
    if compiler.name != "clang++" {
        test_basic_compile(compiler.clone(), tempdir);
    }
    test_compile_with_define(compiler.clone(), tempdir);
    if compiler.name == "cl.exe" {
        test_msvc_deps(compiler.clone(), tempdir);
        test_msvc_responsefile(compiler.clone(), tempdir);
    }
    if compiler.name == "gcc" {
        test_gcc_mp_werror(compiler.clone(), tempdir);
        test_gcc_fprofile_generate_source_changes(compiler.clone(), tempdir);
    }
    if compiler.name == "clang" || compiler.name == "gcc" {
        test_gcc_clang_no_warnings_from_macro_expansion(compiler.clone(), tempdir);
    }
    if compiler.name == "clang++" {
        test_clang_multicall(compiler.clone(), tempdir);
    }

    // If we are testing with clang-14 or later, we expect the -fminimize-whitespace flag to be used.
    if compiler.name == "clang" || compiler.name == "clang++" {
        let version_cmd = Command::new(compiler.exe.clone())
            .arg("--version")
            .output()
            .expect("Failure when getting compiler version");
        assert!(version_cmd.status.success());

        let version_output = match str::from_utf8(&version_cmd.stdout) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        // Regex to match "Apple LLVM clang version" or "Apple clang version"
        let re = Regex::new(r"(?P<apple>Apple)?.*clang version (?P<major>\d+)").unwrap();
        let (major, is_appleclang) = match re.captures(version_output) {
            Some(c) => (
                c.name("major").unwrap().as_str().parse::<usize>().unwrap(),
                c.name("apple").is_some(),
            ),
            None => panic!(
                "Version info not found in --version output: {}",
                version_output
            ),
        };
        test_clang_cache_whitespace_normalization(
            compiler,
            tempdir,
            !is_appleclang && major >= 14,
            preprocessor_cache_mode,
        );
    } else {
        test_clang_cache_whitespace_normalization(
            compiler,
            tempdir,
            false,
            preprocessor_cache_mode,
        );
    }
}

fn test_cuda_compiles(compiler: &Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("run_sccache_command_test: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_CUDA_A, INPUT_FOR_CUDA_B], tempdir);

    let out_file = tempdir.join(OUTPUT);
    trace!("compile A");
    sccache_command()
        .args(&compile_cuda_cmdline(
            name,
            exe,
            INPUT_FOR_CUDA_A,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_misses.get("CUDA").unwrap());
        let adv_cuda_key = adv_key_kind("cuda", compiler.name);
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_cuda_key).unwrap());
    });
    trace!("compile A");
    fs::remove_file(&out_file).unwrap();
    sccache_command()
        .args(&compile_cuda_cmdline(
            name,
            exe,
            INPUT_FOR_CUDA_A,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("CUDA").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("CUDA").unwrap());
        let adv_cuda_key = adv_key_kind("cuda", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_cuda_key).unwrap());
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_cuda_key).unwrap());
    });
    // By compiling another input source we verify that the pre-processor
    // phase is correctly running and outputting text
    trace!("compile B");
    sccache_command()
        .args(&compile_cuda_cmdline(
            name,
            exe,
            INPUT_FOR_CUDA_B,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(3, info.stats.compile_requests);
        assert_eq!(3, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("CUDA").unwrap());
        assert_eq!(&2, info.stats.cache_misses.get("CUDA").unwrap());
        let adv_cuda_key = adv_key_kind("cuda", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_cuda_key).unwrap());
        assert_eq!(&2, info.stats.cache_misses.get_adv(&adv_cuda_key).unwrap());
    });
}

fn test_proper_lang_stat_tracking(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    zero_stats();

    trace!("run_sccache_command_test: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_CUDA_C, INPUT], tempdir);

    let out_file = tempdir.join(OUTPUT);
    trace!("compile CUDA A");
    sccache_command()
        .args(&compile_cmdline(
            name,
            &exe,
            INPUT_FOR_CUDA_C,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    trace!("compile CUDA A");
    sccache_command()
        .args(&compile_cmdline(
            name,
            &exe,
            INPUT_FOR_CUDA_C,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    trace!("compile C++ A");
    sccache_command()
        .args(&compile_cmdline(name, &exe, INPUT, OUTPUT, Vec::new()))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    trace!("compile C++ A");
    sccache_command()
        .args(&compile_cmdline(name, &exe, INPUT, OUTPUT, Vec::new()))
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();

    trace!("request stats");
    get_stats(|info| {
        assert_eq!(4, info.stats.compile_requests);
        assert_eq!(4, info.stats.requests_executed);
        assert_eq!(2, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("C/C++").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("C/C++").unwrap());
        assert_eq!(&1, info.stats.cache_hits.get("CUDA").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("CUDA").unwrap());
    });
}

fn run_sccache_cuda_command_tests(compiler: Compiler, tempdir: &Path) {
    test_cuda_compiles(&compiler, tempdir);
    test_proper_lang_stat_tracking(compiler, tempdir);
}

fn test_hip_compiles(compiler: &Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("run_sccache_command_test: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_HIP_A, INPUT_FOR_HIP_B], tempdir);

    let target_arch = vec!["gfx900".to_string()];

    let out_file = tempdir.join(OUTPUT);
    trace!("compile A");
    sccache_command()
        .args(&compile_hip_cmdline(
            name,
            exe,
            INPUT_FOR_HIP_A,
            OUTPUT,
            &target_arch,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_misses.get("HIP").unwrap());
        let adv_hip_key = adv_key_kind("hip", compiler.name);
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_hip_key).unwrap());
    });
    trace!("compile A");
    fs::remove_file(&out_file).unwrap();
    sccache_command()
        .args(&compile_hip_cmdline(
            name,
            exe,
            INPUT_FOR_HIP_A,
            OUTPUT,
            &target_arch,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("HIP").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("HIP").unwrap());
        let adv_hip_key = adv_key_kind("hip", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_hip_key).unwrap());
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_hip_key).unwrap());
    });
    // By compiling another input source we verify that the pre-processor
    // phase is correctly running and outputting text
    trace!("compile B");
    sccache_command()
        .args(&compile_hip_cmdline(
            name,
            exe,
            INPUT_FOR_HIP_B,
            OUTPUT,
            &target_arch,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(3, info.stats.compile_requests);
        assert_eq!(3, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("HIP").unwrap());
        assert_eq!(&2, info.stats.cache_misses.get("HIP").unwrap());
        let adv_hip_key = adv_key_kind("hip", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_hip_key).unwrap());
        assert_eq!(&2, info.stats.cache_misses.get_adv(&adv_hip_key).unwrap());
    });
}

fn test_hip_compiles_multi_targets(compiler: &Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("run_sccache_command_test: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_HIP_A, INPUT_FOR_HIP_B], tempdir);

    let target_arches: Vec<String> = vec!["gfx900".to_string(), "gfx1030".to_string()];

    let out_file = tempdir.join(OUTPUT);
    trace!("compile A with gfx900 and gfx1030");
    sccache_command()
        .args(&compile_hip_cmdline(
            name,
            exe,
            INPUT_FOR_HIP_A,
            OUTPUT,
            &target_arches,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_misses.get("HIP").unwrap());
        let adv_hip_key = adv_key_kind("hip", compiler.name);
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_hip_key).unwrap());
    });

    trace!("compile A with with gfx900 and gfx1030 again");
    fs::remove_file(&out_file).unwrap();
    sccache_command()
        .args(&compile_hip_cmdline(
            name,
            exe,
            INPUT_FOR_HIP_A,
            OUTPUT,
            &target_arches,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("HIP").unwrap());
        assert_eq!(&1, info.stats.cache_misses.get("HIP").unwrap());
        let adv_hip_key = adv_key_kind("hip", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_hip_key).unwrap());
        assert_eq!(&1, info.stats.cache_misses.get_adv(&adv_hip_key).unwrap());
    });

    // By compiling another input source we verify that the pre-processor
    // phase is correctly running and outputting text
    trace!("compile B with gfx900 and gfx1030");
    sccache_command()
        .args(&compile_hip_cmdline(
            name,
            exe,
            INPUT_FOR_HIP_B,
            OUTPUT,
            &target_arches,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    get_stats(|info| {
        assert_eq!(3, info.stats.compile_requests);
        assert_eq!(3, info.stats.requests_executed);
        assert_eq!(1, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
        assert_eq!(&1, info.stats.cache_hits.get("HIP").unwrap());
        assert_eq!(&2, info.stats.cache_misses.get("HIP").unwrap());
        let adv_hip_key = adv_key_kind("hip", compiler.name);
        assert_eq!(&1, info.stats.cache_hits.get_adv(&adv_hip_key).unwrap());
        assert_eq!(&2, info.stats.cache_misses.get_adv(&adv_hip_key).unwrap());
    });
}

fn run_sccache_hip_command_tests(compiler: Compiler, tempdir: &Path) {
    zero_stats();
    test_hip_compiles(&compiler, tempdir);
    zero_stats();
    test_hip_compiles_multi_targets(&compiler, tempdir);
    // test_proper_lang_stat_tracking(compiler, tempdir);
}

fn test_clang_multicall(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    println!("test_clang_multicall: {}", name);
    // Compile a source file.
    copy_to_tempdir(&[INPUT_CLANG_MULTICALL], tempdir);

    println!("compile clang_multicall");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT_CLANG_MULTICALL,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
}

fn test_clang_cache_whitespace_normalization(
    compiler: Compiler,
    tempdir: &Path,
    hit: bool,
    preprocessor_cache_mode: bool,
) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    println!("run_sccache_command_test: {}", name);
    println!("expecting hit: {}", hit);
    // Compile a source file.
    copy_to_tempdir(&[INPUT_WITH_WHITESPACE, INPUT_WITH_WHITESPACE_ALT], tempdir);
    zero_stats();

    println!("compile whitespace");
    sccache_command()
        .args(&compile_cmdline(
            name,
            &exe,
            INPUT_WITH_WHITESPACE,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    println!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });

    println!("compile whitespace_alt");
    sccache_command()
        .args(&compile_cmdline(
            name,
            &exe,
            INPUT_WITH_WHITESPACE_ALT,
            OUTPUT,
            Vec::new(),
        ))
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    println!("request stats (expecting cache hit)");
    if hit {
        get_stats(move |info| {
            assert_eq!(2, info.stats.compile_requests);
            assert_eq!(2, info.stats.requests_executed);
            if preprocessor_cache_mode {
                // Preprocessor cache mode hashes the input file, so whitespace
                // normalization does not work.
                assert_eq!(0, info.stats.cache_hits.all());
                assert_eq!(2, info.stats.cache_misses.all());
            } else {
                assert_eq!(1, info.stats.cache_hits.all());
                assert_eq!(1, info.stats.cache_misses.all());
            }
        });
    } else {
        get_stats(|info| {
            assert_eq!(2, info.stats.compile_requests);
            assert_eq!(2, info.stats.requests_executed);
            assert_eq!(0, info.stats.cache_hits.all());
            assert_eq!(2, info.stats.cache_misses.all());
        });
    }
}

#[cfg(unix)]
fn find_compilers() -> Vec<Compiler> {
    let cwd = env::current_dir().unwrap();
    COMPILERS
        .iter()
        .filter_map(|c| {
            which_in(c, env::var_os("PATH"), &cwd)
                .ok()
                .map(|full_path| Compiler {
                    name: c,
                    exe: full_path.into(),
                    env_vars: vec![],
                })
        })
        .collect::<Vec<_>>()
}

#[cfg(target_env = "msvc")]
fn find_compilers() -> Vec<Compiler> {
    let tool = cc::Build::new()
        .opt_level(1)
        .host("x86_64-pc-windows-msvc")
        .target("x86_64-pc-windows-msvc")
        .debug(false)
        .get_compiler();
    vec![Compiler {
        name: "cl.exe",
        exe: tool.path().as_os_str().to_os_string(),
        env_vars: tool.env().to_vec(),
    }]
}

fn find_cuda_compilers() -> Vec<Compiler> {
    let cwd = env::current_dir().unwrap();
    // CUDA compilers like clang don't come with all of the components for compilation.
    // To consider a machine to have any cuda compilers we rely on the existence of `nvcc`
    let compilers = match which("nvcc") {
        Ok(_) => CUDA_COMPILERS
            .iter()
            .filter_map(|c| {
                which_in(c, env::var_os("PATH"), &cwd)
                    .ok()
                    .map(|full_path| Compiler {
                        name: c,
                        exe: full_path.into(),
                        env_vars: vec![],
                    })
            })
            .collect::<Vec<_>>(),
        Err(_) => vec![],
    };
    compilers
}

// We detect the HIP Clang compiler through 2 methods:
// 1. If the env var HIP_CLANG_PATH is set, try $HIP_CLANG_PATH/clang. This is the same behavior as
//    hipcc, but is rarely know, so we have another option.
// 2. If the env var ROCM_PATH is set, try $ROCM_PATH/llvm/bin/clang. This is the location in
//    AMD's official debian packages.
// 3. Otherwise, just bail.
fn find_hip_compiler() -> Option<Compiler> {
    let env_vars: Vec<(OsString, OsString)> = env::vars_os().collect();

    if let Ok(hip_clang_path) = env::var("HIP_CLANG_PATH") {
        let clang_path = Path::new(&hip_clang_path).join("clang");

        if let Ok(true) = clang_path.try_exists() {
            return Some(Compiler {
                name: "clang",
                exe: clang_path.into_os_string(),
                env_vars,
            });
        }
    }
    if let Ok(rocm_path) = env::var("ROCM_PATH") {
        let clang_path = Path::new(&rocm_path).join("llvm").join("bin").join("clang");

        if let Ok(true) = clang_path.try_exists() {
            return Some(Compiler {
                name: "hip",
                exe: clang_path.into_os_string(),
                env_vars,
            });
        }
    }
    None
}

// TODO: This runs multiple test cases, for multiple compilers. It should be
// split up to run them individually. In the current form, it is hard to see
// which sub test cases are executed, and if one fails, the remaining tests
// are not run.
#[test_case(true ; "with preprocessor cache")]
#[test_case(false ; "without preprocessor cache")]
#[serial]
#[cfg(any(unix, target_env = "msvc"))]
fn test_sccache_command(preprocessor_cache_mode: bool) {
    let _ = env_logger::try_init();
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_system_test")
        .tempdir()
        .unwrap();
    let compilers = find_compilers();
    if compilers.is_empty() {
        warn!("No compilers found, skipping test");
    } else {
        // Ensure there's no existing sccache server running.
        stop_local_daemon();
        // Create the configurations
        let sccache_cfg = sccache_client_cfg(tempdir.path(), preprocessor_cache_mode);
        write_json_cfg(tempdir.path(), "sccache-cfg.json", &sccache_cfg);
        let sccache_cached_cfg_path = tempdir.path().join("sccache-cached-cfg");
        // Start a server.
        trace!("start server");
        start_local_daemon(
            &tempdir.path().join("sccache-cfg.json"),
            &sccache_cached_cfg_path,
        );
        for compiler in compilers {
            run_sccache_command_tests(compiler, tempdir.path(), preprocessor_cache_mode);
            zero_stats();
        }
        stop_local_daemon();
    }
}

#[test]
#[serial]
fn test_stats_no_server() {
    // Ensure there's no existing sccache server running.
    stop_local_daemon();
    get_stats(|_| {});
    assert!(
        !stop_local_daemon(),
        "Server shouldn't be running after --show-stats"
    );
}

#[test_case(true ; "with preprocessor cache")]
#[test_case(false ; "without preprocessor cache")]
#[serial]
#[cfg(any(unix, target_env = "msvc"))]
fn test_cuda_sccache_command(preprocessor_cache_mode: bool) {
    let _ = env_logger::try_init();
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_system_test")
        .tempdir()
        .unwrap();
    let compilers = find_cuda_compilers();
    if compilers.is_empty() {
        warn!("No compilers found, skipping test");
    } else {
        // Ensure there's no existing sccache server running.
        stop_local_daemon();
        // Create the configurations
        let sccache_cfg = sccache_client_cfg(tempdir.path(), preprocessor_cache_mode);
        write_json_cfg(tempdir.path(), "sccache-cfg.json", &sccache_cfg);
        let sccache_cached_cfg_path = tempdir.path().join("sccache-cached-cfg");
        // Start a server.
        trace!("start server");
        start_local_daemon(
            &tempdir.path().join("sccache-cfg.json"),
            &sccache_cached_cfg_path,
        );
        for compiler in compilers {
            run_sccache_cuda_command_tests(compiler, tempdir.path());
            zero_stats();
        }
        stop_local_daemon();
    }
}

#[test_case(true ; "with preprocessor cache")]
#[test_case(false ; "without preprocessor cache")]
#[serial]
#[cfg(any(unix, target_env = "msvc"))]
fn test_hip_sccache_command(preprocessor_cache_mode: bool) {
    let _ = env_logger::try_init();
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_system_test")
        .tempdir()
        .unwrap();

    if let Some(compiler) = find_hip_compiler() {
        stop_local_daemon();
        // Create the configurations
        let sccache_cfg = sccache_client_cfg(tempdir.path(), preprocessor_cache_mode);
        write_json_cfg(tempdir.path(), "sccache-cfg.json", &sccache_cfg);
        let sccache_cached_cfg_path = tempdir.path().join("sccache-cached-cfg");
        // Start a server.
        trace!("start server");
        start_local_daemon(
            &tempdir.path().join("sccache-cfg.json"),
            &sccache_cached_cfg_path,
        );
        run_sccache_hip_command_tests(compiler, tempdir.path());
        zero_stats();
        stop_local_daemon();
    }
}
