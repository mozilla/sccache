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
    get_stats, sccache_client_cfg, sccache_command, server_info, start_local_daemon,
    stop_local_daemon, write_json_cfg, write_source, zero_stats,
};
use assert_cmd::prelude::*;
use fs::File;
use fs_err as fs;
use log::Level::Trace;
use predicates::prelude::*;
use regex::Regex;
use sccache::compiler::{CCompilerKind, CompilerKind, Language};
use sccache::server::{ServerInfo, ServerStats};
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
        "nvcc" => match lang {
            "cudafe++" => "cuda [cudafe++]".to_owned(),
            "ptx" => language + " [cicc]",
            "cubin" => language + " [ptxas]",
            _ => language + " [nvcc]",
        },
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
    compile_flag: &str,
    input: &str,
    output: &str,
    extra_args: &[OsString],
) -> Vec<OsString> {
    let mut arg = match compiler {
        "nvcc" => vec_from!(OsString, exe.as_ref(), compile_flag, input, "-o", output),
        "clang++" => {
            vec_from!(
                OsString,
                exe,
                compile_flag,
                input,
                "--cuda-gpu-arch=sm_70",
                format!(
                    "--cuda-path={}",
                    env::var_os("CUDA_PATH")
                        .or(env::var_os("CUDA_HOME"))
                        .unwrap_or("/usr/local/cuda".into())
                        .to_string_lossy()
                ),
                "--no-cuda-version-check",
                // work around for clang-cuda on windows-2019 (https://github.com/microsoft/STL/issues/2359)
                "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH",
                "-o",
                output
            )
        }
        _ => panic!("Unsupported compiler: {}", compiler),
    };
    if !extra_args.is_empty() {
        arg.append(&mut extra_args.to_vec())
    }
    arg.iter().filter(|x| *x != "").cloned().collect::<Vec<_>>()
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
const INPUT_FOR_CUDA_A_COPY: &str = "test_a_copy.cu";
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
    println!("test_basic_compile: {}", name);
    // Compile a source file.
    copy_to_tempdir(&[INPUT, INPUT_ERR], tempdir);

    let out_file = tempdir.join(OUTPUT);
    trace!("compile");
    sccache_command()
        .args(compile_cmdline(name, &exe, INPUT, OUTPUT, Vec::new()))
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
        .args(compile_cmdline(name, &exe, INPUT, OUTPUT, Vec::new()))
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
    println!("test_noncacheable_stats: {}", name);
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

/* test case like this:
    echo "int test(){}" > test.cc
    mkdir o1 o2
    sccache g++ -c -g -gsplit-dwarf test.cc -o test1.o
    sccache g++ -c -g -gsplit-dwarf test.cc -o test1.o   --- > cache hit
    sccache g++ -c -g -gsplit-dwarf test.cc -o test2.o   --- > cache miss
    strings test2.o |grep test2.dwo
*/
fn test_split_dwarf_object_generate_output_dir_changes(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    trace!("test -g -gsplit-dwarf with different output");
    zero_stats();
    const SRC: &str = "source.c";
    write_source(tempdir, SRC, "int test(){}");
    let mut args = compile_cmdline(name, exe.clone(), SRC, "test1.o", Vec::new());
    args.extend(vec_from!(OsString, "-g"));
    args.extend(vec_from!(OsString, "-gsplit-dwarf"));
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
    // Compile the same source again with different output
    // to ensure we can force generate new object file.
    let mut args2 = compile_cmdline(name, exe, SRC, "test2.o", Vec::new());
    args2.extend(vec_from!(OsString, "-g"));
    args2.extend(vec_from!(OsString, "-gsplit-dwarf"));
    trace!("compile source.c (2)");
    sccache_command()
        .args(&args2)
        .current_dir(tempdir)
        .envs(env_vars.clone())
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
    println!("test_gcc_clang_no_warnings_from_macro_expansion: {}", name);
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
    println!("test_compile_with_define: {}", name);
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

fn test_gcc_clang_depfile(compiler: Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    println!("test_gcc_clang_depfile: {}", name);
    copy_to_tempdir(&[INPUT], tempdir);
    fs::copy(tempdir.join(INPUT), tempdir.join("same-content.c")).unwrap();

    trace!("compile");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe.clone(),
            INPUT,
            OUTPUT,
            Vec::new(),
        ))
        .args(vec_from!(OsString, "-MD", "-MF", "first.d"))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            "same-content.c",
            "same-content.o",
            Vec::new(),
        ))
        .args(vec_from!(OsString, "-MD", "-MF", "second.d"))
        .current_dir(tempdir)
        .envs(env_vars)
        .assert()
        .success();
    let mut first = String::new();
    let mut second = String::new();
    File::open(tempdir.join("first.d"))
        .unwrap()
        .read_to_string(&mut first)
        .unwrap();
    File::open(tempdir.join("second.d"))
        .unwrap()
        .read_to_string(&mut second)
        .unwrap();
    assert_ne!(first, second);
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
        test_split_dwarf_object_generate_output_dir_changes(compiler.clone(), tempdir);
        test_gcc_clang_depfile(compiler.clone(), tempdir);
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

#[derive(Clone, Debug, Default)]
struct AdditionalStats {
    cache_writes: Option<u64>,
    compilations: Option<u64>,
    compile_requests: Option<u64>,
    requests_executed: Option<u64>,
    requests_not_compile: Option<u64>,
    cache_hits: Option<Vec<(CCompilerKind, Language, u64)>>,
    cache_misses: Option<Vec<(CCompilerKind, Language, u64)>>,
}

fn test_nvcc_cuda_compiles(compiler: &Compiler, tempdir: &Path, with_debug_flags: bool) {
    let mut stats = server_info().stats;

    let extra_args = if with_debug_flags {
        vec!["-G".into()]
    } else {
        vec![]
    };

    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    println!("test_nvcc_cuda_compiles: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(
        &[INPUT_FOR_CUDA_A, INPUT_FOR_CUDA_A_COPY, INPUT_FOR_CUDA_B],
        tempdir,
    );

    let mut run_cuda_test = |compile_flag: &str,
                             input: &Path,
                             output: &Path,
                             extra_args: &[OsString],
                             additional_stats: AdditionalStats| {
        sccache_command()
            .args(compile_cuda_cmdline(
                name,
                exe,
                compile_flag,
                input.to_string_lossy().as_ref(),
                output.to_string_lossy().as_ref(),
                extra_args,
            ))
            .current_dir(tempdir)
            .envs(env_vars.clone())
            .assert()
            .success();

        assert!(fs::metadata(tempdir.join(output))
            .map(|m| m.len() > 0)
            .unwrap());

        fs::remove_file(tempdir.join(output)).unwrap();

        stats.cache_writes += additional_stats.cache_writes.unwrap_or(0);
        stats.compilations += additional_stats.compilations.unwrap_or(0);
        stats.compile_requests += additional_stats.compile_requests.unwrap_or(0);
        stats.requests_executed += additional_stats.requests_executed.unwrap_or(0);
        stats.requests_not_compile += additional_stats.requests_not_compile.unwrap_or(0);
        stats.non_cacheable_compilations += 1;

        for (kind, lang, count) in additional_stats.cache_hits.unwrap_or_default() {
            let kind = CompilerKind::C(kind);
            for _ in 0..count {
                stats.cache_hits.increment(&kind, &lang);
            }
        }

        for (kind, lang, count) in additional_stats.cache_misses.unwrap_or_default() {
            let kind = CompilerKind::C(kind);
            for _ in 0..count {
                stats.cache_misses.increment(&kind, &lang);
            }
        }

        assert_eq!(
            stats,
            ServerStats {
                cache_write_duration: stats.cache_write_duration,
                cache_read_hit_duration: stats.cache_read_hit_duration,
                compiler_write_duration: stats.compiler_write_duration,
                ..server_info().stats
            }
        );
    };

    trace!("compile A ptx");
    run_cuda_test(
        "-ptx",
        Path::new(INPUT_FOR_CUDA_A), // relative path for input
        Path::new("test.ptx"),       // relative path for output
        &extra_args,
        AdditionalStats {
            cache_writes: Some(1),
            compilations: Some(2),
            compile_requests: Some(1),
            requests_executed: Some(2),
            cache_misses: Some(vec![(CCompilerKind::Cicc, Language::Ptx, 1)]),
            ..Default::default()
        },
    );

    trace!("compile A cubin");
    run_cuda_test(
        "-cubin",
        Path::new(INPUT_FOR_CUDA_A), // relative path for input
        &tempdir.join("test.cubin"), // absolute path for output
        &extra_args,
        AdditionalStats {
            cache_writes: Some(1),
            compilations: Some(2),
            compile_requests: Some(1),
            requests_executed: Some(3),
            cache_hits: Some(vec![(CCompilerKind::Cicc, Language::Ptx, 1)]),
            cache_misses: Some(vec![(CCompilerKind::Ptxas, Language::Cubin, 1)]),
            ..Default::default()
        },
    );

    trace!("compile A");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_A), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &extra_args,
        AdditionalStats {
            cache_writes: Some(2),
            compilations: Some(3),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
            ]),
            ..Default::default()
        },
    );

    trace!("compile A (cached)");
    run_cuda_test(
        "-c",
        &tempdir.join(INPUT_FOR_CUDA_A), // absolute path for input
        &tempdir.join(OUTPUT),           // absolute path for output
        &extra_args,
        AdditionalStats {
            compilations: Some(1),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_hits: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Compile a copy of `test_a.cu` to ensure we get cache hits for identical PTX across different files.
    trace!("compile A (copy)");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_A_COPY), // relative path for input
        Path::new(OUTPUT),                // relative path for output
        &extra_args,
        // Since `test_a_copy.cu` is a copy of `test_a.cu`, its PTX will be identical when *not* using -G.
        // But -G causes cudafe++ and cicc to embed the source path their output, and we get cache misses.
        AdditionalStats {
            cache_writes: Some(3 + with_debug_flags as u64),
            compilations: Some(4 + with_debug_flags as u64),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_hits: Some(vec![(
                CCompilerKind::Ptxas,
                Language::Cubin,
                !with_debug_flags as u64,
            )]),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (
                    CCompilerKind::Ptxas,
                    Language::Cubin,
                    with_debug_flags as u64,
                ),
            ]),
            ..Default::default()
        },
    );

    trace!("compile A (copy) (cached)");
    run_cuda_test(
        "-c",
        &tempdir.join(INPUT_FOR_CUDA_A_COPY), // absolute path for input
        &tempdir.join(OUTPUT),                // absolute path for output
        &extra_args,
        AdditionalStats {
            compilations: Some(1),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_hits: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // By compiling another input source we verify that the pre-processor
    // phase is correctly running and outputting text
    trace!("compile B");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_B), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &extra_args,
        AdditionalStats {
            cache_writes: Some(4),
            compilations: Some(5),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    trace!("compile B (cached)");
    run_cuda_test(
        "-c",
        &tempdir.join(INPUT_FOR_CUDA_B), // absolute path for input
        &tempdir.join(OUTPUT),           // absolute path for output
        &extra_args,
        AdditionalStats {
            compilations: Some(1),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_hits: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Test to ensure #2299 doesn't regress (https://github.com/mozilla/sccache/issues/2299)
    let test_2299_src_name = "test_2299.cu";
    let test_2299_out_name = "test_2299.cu.o";
    // Two versions of the source with different contents inside the #ifndef __CUDA_ARCH__
    let test_2299_cu_src_1 = "
#ifndef __CUDA_ARCH__
static const auto x = 5;
#endif
int main(int argc, char** argv) {
  return 0;
}
";
    let test_2299_cu_src_2 = "
#ifndef __CUDA_ARCH__
static const auto x = \"5\";
#endif
int main(int argc, char** argv) {
  return 0;
}
";
    write_source(tempdir, test_2299_src_name, test_2299_cu_src_1);
    run_cuda_test(
        "-c",
        Path::new(test_2299_src_name), // relative path for input
        Path::new(test_2299_out_name), // relative path for output
        &extra_args,
        AdditionalStats {
            cache_writes: Some(4),
            compilations: Some(5),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    write_source(tempdir, test_2299_src_name, test_2299_cu_src_2);
    trace!("compile test_2299.cu (2)");
    run_cuda_test(
        "-c",
        Path::new(test_2299_src_name), // relative path for input
        Path::new(test_2299_out_name), // relative path for output
        &extra_args,
        AdditionalStats {
            cache_writes: Some(2),
            compilations: Some(3),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
            ]),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Recompile the original version again to ensure only cache hits
    write_source(tempdir, test_2299_src_name, test_2299_cu_src_1);
    trace!("compile test_2299.cu (3)");
    run_cuda_test(
        "-c",
        &tempdir.join(test_2299_src_name), // absolute path for input
        &tempdir.join(test_2299_out_name), // absolute path for output
        &extra_args,
        AdditionalStats {
            compilations: Some(1),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_hits: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Precompile sm_86 PTX and cubin so their cache entries potentially have a different .module_id file
    trace!("compile A cubin sm_86");
    run_cuda_test(
        "-cubin",
        Path::new(INPUT_FOR_CUDA_A), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &[
            extra_args.as_slice(),
            &["-gencode=arch=compute_86,code=[sm_86]".into()],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(2),
            compilations: Some(3),
            compile_requests: Some(1),
            requests_executed: Some(3),
            cache_misses: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Test compiling a file whose PTX yields a cache hit for a cubin from another file (`test_a.cu`)
    trace!("compile B cubin sm_86");
    run_cuda_test(
        "-cubin",
        Path::new(INPUT_FOR_CUDA_B), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &[
            extra_args.as_slice(),
            &["-gencode=arch=compute_86,code=[sm_86]".into()],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(1 + with_debug_flags as u64),
            compilations: Some(2 + with_debug_flags as u64),
            compile_requests: Some(1),
            requests_executed: Some(3),
            cache_hits: Some(vec![(
                CCompilerKind::Ptxas,
                Language::Cubin,
                !with_debug_flags as u64,
            )]),
            cache_misses: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (
                    CCompilerKind::Ptxas,
                    Language::Cubin,
                    with_debug_flags as u64,
                ),
            ]),
            ..Default::default()
        },
    );

    // Test compiling a multiarch object where the PTX and cubin for one of the archs is cached
    trace!("compile A sm_80,sm_86");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_A), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &[
            extra_args.as_slice(),
            &[
                "-gencode=arch=compute_80,code=[sm_80]".into(),
                "-gencode=arch=compute_86,code=[compute_86,sm_86]".into(),
            ],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(4),
            compilations: Some(5),
            compile_requests: Some(1),
            requests_executed: Some(7),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Test compiling a multiarch object of a different source file, but
    // whose device code is the same as a previously-compiled files'
    trace!("compile A (copy) sm_80,sm_86");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_A_COPY), // relative path for input
        Path::new(OUTPUT),                // relative path for output
        &[
            extra_args.as_slice(),
            &[
                "-gencode=arch=compute_80,code=[sm_80]".into(),
                "-gencode=arch=compute_86,code=[compute_86,sm_86]".into(),
            ],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(4 + 2 * with_debug_flags as u64),
            compilations: Some(5 + 2 * with_debug_flags as u64),
            compile_requests: Some(1),
            requests_executed: Some(7),
            cache_hits: Some(vec![(
                CCompilerKind::Ptxas,
                Language::Cubin,
                2 * !with_debug_flags as u64,
            )]),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 2),
                (
                    CCompilerKind::Ptxas,
                    Language::Cubin,
                    2 * with_debug_flags as u64,
                ),
            ]),
            ..Default::default()
        },
    );

    trace!("compile B sm_80,sm_86");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_B), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &[
            extra_args.as_slice(),
            &[
                "-gencode=arch=compute_80,code=[sm_80]".into(),
                "-gencode=arch=compute_86,code=[compute_86,sm_86]".into(),
            ],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(4),
            compilations: Some(5),
            compile_requests: Some(1),
            requests_executed: Some(7),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Test that compiling a single-arch object where the arch is a subset of
    // a previous multi-arch compilation produces cache hits on the underlying
    // PTX and cubin compilations.
    trace!("compile A sm_80");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_A), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &[
            extra_args.as_slice(),
            &["-gencode=arch=compute_80,code=[compute_80,sm_80]".into()],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(2),
            compilations: Some(3),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
            ]),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    trace!("compile B sm_80");
    run_cuda_test(
        "-c",
        Path::new(INPUT_FOR_CUDA_B), // relative path for input
        Path::new(OUTPUT),           // relative path for output
        &[
            extra_args.as_slice(),
            &["-gencode=arch=compute_80,code=[compute_80,sm_80]".into()],
        ]
        .concat(),
        AdditionalStats {
            cache_writes: Some(2),
            compilations: Some(3),
            compile_requests: Some(1),
            requests_executed: Some(5),
            cache_misses: Some(vec![
                (CCompilerKind::Nvcc, Language::Cuda, 1),
                (CCompilerKind::CudaFE, Language::CudaFE, 1),
            ]),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    // Test that compiling a single-arch cubin where the arch is a subset of
    // a previous multi-arch compilation produces cache hits on the underlying
    // PTX and cubin compilations.
    trace!("compile A cubin sm_80");
    run_cuda_test(
        "-cubin",
        &tempdir.join(INPUT_FOR_CUDA_A), // absolute path for input
        &tempdir.join("test.cubin"),     // absolute path for output
        &[
            extra_args.as_slice(),
            &["-gencode=arch=compute_80,code=[sm_80]".into()],
        ]
        .concat(),
        AdditionalStats {
            compilations: Some(1),
            compile_requests: Some(1),
            requests_executed: Some(3),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    trace!("compile B cubin sm_80");
    run_cuda_test(
        "-cubin",
        &tempdir.join(INPUT_FOR_CUDA_B), // absolute path for input
        &tempdir.join("test.cubin"),     // absolute path for output
        &[
            extra_args.as_slice(),
            &["-gencode=arch=compute_80,code=[sm_80]".into()],
        ]
        .concat(),
        AdditionalStats {
            compilations: Some(1),
            compile_requests: Some(1),
            requests_executed: Some(3),
            cache_hits: Some(vec![
                (CCompilerKind::Cicc, Language::Ptx, 1),
                (CCompilerKind::Ptxas, Language::Cubin, 1),
            ]),
            ..Default::default()
        },
    );

    if !cfg!(target_os = "windows") {
        // Test compiling an executable (`nvcc -x cu test_a.cu -o test_a`)
        trace!("compile A to executable");
        run_cuda_test(
            "",
            Path::new(INPUT_FOR_CUDA_A), // relative path for input
            Path::new("test_a"),         // relative path for output
            &[
                extra_args.as_slice(),
                &[
                    "-gencode=arch=compute_80,code=[sm_80]".into(),
                    "-gencode=arch=compute_86,code=[compute_86,sm_86]".into(),
                ],
            ]
            .concat(),
            AdditionalStats {
                cache_writes: Some(1),
                compilations: Some(2),
                compile_requests: Some(1),
                requests_executed: Some(8),
                cache_hits: Some(vec![
                    (CCompilerKind::Nvcc, Language::Cuda, 1),
                    (CCompilerKind::CudaFE, Language::CudaFE, 1),
                    (CCompilerKind::Cicc, Language::Ptx, 2),
                    (CCompilerKind::Ptxas, Language::Cubin, 2),
                ]),
                cache_misses: Some(vec![(CCompilerKind::Nvcc, Language::Cuda, 1)]),
                ..Default::default()
            },
        );

        // Test compiling an executable (`nvcc -x cu test_a_copy.cu -o test_a_copy`)
        trace!("compile A (copy) to executable");
        run_cuda_test(
            "",
            Path::new(INPUT_FOR_CUDA_A_COPY), // relative path for input
            Path::new("test_a_copy"),         // relative path for output
            &[
                extra_args.as_slice(),
                &[
                    "-gencode=arch=compute_80,code=[sm_80]".into(),
                    "-gencode=arch=compute_86,code=[compute_86,sm_86]".into(),
                ],
            ]
            .concat(),
            AdditionalStats {
                cache_writes: Some(1),
                compilations: Some(2),
                compile_requests: Some(1),
                requests_executed: Some(8),
                cache_hits: Some(vec![
                    (CCompilerKind::Nvcc, Language::Cuda, 1),
                    (CCompilerKind::CudaFE, Language::CudaFE, 1),
                    (CCompilerKind::Cicc, Language::Ptx, 2),
                    (CCompilerKind::Ptxas, Language::Cubin, 2),
                ]),
                cache_misses: Some(vec![(CCompilerKind::Nvcc, Language::Cuda, 1)]),
                ..Default::default()
            },
        );

        // Test compiling an executable (`nvcc -x cu test_b.cu -o test_b`)
        trace!("compile B to executable");
        run_cuda_test(
            "",
            Path::new(INPUT_FOR_CUDA_B), // relative path for input
            Path::new("test_b"),         // relative path for output
            &[
                extra_args.as_slice(),
                &[
                    "-gencode=arch=compute_80,code=[sm_80]".into(),
                    "-gencode=arch=compute_86,code=[compute_86,sm_86]".into(),
                ],
            ]
            .concat(),
            AdditionalStats {
                cache_writes: Some(1),
                compilations: Some(2),
                compile_requests: Some(1),
                requests_executed: Some(8),
                cache_hits: Some(vec![
                    (CCompilerKind::Nvcc, Language::Cuda, 1),
                    (CCompilerKind::CudaFE, Language::CudaFE, 1),
                    (CCompilerKind::Cicc, Language::Ptx, 2),
                    (CCompilerKind::Ptxas, Language::Cubin, 2),
                ]),
                cache_misses: Some(vec![(CCompilerKind::Nvcc, Language::Cuda, 1)]),
                ..Default::default()
            },
        );
    }
}

fn test_nvcc_proper_lang_stat_tracking(
    compiler: &Compiler,
    tempdir: &Path,
    with_debug_flags: bool,
) {
    let mut stats = server_info().stats;

    let extra_args = if with_debug_flags {
        vec!["--device-debug".into()]
    } else {
        vec![]
    };

    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;

    println!("test_nvcc_proper_lang_stat_tracking: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_CUDA_C, INPUT], tempdir);

    let out_file = tempdir.join(OUTPUT);

    trace!("compile CUDA C");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT_FOR_CUDA_C,
            OUTPUT,
            extra_args.clone(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();

    stats.cache_writes += 4;
    stats.compilations += 5;
    stats.compile_requests += 1;
    stats.requests_executed += 5;
    stats.non_cacheable_compilations += 1;
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Nvcc), &Language::Cuda);
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::CudaFE), &Language::CudaFE);
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Cicc), &Language::Ptx);
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Ptxas), &Language::Cubin);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile CUDA C");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT_FOR_CUDA_C,
            OUTPUT,
            extra_args.clone(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();

    stats.compilations += 1;
    stats.compile_requests += 1;
    stats.requests_executed += 5;
    stats.non_cacheable_compilations += 1;
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Nvcc), &Language::Cuda);
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::CudaFE), &Language::CudaFE);
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Cicc), &Language::Ptx);
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Ptxas), &Language::Cubin);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile C++");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT,
            OUTPUT,
            extra_args.clone(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();

    stats.cache_writes += 1;
    stats.compilations += 2;
    stats.compile_requests += 1;
    stats.requests_executed += 2;
    stats.non_cacheable_compilations += 1;
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Nvcc), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile C++");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT,
            OUTPUT,
            extra_args.clone(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();

    stats.compilations += 1;
    stats.compile_requests += 1;
    stats.requests_executed += 2;
    stats.non_cacheable_compilations += 1;
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Nvcc), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );
}

fn run_sccache_nvcc_cuda_command_tests(compiler: Compiler, tempdir: &Path, with_debug_flags: bool) {
    test_nvcc_cuda_compiles(&compiler, tempdir, with_debug_flags);
    test_nvcc_proper_lang_stat_tracking(&compiler, tempdir, with_debug_flags);
}

fn test_clang_cuda_compiles(compiler: &Compiler, tempdir: &Path, with_debug_flags: bool) {
    let mut stats = server_info().stats;

    let extra_args = if with_debug_flags {
        vec!["-g".into(), "--cuda-noopt-device-debug".into()]
    } else {
        vec![]
    };

    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    println!("test_clang_cuda_compiles: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_CUDA_A, INPUT_FOR_CUDA_B], tempdir);

    let out_file = tempdir.join(OUTPUT);
    trace!("compile A");
    sccache_command()
        .args(compile_cuda_cmdline(
            name,
            exe,
            "-c",
            INPUT_FOR_CUDA_A,
            OUTPUT,
            &extra_args,
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    stats.cache_writes += 1;
    stats.compilations += 1;
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile A");
    fs::remove_file(&out_file).unwrap();
    sccache_command()
        .args(compile_cuda_cmdline(
            name,
            exe,
            "-c",
            INPUT_FOR_CUDA_A,
            OUTPUT,
            &extra_args,
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    // By compiling another input source we verify that the pre-processor
    // phase is correctly running and outputting text
    trace!("compile B");
    sccache_command()
        .args(compile_cuda_cmdline(
            name,
            exe,
            "-c",
            INPUT_FOR_CUDA_B,
            OUTPUT,
            &extra_args,
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    assert!(fs::metadata(&out_file).map(|m| m.len() > 0).unwrap());
    trace!("request stats");
    stats.cache_writes += 1;
    stats.compilations += 1;
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );
}

fn test_clang_proper_lang_stat_tracking(
    compiler: &Compiler,
    tempdir: &Path,
    with_debug_flags: bool,
) {
    let mut stats = server_info().stats;

    let extra_args = if with_debug_flags {
        vec!["-g".into(), "--cuda-noopt-device-debug".into()]
    } else {
        vec![]
    };

    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;

    println!("test_clang_proper_lang_stat_tracking: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_CUDA_C, INPUT], tempdir);

    let out_file = tempdir.join(OUTPUT);
    trace!("compile CUDA A");
    sccache_command()
        .args(compile_cuda_cmdline(
            name,
            exe,
            "-c",
            INPUT_FOR_CUDA_C,
            OUTPUT,
            &extra_args,
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    stats.cache_writes += 1;
    stats.compilations += 1;
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile CUDA A");
    sccache_command()
        .args(compile_cuda_cmdline(
            name,
            exe,
            "-c",
            INPUT_FOR_CUDA_C,
            OUTPUT,
            &extra_args,
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cuda);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile C++ A");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT,
            OUTPUT,
            extra_args.clone(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    stats.cache_writes += 1;
    stats.compilations += 1;
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_misses
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cxx);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );

    trace!("compile C++ A");
    sccache_command()
        .args(compile_cmdline(
            name,
            exe,
            INPUT,
            OUTPUT,
            extra_args.clone(),
        ))
        .current_dir(tempdir)
        .envs(env_vars.clone())
        .assert()
        .success();
    fs::remove_file(&out_file).unwrap();
    stats.compile_requests += 1;
    stats.requests_executed += 1;
    stats
        .cache_hits
        .increment(&CompilerKind::C(CCompilerKind::Clang), &Language::Cxx);
    assert_eq!(
        stats,
        ServerStats {
            cache_write_duration: stats.cache_write_duration,
            cache_read_hit_duration: stats.cache_read_hit_duration,
            compiler_write_duration: stats.compiler_write_duration,
            ..server_info().stats
        }
    );
}

fn run_sccache_clang_cuda_command_tests(
    compiler: Compiler,
    tempdir: &Path,
    with_debug_flags: bool,
) {
    test_clang_cuda_compiles(&compiler, tempdir, with_debug_flags);
    test_clang_proper_lang_stat_tracking(&compiler, tempdir, with_debug_flags);
}

fn test_hip_compiles(compiler: &Compiler, tempdir: &Path) {
    let Compiler {
        name,
        exe,
        env_vars,
    } = compiler;
    println!("test_hip_compiles: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_HIP_A, INPUT_FOR_HIP_B], tempdir);

    let target_arch = vec!["gfx900".to_string()];

    let out_file = tempdir.join(OUTPUT);
    trace!("compile A");
    sccache_command()
        .args(compile_hip_cmdline(
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
        .args(compile_hip_cmdline(
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
        .args(compile_hip_cmdline(
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
    println!("test_hip_compiles_multi_targets: {}", name);
    // Compile multiple source files.
    copy_to_tempdir(&[INPUT_FOR_HIP_A, INPUT_FOR_HIP_B], tempdir);

    let target_arches: Vec<String> = vec!["gfx900".to_string(), "gfx1030".to_string()];

    let out_file = tempdir.join(OUTPUT);
    trace!("compile A with gfx900 and gfx1030");
    sccache_command()
        .args(compile_hip_cmdline(
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
        .args(compile_hip_cmdline(
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
        .args(compile_hip_cmdline(
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
    println!("test_clang_cache_whitespace_normalization: {}", name);
    debug!("expecting hit: {}", hit);
    // Compile a source file.
    copy_to_tempdir(&[INPUT_WITH_WHITESPACE, INPUT_WITH_WHITESPACE_ALT], tempdir);
    zero_stats();

    debug!("compile whitespace");
    sccache_command()
        .args(compile_cmdline(
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
    debug!("request stats");
    get_stats(|info| {
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });

    debug!("compile whitespace_alt");
    sccache_command()
        .args(compile_cmdline(
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
    debug!("request stats (expecting cache hit)");
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
        Err(_) => {
            eprintln!(
                "unable to find `nvcc` in PATH={:?}",
                env::var_os("PATH").unwrap_or_default()
            );
            vec![]
        }
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

#[test_case(true, false ; "with preprocessor cache")]
#[test_case(false, false ; "without preprocessor cache")]
#[test_case(true, true ; "with preprocessor cache and device debug")]
#[test_case(false, true ; "without preprocessor cache and device debug")]
#[serial]
#[cfg(any(unix, target_env = "msvc"))]
fn test_cuda_sccache_command(preprocessor_cache_mode: bool, with_debug_flags: bool) {
    let _ = env_logger::try_init();
    let tempdir = tempfile::Builder::new()
        .prefix("sccache_system_test")
        .tempdir()
        .unwrap();
    let compilers = find_cuda_compilers();
    println!(
        "CUDA compilers: {:?}",
        compilers
            .iter()
            .map(|c| c.exe.to_string_lossy())
            .collect::<Vec<_>>()
    );
    if compilers.is_empty() {
        warn!("No compilers found, skipping test");
    } else {
        // Persist the tempdir if SCCACHE_DEBUG is defined
        let tempdir_pathbuf = if env::var("SCCACHE_DEBUG").is_ok() {
            tempdir.into_path()
        } else {
            tempdir.path().to_path_buf()
        };
        let tempdir_path = tempdir_pathbuf.as_path();

        // Ensure there's no existing sccache server running.
        stop_local_daemon();
        // Create the configurations
        let sccache_cfg = sccache_client_cfg(tempdir_path, preprocessor_cache_mode);
        write_json_cfg(tempdir_path, "sccache-cfg.json", &sccache_cfg);
        let sccache_cached_cfg_path = tempdir_path.join("sccache-cached-cfg");
        // Start a server.
        trace!("start server");
        start_local_daemon(
            &tempdir_path.join("sccache-cfg.json"),
            &sccache_cached_cfg_path,
        );
        for compiler in compilers {
            match compiler.name {
                "nvcc" => {
                    run_sccache_nvcc_cuda_command_tests(compiler, tempdir_path, with_debug_flags)
                }
                "clang++" => {
                    run_sccache_clang_cuda_command_tests(compiler, tempdir_path, with_debug_flags)
                }
                _ => {}
            }
        }
        zero_stats();
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
