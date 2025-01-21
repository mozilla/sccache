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

#![allow(unused_imports, dead_code, unused_variables)]

use crate::compiler::args::*;
use crate::compiler::c::{ArtifactDescriptor, CCompilerImpl, CCompilerKind, ParsedArguments};
use crate::compiler::gcc::ArgData::*;
use crate::compiler::{
    gcc, write_temp_file, CCompileCommand, Cacheable, CompileCommand, CompilerArguments, Language,
};
use crate::mock_command::{CommandCreator, CommandCreatorSync, RunCommand};
use crate::util::{run_input_output, OsStrExt};
use crate::{counted_array, dist};
use async_trait::async_trait;
use fs::File;
use fs_err as fs;
use semver::{BuildMetadata, Prerelease, Version};
use std::ffi::OsString;
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use crate::errors::*;

/// A struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct Clang {
    /// true iff this is clang++.
    pub clangplusplus: bool,
    /// true iff this is Apple's clang(++).
    pub is_appleclang: bool,
    /// String from __VERSION__ macro.
    pub version: Option<String>,
}

impl Clang {
    fn is_minversion(&self, major: u64) -> bool {
        // Apple clang follows its own versioning scheme.
        if self.is_appleclang {
            return false;
        }

        let version_val = match self.version.clone() {
            Some(version_val) => version_val,
            None => return false,
        };

        let version_str = match version_val.split(' ').find(|x| x.contains('.')) {
            Some(version_str) => version_str,
            None => return false,
        };

        let parsed_version = match Version::parse(version_str.trim_end_matches('"')) {
            Ok(parsed_version) => parsed_version,
            Err(e) => return false,
        };

        parsed_version
            >= (Version {
                major,
                minor: 0,
                patch: 0,
                pre: Prerelease::default(),
                build: BuildMetadata::default(),
            })
    }
}

#[async_trait]
impl CCompilerImpl for Clang {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::Clang
    }
    fn plusplus(&self) -> bool {
        self.clangplusplus
    }
    fn version(&self) -> Option<String> {
        self.version.clone()
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments> {
        gcc::parse_arguments(
            arguments,
            cwd,
            (&gcc::ARGS[..], &ARGS[..]),
            self.clangplusplus,
            self.kind(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn preprocess<T>(
        &self,
        creator: &T,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        may_dist: bool,
        rewrite_includes_only: bool,
        preprocessor_cache_mode: bool,
    ) -> Result<process::Output>
    where
        T: CommandCreatorSync,
    {
        let mut ignorable_whitespace_flags = if preprocessor_cache_mode {
            vec![]
        } else {
            vec!["-P".to_string()]
        };

        // Clang 14 and later support -fminimize-whitespace, which normalizes away non-semantic whitespace which in turn increases cache hit rate.
        if self.is_minversion(14) {
            ignorable_whitespace_flags.push("-fminimize-whitespace".to_string())
        }

        gcc::preprocess(
            creator,
            executable,
            parsed_args,
            cwd,
            env_vars,
            may_dist,
            self.kind(),
            rewrite_includes_only,
            ignorable_whitespace_flags,
            language_to_clang_arg,
        )
        .await
    }

    fn generate_compile_commands<T>(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        rewrite_includes_only: bool,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )>
    where
        T: CommandCreatorSync,
    {
        gcc::generate_compile_commands(
            path_transformer,
            executable,
            parsed_args,
            cwd,
            env_vars,
            self.kind(),
            rewrite_includes_only,
            language_to_clang_arg,
        )
        .map(|(command, dist_command, cacheable)| {
            (CCompileCommand::new(command), dist_command, cacheable)
        })
    }
}

pub fn language_to_clang_arg(lang: Language) -> Option<&'static str> {
    match lang {
        Language::C => Some("c"),
        Language::CHeader => Some("c-header"),
        Language::Cxx => Some("c++"),
        Language::CxxHeader => Some("c++-header"),
        Language::ObjectiveC => Some("objective-c"),
        Language::ObjectiveCxx => Some("objective-c++"),
        Language::ObjectiveCxxHeader => Some("objective-c++-header"),
        Language::Cuda => Some("cuda"),
        Language::Ptx => None,
        Language::Cubin => None,
        Language::Rust => None, // Let the compiler decide
        Language::Hip => Some("hip"),
        Language::GenericHeader => None, // Let the compiler decide
    }
}

counted_array!(pub static ARGS: [ArgInfo<gcc::ArgData>; _] = [
    take_arg!("--dependent-lib", OsString, Concatenated('='), PassThrough),
    take_arg!("--hip-device-lib-path", PathBuf, Concatenated('='), PassThroughPath),
    take_arg!("--hip-path", PathBuf, Concatenated('='), PassThroughPath),
    take_arg!("--rocm-path", PathBuf, Concatenated('='), PassThroughPath),
    take_arg!("--serialize-diagnostics", OsString, Separated, PassThrough),
    take_arg!("--target", OsString, Separated, PassThrough),
    // Note: for clang we must override the dep options from gcc.rs with `CanBeSeparated`.
    take_arg!("-MF", PathBuf, CanBeSeparated, DepArgumentPath),
    take_arg!("-MQ", OsString, CanBeSeparated, DepTarget),
    take_arg!("-MT", OsString, CanBeSeparated, DepTarget),
    flag!("-Wno-unknown-cuda-version", PassThroughFlag),
    flag!("-Wno-unused-parameter", PassThroughFlag),
    take_arg!("-Xclang", OsString, Separated, XClang),
    take_arg!("-add-plugin", OsString, Separated, PassThrough),
    take_arg!("-debug-info-kind", OsString, Concatenated('='), PassThrough),
    take_arg!("-dependency-file", PathBuf, Separated, DepArgumentPath),
    flag!("-emit-pch", PassThroughFlag),
    flag!("-fcolor-diagnostics", DiagnosticsColorFlag),
    flag!("-fcuda-allow-variadic-functions", PassThroughFlag),
    flag!("-fcxx-modules", TooHardFlag),
    take_arg!("-fdebug-compilation-dir", OsString, Separated, PassThrough),
    take_arg!("-fembed-offload-object", PathBuf, Concatenated('='), ExtraHashFile),
    flag!("-fmodules", TooHardFlag),
    flag!("-fno-color-diagnostics", NoDiagnosticsColorFlag),
    flag!("-fno-pch-timestamp", PassThroughFlag),
    flag!("-fno-profile-instr-generate", TooHardFlag),
    flag!("-fno-profile-instr-use", TooHardFlag),
    take_arg!("-fplugin", PathBuf, CanBeConcatenated('='), ExtraHashFile),
    flag!("-fprofile-instr-generate", ProfileGenerate),
    // Note: the PathBuf argument is optional
    take_arg!("-fprofile-instr-use", PathBuf, Concatenated('='), ClangProfileUse),
    // Note: this overrides the -fprofile-use option in gcc.rs.
    take_arg!("-fprofile-use", PathBuf, Concatenated('='), ClangProfileUse),
    take_arg!("-fsanitize-blacklist", PathBuf, Concatenated('='), ExtraHashFile),
    flag!("-fuse-ctor-homing", PassThroughFlag),
    take_arg!("-gcc-toolchain", OsString, Separated, PassThrough),
    flag!("-gcodeview", PassThroughFlag),
    take_arg!("-include-pch", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-load", PathBuf, Separated, ExtraHashFile),
    take_arg!("-mllvm", OsString, Separated, PassThrough),
    flag!("-no-opaque-pointers", PreprocessorArgumentFlag),
    take_arg!("-plugin-arg", OsString, Concatenated('-'), PassThrough),
    take_arg!("-target", OsString, Separated, PassThrough),
    flag!("-verify", PreprocessorArgumentFlag),
    take_arg!("/winsysroot", PathBuf, CanBeSeparated, PassThroughPath),
]);

// Maps the `-fprofile-use` argument to the actual path of the
// .profdata file Clang will try to use.
pub(crate) fn resolve_profile_use_path(arg: &Path, cwd: &Path) -> PathBuf {
    // Note that `arg` might be empty (if no argument was given to
    // -fprofile-use), in which case `path` will be `cwd` after
    // the next statement and "./default.profdata" at the end of the
    // block. This matches Clang's behavior for when no argument is
    // given.
    let mut path = cwd.join(arg);

    assert!(!arg.as_os_str().is_empty() || path == cwd);

    // Clang allows specifying a directory here, in which case it
    // will look for the file `default.profdata` in that directory.
    if path.is_dir() {
        path.push("default.profdata");
    }

    path
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::gcc;
    use crate::compiler::*;
    use crate::mock_command::*;
    use crate::server;
    use crate::test::mock_storage::MockStorage;
    use crate::test::utils::*;
    use std::collections::HashMap;
    use std::future::Future;
    use std::path::PathBuf;

    fn parse_arguments_(arguments: Vec<String>) -> CompilerArguments<ParsedArguments> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        Clang {
            clangplusplus: false,
            is_appleclang: false,
            version: None,
        }
        .parse_arguments(&arguments, &std::env::current_dir().unwrap(), &[])
    }

    macro_rules! parses {
        ( $( $s:expr ),* ) => {
            match parse_arguments_(vec![ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(a) => a,
                o => panic!("Got unexpected parse result: {:?}", o),
            }
        }
    }

    #[test]
    fn test_is_minversion() {
        assert!(Clang {
            clangplusplus: false,
            is_appleclang: false,
            version: Some("\"Ubuntu Clang 14.0.0\"".to_string()),
        }
        .is_minversion(14));
        assert!(!Clang {
            clangplusplus: false,
            is_appleclang: false,
            version: Some("\"Ubuntu Clang 13.0.0\"".to_string()),
        }
        .is_minversion(14));
        assert!(Clang {
            clangplusplus: false,
            is_appleclang: false,
            version: Some("\"FreeBSD Clang 14.0.5 (https://github.com/llvm/llvm-project.git llvmorg-14.0.5-0-gc12386ae247c)\"".to_string()),
        }.is_minversion(14));
        assert!(!Clang {
            clangplusplus: false,
            is_appleclang: false,
            version: Some("\"FreeBSD Clang 13.0.0 (git@github.com:llvm/llvm-project.git llvmorg-13.0.0-0-gd7b669b3a303)\"".to_string()),
        }.is_minversion(14));

        assert!(!Clang {
            clangplusplus: false,
            is_appleclang: true,
            version: Some("\"FreeBSD Clang 14.0.5 (https://github.com/llvm/llvm-project.git llvmorg-14.0.5-0-gc12386ae247c)\"".to_string()),
        }.is_minversion(14)); // is_appleclang wins
    }

    #[test]
    fn test_parse_arguments_simple() {
        let a = parses!("-c", "foo.c", "-o", "foo.o");
        assert_eq!(Some("foo.c"), a.input.to_str());
        assert_eq!(Language::C, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(a.preprocessor_args.is_empty());
        assert!(a.common_args.is_empty());
    }

    #[test]
    fn test_parse_arguments_values() {
        let a = parses!(
            "-c",
            "foo.cxx",
            "-arch",
            "xyz",
            "-fabc",
            "-I",
            "include",
            "-o",
            "foo.o",
            "-include",
            "file",
            "/winsysroot../some/dir"
        );
        assert_eq!(Some("foo.cxx"), a.input.to_str());
        assert_eq!(Language::Cxx, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert_eq!(ovec!["-Iinclude", "-include", "file"], a.preprocessor_args);
        assert_eq!(ovec!["-fabc", "/winsysroot", "../some/dir"], a.common_args);
        assert_eq!(ovec!["-arch", "xyz"], a.arch_args);
    }

    #[test]
    fn test_parse_arguments_cuda() {
        let a = parses!("-c", "foo.cu", "-o", "foo.o");
        assert_eq!(Some("foo.cu"), a.input.to_str());
        assert_eq!(Language::Cuda, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(a.preprocessor_args.is_empty());
        assert!(a.common_args.is_empty());
    }

    #[test]
    fn test_parse_arguments_cuda_flags() {
        let a = parses!(
            "-c",
            "foo.cpp",
            "-x",
            "cuda",
            "--cuda-gpu-arch=sm_50",
            "-o",
            "foo.o"
        );
        assert_eq!(Some("foo.cpp"), a.input.to_str());
        assert_eq!(Language::Cuda, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(a.preprocessor_args.is_empty());
        assert_eq!(ovec!["--cuda-gpu-arch=sm_50"], a.common_args);

        let b = parses!(
            "-c",
            "foo.cpp",
            "-x",
            "cu",
            "--cuda-gpu-arch=sm_50",
            "--no-cuda-include-ptx=sm_50",
            "-o",
            "foo.o"
        );
        assert_eq!(Some("foo.cpp"), b.input.to_str());
        assert_eq!(Language::Cuda, b.language);
        assert_map_contains!(
            b.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(b.preprocessor_args.is_empty());
        assert_eq!(
            ovec!["--cuda-gpu-arch=sm_50", "--no-cuda-include-ptx=sm_50"],
            b.common_args
        );
    }

    #[test]
    fn test_parse_arguments_hip() {
        let a = parses!("-c", "foo.hip", "-o", "foo.o");
        assert_eq!(Some("foo.hip"), a.input.to_str());
        assert_eq!(Language::Hip, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(a.preprocessor_args.is_empty());
        assert!(a.common_args.is_empty());
    }

    #[test]
    fn test_parse_arguments_hip_flags() {
        let a = parses!(
            "-c",
            "foo.cpp",
            "-x",
            "hip",
            "--offload-arch=gfx900",
            "-o",
            "foo.o"
        );
        assert_eq!(Some("foo.cpp"), a.input.to_str());
        assert_eq!(Language::Hip, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(a.preprocessor_args.is_empty());
        assert_eq!(ovec!["--offload-arch=gfx900"], a.common_args);

        let b = parses!(
            "-c",
            "foo.cpp",
            "-x",
            "hip",
            "--offload-arch=gfx900",
            "-o",
            "foo.o"
        );
        assert_eq!(Some("foo.cpp"), b.input.to_str());
        assert_eq!(Language::Hip, b.language);
        assert_map_contains!(
            b.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(b.preprocessor_args.is_empty());
        assert_eq!(ovec!["--offload-arch=gfx900"], b.common_args);
    }

    #[test]
    fn test_parse_arguments_hip_paths() {
        let a = parses!(
            "-c",
            "foo.cpp",
            "-x",
            "hip",
            "--offload-arch=gfx900",
            "-o",
            "foo.o",
            "--hip-path=/usr"
        );
        assert_eq!(Some("foo.cpp"), a.input.to_str());
        assert_eq!(Language::Hip, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(a.preprocessor_args.is_empty());
        assert_eq!(
            ovec!["--offload-arch=gfx900", "--hip-path=/usr"],
            a.common_args
        );

        let b = parses!(
            "-c",
            "foo.cpp",
            "-x",
            "hip",
            "--offload-arch=gfx900",
            "-o",
            "foo.o",
            "--hip-device-lib-path=/usr/lib64/amdgcn/bitcode"
        );
        assert_eq!(Some("foo.cpp"), b.input.to_str());
        assert_eq!(Language::Hip, b.language);
        assert_map_contains!(
            b.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(b.preprocessor_args.is_empty());
        assert_eq!(
            ovec![
                "--offload-arch=gfx900",
                "--hip-device-lib-path=/usr/lib64/amdgcn/bitcode"
            ],
            b.common_args
        );
    }

    #[test]
    fn test_dependent_lib() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "--dependent-lib=msvcrt"
        );
        assert_eq!(Some("foo.c"), a.input.to_str());
        assert_eq!(Language::C, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert_eq!(ovec!["-Xclang", "--dependent-lib=msvcrt"], a.common_args);
    }

    #[test]
    fn test_parse_arguments_others() {
        parses!("-c", "foo.c", "-B", "somewhere", "-o", "foo.o");
        parses!(
            "-c",
            "foo.c",
            "-target",
            "x86_64-apple-darwin11",
            "-o",
            "foo.o"
        );
        parses!("-c", "foo.c", "-gcc-toolchain", "somewhere", "-o", "foo.o");
    }

    #[test]
    fn test_gcodeview() {
        parses!("-c", "foo.c", "-o", "foo.o", "-Xclang", "-gcodeview");
    }

    #[test]
    fn test_emit_pch() {
        let a = parses!(
            "-Xclang",
            "-emit-pch",
            "-Xclang",
            "-include",
            "-Xclang",
            "pch.hxx",
            "-x",
            "c++-header",
            "-o",
            "pch.hxx.pch",
            "-c",
            "pch.hxx.cxx"
        );
        assert_eq!(Some("pch.hxx.cxx"), a.input.to_str());
        assert_eq!(Language::CxxHeader, a.language);
        assert_map_contains!(
            a.outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("pch.hxx.pch"),
                    optional: false
                }
            )
        );
        println!("{:?}", a);
        assert_eq!(
            ovec!["-Xclang", "-include", "-Xclang", "pch.hxx"],
            a.preprocessor_args
        );
        assert_eq!(ovec!["-Xclang", "-emit-pch"], a.common_args)
    }

    #[test]
    fn test_parse_clang_short_dependency_arguments_can_be_separated() {
        let args = vec!["-MF", "-MT", "-MQ"];
        let formats = vec![
            "foo.c.d",
            "\"foo.c.d\"",
            "=foo.c.d",
            "./foo.c.d",
            "/somewhere/foo.c.d",
        ];

        for arg in args {
            for format in &formats {
                let parsed_separated = parses!("-c", "foo.c", "-MD", arg, format);
                let parsed = parses!("-c", "foo.c", "-MD", format!("{arg}{format}"));
                assert_eq!(parsed.dependency_args, parsed_separated.dependency_args);
            }
        }
    }

    #[test]
    fn test_parse_arguments_clangmodules() {
        assert_eq!(
            CompilerArguments::CannotCache("-fcxx-modules", None),
            parse_arguments_(stringvec!["-c", "foo.c", "-fcxx-modules", "-o", "foo.o"])
        );
        assert_eq!(
            CompilerArguments::CannotCache("-fmodules", None),
            parse_arguments_(stringvec!["-c", "foo.c", "-fmodules", "-o", "foo.o"])
        );
    }

    #[test]
    fn test_parse_xclang_invalid() {
        assert_eq!(
            CompilerArguments::CannotCache(
                "Can't handle Raw arguments with -Xclang",
                Some("broken".to_string())
            ),
            parse_arguments_(stringvec![
                "-c", "foo.c", "-o", "foo.o", "-Xclang", "broken"
            ])
        );
        assert_eq!(
            CompilerArguments::CannotCache(
                "Can't handle UnknownFlag arguments with -Xclang",
                Some("-broken".to_string())
            ),
            parse_arguments_(stringvec![
                "-c", "foo.c", "-o", "foo.o", "-Xclang", "-broken"
            ])
        );
        assert_eq!(
            CompilerArguments::CannotCache(
                "argument parse",
                Some("Unexpected end of args".to_string())
            ),
            parse_arguments_(stringvec!["-c", "foo.c", "-o", "foo.o", "-Xclang", "-load"])
        );
    }

    #[test]
    fn test_parse_xclang_load() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-load",
            "-Xclang",
            "plugin.so"
        );
        println!("A {:#?}", a);
        assert_eq!(
            ovec!["-Xclang", "-load", "-Xclang", "plugin.so"],
            a.common_args
        );
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("plugin.so")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_xclang_add_plugin() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-add-plugin",
            "-Xclang",
            "foo"
        );
        assert_eq!(
            ovec!["-Xclang", "-add-plugin", "-Xclang", "foo"],
            a.common_args
        );
    }

    #[test]
    fn test_parse_xclang_llvm_stuff() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-mllvm",
            "-Xclang",
            "-instcombine-lower-dbg-declare=0",
            "-Xclang",
            "-debug-info-kind=constructor"
        );
        assert_eq!(
            ovec![
                "-Xclang",
                "-mllvm",
                "-Xclang",
                "-instcombine-lower-dbg-declare=0",
                "-Xclang",
                "-debug-info-kind=constructor"
            ],
            a.common_args
        );
    }

    #[test]
    fn test_parse_xclang_plugin_arg_blink_gc_plugin() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-add-plugin",
            "-Xclang",
            "blink-gc-plugin",
            "-Xclang",
            "-plugin-arg-blink-gc-plugin",
            "-Xclang",
            "no-members-in-stack-allocated"
        );
        assert_eq!(
            ovec![
                "-Xclang",
                "-add-plugin",
                "-Xclang",
                "blink-gc-plugin",
                "-Xclang",
                "-plugin-arg-blink-gc-plugin",
                "-Xclang",
                "no-members-in-stack-allocated"
            ],
            a.common_args
        );
    }

    #[test]
    fn test_parse_xclang_plugin_arg_find_bad_constructs() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-add-plugin",
            "-Xclang",
            "find-bad-constructs",
            "-Xclang",
            "-plugin-arg-find-bad-constructs",
            "-Xclang",
            "check-ipc"
        );
        assert_eq!(
            ovec![
                "-Xclang",
                "-add-plugin",
                "-Xclang",
                "find-bad-constructs",
                "-Xclang",
                "-plugin-arg-find-bad-constructs",
                "-Xclang",
                "check-ipc"
            ],
            a.common_args
        );
    }

    #[test]
    fn test_parse_xclang_verify() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-Xclang", "-verify");
        assert_eq!(ovec!["-Xclang", "-verify"], a.preprocessor_args);
    }

    #[test]
    fn test_parse_xclang_no_opaque_pointers() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-no-opaque-pointers"
        );
        assert_eq!(ovec!["-Xclang", "-no-opaque-pointers"], a.preprocessor_args);
    }

    #[test]
    fn test_parse_xclang_fno_pch_timestamp() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-Xclang",
            "-fno-pch-timestamp"
        );
        assert_eq!(ovec!["-Xclang", "-fno-pch-timestamp"], a.common_args);
    }

    #[test]
    fn test_parse_xclang_use_ctor_homing() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-Xclang", "-fuse-ctor-homing");
        assert_eq!(ovec!["-Xclang", "-fuse-ctor-homing"], a.common_args);
    }

    #[test]
    fn test_parse_fplugin() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fplugin", "plugin.so");
        println!("A {:#?}", a);
        assert_eq!(ovec!["-fplugin", "plugin.so"], a.common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("plugin.so")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_fsanitize_blacklist() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-fsanitize-blacklist=list.txt"
        );
        assert_eq!(ovec!["-fsanitize-blacklist=list.txt"], a.common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("list.txt")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_color_diags() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fcolor-diagnostics");
        assert_eq!(a.color_mode, ColorMode::On);

        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fno-color-diagnostics");
        assert_eq!(a.color_mode, ColorMode::Off);

        let a = parses!("-c", "foo.c", "-o", "foo.o");
        assert_eq!(a.color_mode, ColorMode::Auto);
    }

    #[test]
    fn test_parse_arguments_profile_instr_use() {
        let a = parses!(
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-fprofile-instr-use=foo.profdata"
        );
        assert_eq!(ovec!["-fprofile-instr-use=foo.profdata"], a.common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("foo.profdata")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_arguments_profile_use() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fprofile-use=xyz.profdata");

        assert_eq!(ovec!["-fprofile-use=xyz.profdata"], a.common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("xyz.profdata")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_arguments_profile_use_with_directory() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fprofile-use=.");

        assert_eq!(ovec!["-fprofile-use=."], a.common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("default.profdata")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_arguments_profile_use_with_no_argument() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fprofile-use");

        assert_eq!(ovec!["-fprofile-use"], a.common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("default.profdata")],
            a.extra_hash_files
        );
    }

    #[test]
    fn test_parse_arguments_pgo_cancellation() {
        assert_eq!(
            CompilerArguments::CannotCache("-fno-profile-use", None),
            parse_arguments_(stringvec![
                "-c",
                "foo.c",
                "-o",
                "foo.o",
                "-fprofile-use",
                "-fno-profile-use"
            ])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-fno-profile-instr-use", None),
            parse_arguments_(stringvec![
                "-c",
                "foo.c",
                "-o",
                "foo.o",
                "-fprofile-instr-use",
                "-fno-profile-instr-use"
            ])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-fno-profile-generate", None),
            parse_arguments_(stringvec![
                "-c",
                "foo.c",
                "-o",
                "foo.o",
                "-fprofile-generate",
                "-fno-profile-generate"
            ])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-fno-profile-instr-generate", None),
            parse_arguments_(stringvec![
                "-c",
                "foo.c",
                "-o",
                "foo.o",
                "-fprofile-instr-generate",
                "-fno-profile-instr-generate"
            ])
        );
    }

    #[test]
    fn test_compile_clang_cuda_does_not_dist_compile() {
        let creator = new_creator();
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.cu".into(),
            double_dash_input: false,
            language: Language::Cuda,
            compilation_flag: "-c".into(),
            depfile: None,
            outputs: vec![(
                "obj",
                ArtifactDescriptor {
                    path: "foo.cu.o".into(),
                    optional: false,
                },
            )]
            .into_iter()
            .collect(),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: vec![],
            arch_args: vec![],
            unhashed_args: vec![],
            extra_dist_files: vec![],
            extra_hash_files: vec![],
            msvc_show_includes: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        };
        let runtime = single_threaded_runtime();
        let storage = MockStorage::new(None, false);
        let storage: std::sync::Arc<MockStorage> = std::sync::Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage, runtime.handle().clone());
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::new();
        let (command, dist_command, cacheable) = gcc::generate_compile_commands(
            &mut path_transformer,
            compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
            CCompilerKind::Clang,
            false,
            language_to_clang_arg,
        )
        .unwrap();
        // ClangCUDA cannot be dist-compiled
        assert!(dist_command.is_none());
        let _ = command.execute(&service, &creator).wait();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
