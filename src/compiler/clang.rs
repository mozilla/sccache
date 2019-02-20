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

#![allow(unused_imports,dead_code,unused_variables)]

use ::compiler::{
    gcc,
    Cacheable,
    CompilerArguments,
    CompileCommand,
    write_temp_file,
};
use dist;
use compiler::args::*;
use compiler::c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments};
use compiler::gcc::ArgData::*;
use futures::future::{self, Future};
use futures_cpupool::CpuPool;
use mock_command::{
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
};
use std::ffi::OsString;
use std::fs::File;
use std::io::{
    self,
    Write,
};
use std::path::{Path, PathBuf};
use std::process;
use util::{run_input_output, OsStrExt};

use errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct Clang;

impl CCompilerImpl for Clang {
    fn kind(&self) -> CCompilerKind { CCompilerKind::Clang }
    fn parse_arguments(&self,
                       arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        gcc::parse_arguments(arguments, cwd, (&gcc::ARGS[..], &ARGS[..]))
    }

    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     may_dist: bool)
                     -> SFuture<process::Output> where T: CommandCreatorSync
    {
        gcc::preprocess(creator, executable, parsed_args, cwd, env_vars, may_dist)
    }

    fn generate_compile_commands(&self,
                                path_transformer: &mut dist::PathTransformer,
                                executable: &Path,
                                parsed_args: &ParsedArguments,
                                cwd: &Path,
                                env_vars: &[(OsString, OsString)])
                                -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>
    {
        gcc::generate_compile_commands(path_transformer, executable, parsed_args, cwd, env_vars)
    }
}

counted_array!(pub static ARGS: [ArgInfo<gcc::ArgData>; _] = [
    take_arg!("--serialize-diagnostics", OsString, Separated, PassThrough),
    take_arg!("--target", OsString, Separated, PassThrough),
    take_arg!("-Xclang", OsString, Separated, XClang),
    take_arg!("-add-plugin", OsString, Separated, PassThrough),
    flag!("-fcxx-modules", TooHardFlag),
    flag!("-fmodules", TooHardFlag),
    take_arg!("-fplugin", PathBuf, CanBeConcatenated('='), ExtraHashFile),
    flag!("-fprofile-instr-generate", ProfileGenerate),
    // Can be either -fprofile-instr-use or -fprofile-instr-use=path
    take_arg!("-fprofile-instr-use", OsString, Concatenated, TooHard),
    take_arg!("-gcc-toolchain", OsString, Separated, PassThrough),
    take_arg!("-include-pch", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-load", PathBuf, Separated, ExtraHashFile),
    take_arg!("-mllvm", OsString, Separated, PassThrough),
    take_arg!("-target", OsString, Separated, PassThrough),
    flag!("-verify", PreprocessorArgumentFlag),
]);

#[cfg(test)]
mod test {
    use compiler::*;
    use compiler::gcc;
    use futures::Future;
    use futures_cpupool::CpuPool;
    use mock_command::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use super::*;
    use tempdir::TempDir;
    use test::utils::*;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        Clang.parse_arguments(&arguments, ".".as_ref())
    }

    macro_rules! parses {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(a) => a,
                o @ _ => panic!("Got unexpected parse result: {:?}", o),
            }
        }
    }


    #[test]
    fn test_parse_arguments_simple() {
        let a = parses!("-c", "foo.c", "-o", "foo.o");
        assert_eq!(Some("foo.c"), a.input.to_str());
        assert_eq!(Language::C, a.language);
        assert_map_contains!(a.outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, a.outputs.len());
        assert!(a.preprocessor_args.is_empty());
        assert!(a.common_args.is_empty());
    }

    #[test]
    fn test_parse_arguments_values() {
        let a = parses!("-c", "foo.cxx", "-arch", "xyz", "-fabc","-I", "include", "-o", "foo.o", "-include", "file");
        assert_eq!(Some("foo.cxx"), a.input.to_str());
        assert_eq!(Language::Cxx, a.language);
        assert_map_contains!(a.outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, a.outputs.len());
        assert_eq!(ovec!["-Iinclude", "-include", "file"], a.preprocessor_args);
        assert_eq!(ovec!["-arch", "xyz", "-fabc"], a.common_args);
    }

    #[test]
    fn test_parse_arguments_others() {
        parses!("-c", "foo.c", "-B", "somewhere", "-o", "foo.o");
        parses!("-c", "foo.c", "-target", "x86_64-apple-darwin11", "-o", "foo.o");
        parses!("-c", "foo.c", "-gcc-toolchain", "somewhere", "-o", "foo.o");
    }

    #[test]
    fn test_parse_arguments_clangmodules() {
        assert_eq!(CompilerArguments::CannotCache("-fcxx-modules", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-fcxx-modules", "-o", "foo.o"]));
        assert_eq!(CompilerArguments::CannotCache("-fmodules", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-fmodules", "-o", "foo.o"]));
    }

    #[test]
    fn test_parse_xclang_invalid() {
        assert_eq!(CompilerArguments::CannotCache("Can't handle Raw arguments with -Xclang", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o", "-Xclang", "broken"]));
        assert_eq!(CompilerArguments::CannotCache("Can't handle UnknownFlag arguments with -Xclang", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o", "-Xclang", "-broken"]));
        assert_eq!(CompilerArguments::CannotCache("argument parse", Some("Unexpected end of args".to_string())),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o", "-Xclang", "-load"]));
    }

    #[test]
    fn test_parse_xclang_load() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-Xclang", "-load", "-Xclang", "plugin.so");
        println!("A {:#?}", a);
        assert_eq!(ovec!["-Xclang", "-load", "-Xclang", "plugin.so"], a.common_args);
        assert_eq!(ovec!["plugin.so"], a.extra_hash_files);
    }

    #[test]
    fn test_parse_xclang_add_plugin() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-Xclang", "-add-plugin", "-Xclang", "foo");
        assert_eq!(ovec!["-Xclang", "-add-plugin", "-Xclang", "foo"], a.common_args);
    }

    #[test]
    fn test_parse_xclang_verify() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-Xclang", "-verify");
        assert_eq!(ovec!["-Xclang", "-verify"], a.preprocessor_args);
    }

    #[test]
    fn test_parse_fplugin() {
        let a = parses!("-c", "foo.c", "-o", "foo.o", "-fplugin", "plugin.so");
        println!("A {:#?}", a);
        assert_eq!(ovec!["-fplugin", "plugin.so"], a.common_args);
        assert_eq!(ovec!["plugin.so"], a.extra_hash_files);
    }

    #[test]
    fn handle_response_file_with_quotes() {
        use pretty_assertions::assert_eq;

        let td = TempDir::new("clang_response_file").unwrap();
        let rsp_path = td.path().join("nix_response.rsp");

        std::fs::copy("tests/ue_linux.rsp", &rsp_path).unwrap();

        let parsed = parses!(format!("@{}", rsp_path.display()));
        
        assert_eq!(parsed, ParsedArguments {
            input: PathBuf::from("/home/jake/code/unreal/Engine/Intermediate/Build/Linux/B4D820EA/UnrealHeaderTool/Development/CoreUObject/Module.CoreUObject.5_of_6.cpp"),
            language: Language::Cxx,
            depfile: None,
            outputs: vec![("obj", PathBuf::from("/home/jake/code/unreal/Engine/Intermediate/Build/Linux/B4D820EA/UnrealHeaderTool/Development/CoreUObject/Module.CoreUObject.5_of_6.cpp.o"))].into_iter().collect(),
            preprocessor_args: ovec![
                "-nostdinc++",
                "-IThirdParty/Linux/LibCxx/include/",
                "-IThirdParty/Linux/LibCxx/include/c++/v1",
                "-DPLATFORM_EXCEPTIONS_DISABLED=0",
                "-D_LINUX64",
                "-I/home/jake/code/unreal/Engine/Source",
                "-I/home/jake/code/unreal/Engine/Source/Runtime/CoreUObject/Private",
                "-I/home/jake/code/unreal/Engine/Source/Runtime",
                "-I/home/jake/code/unreal/Engine/Source/Runtime/Projects/Public",
                "-I/home/jake/code/unreal/Engine/Source/Runtime/Core/Public/Linux",
                "-I/home/jake/code/unreal/Engine/Source/Runtime/Core/Public",
                "-I/home/jake/code/unreal/Engine/Source/Runtime/Json/Public",
                "-I/home/jake/code/unreal/Engine/Source/Developer",
                "-I/home/jake/code/unreal/Engine/Source/Developer/TargetPlatform/Public",
                "-I/home/jake/code/unreal/Engine/Intermediate/Build/Linux/B4D820EA/UnrealHeaderTool/Inc/CoreUObject",
                "-I/home/jake/code/unreal/Engine/Source/Runtime/CoreUObject/Public",
                "-I/home/path that shouldnt exist because spaces are the devil/but shit happens",
                "-include",
                "/home/jake/code/unreal/Engine/Intermediate/Build/Linux/B4D820EA/UnrealHeaderTool/Development/CoreUObject/PCH.CoreUObject.h"
            ],
            common_args: ovec![
                "-pipe",
                "-Wall",
                "-Werror",
                "-Wsequence-point",
                "-Wdelete-non-virtual-dtor",
                "-fno-math-errno",
                "-fno-rtti",
                "-fcolor-diagnostics",
                "-Wno-unused-private-field",
                "-Wno-tautological-compare",
                "-Wno-undefined-bool-conversion",
                "-Wno-unused-local-typedef",
                "-Wno-inconsistent-missing-override",
                "-Wno-undefined-var-template",
                "-Wno-unused-lambda-capture",
                "-Wno-unused-variable",
                "-Wno-unused-function",
                "-Wno-switch",
                "-Wno-unknown-pragmas",
                "-Wno-invalid-offsetof",
                "-Wno-gnu-string-literal-operator-template",
                "-Wshadow",
                "-Wno-error=shadow",
                "-Wundef",
                "-gdwarf-4",
                "-glldb",
                "-fstandalone-debug",
                "-O2",
                "-fPIC",
                "-ftls-model=local-dynamic",
                "-fexceptions",
                "-target",
                "x86_64-unknown-linux-gnu",
                "--sysroot=/home/jake/code/unreal/Engine/Extras/ThirdPartyNotUE/SDKs/HostLinux/Linux_x64/v12_clang-6.0.1-centos7/x86_64-unknown-linux-gnu",
                "-std=c++14"
            ],
            extra_hash_files: Vec::new(),
            msvc_show_includes: false,
            profile_generate: false,
        });
    }
}
