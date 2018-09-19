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
    // TODO: should be extracted and reprocessed, though bear in mind some
    // flags are not valid under a -Xclang
    take_arg!("-Xclang", OsString, Separated, TooHard),
    flag!("-fcxx-modules", TooHardFlag),
    flag!("-fmodules", TooHardFlag),
    flag!("-fprofile-instr-generate", ProfileGenerate),
    // Can be either -fprofile-instr-use or -fprofile-instr-use=path
    take_arg!("-fprofile-instr-use", OsString, Concatenated, TooHard),
    take_arg!("-gcc-toolchain", OsString, Separated, PassThrough),
    take_arg!("-include-pch", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-target", OsString, Separated, PassThrough),
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
}
