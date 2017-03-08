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
    write_temp_file,
};
use compiler::c::{CCompilerImpl, CCompilerKind, ParsedArguments};
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
use std::path::Path;
use std::process;
use util::run_input_output;

use errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct Clang;

impl CCompilerImpl for Clang {
    fn kind(&self) -> CCompilerKind { CCompilerKind::Clang }
    fn parse_arguments(&self,
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        gcc::parse_arguments(arguments, cwd, argument_takes_value)
    }

    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &str,
                     parsed_args: &ParsedArguments,
                     cwd: &str,
                     env_vars: &[(OsString, OsString)],
                     pool: &CpuPool)
                     -> SFuture<process::Output> where T: CommandCreatorSync
    {
        gcc::preprocess(creator, executable, parsed_args, cwd, env_vars, pool)
    }

    fn compile<T>(&self,
                  creator: &T,
                  executable: &str,
                  preprocessor_result: process::Output,
                  parsed_args: &ParsedArguments,
                  cwd: &str,
                  env_vars: &[(OsString, OsString)],
                  pool: &CpuPool)
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync
    {
        compile(creator, executable, preprocessor_result, parsed_args, cwd, env_vars, pool)
    }
}

/// Arguments that take a value that aren't in `gcc::ARGS_WITH_VALUE`.
const ARGS_WITH_VALUE: &'static [&'static str] = &[
    "-arch",
    "-B",
    "-target",
    "-Xclang",
];

/// Return true if `arg` is a clang commandline argument that takes a value.
pub fn argument_takes_value(arg: &str) -> bool {
    gcc::ARGS_WITH_VALUE.contains(&arg) || ARGS_WITH_VALUE.contains(&arg)
}

fn compile<T>(creator: &T,
              executable: &str,
              preprocessor_result: process::Output,
              parsed_args: &ParsedArguments,
              cwd: &str,
              env_vars: &[(OsString, OsString)],
              pool: &CpuPool)
              -> SFuture<(Cacheable, process::Output)>
    where T: CommandCreatorSync,
{
    trace!("compile");
    // Clang needs a temporary file for compilation, otherwise debug info
    // doesn't have a reference to the input file.
    let write = {
        let filename = match Path::new(&parsed_args.input).file_name() {
            Some(name) => name,
            None => return future::err("missing input filename".into()).boxed(),
        };
        write_temp_file(pool, filename.as_ref(), preprocessor_result.stdout)
    };
    let input = parsed_args.input.clone();
    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => {
            return future::err("Missing object file output".into()).boxed()
        }
    };

    let mut attempt = creator.clone().new_command_sync(executable);
    attempt.arg("-c")
        .arg("-o")
        .arg(&out_file)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);
    let output = write.and_then(move |(tempdir, input)| {
        attempt.arg(&input);
        run_input_output(attempt, None).map(|output| {
            drop(tempdir);
            (Cacheable::Yes, output)
        })
    });

    // clang may fail when compiling preprocessor output with -Werror,
    // so retry compilation from the original input file if it fails and
    // -Werror is in the commandline.
    //
    // Otherwise if -Werror is missing we can just use the first instance.
    if !parsed_args.common_args.iter().any(|a| a.starts_with("-Werror")) {
        return Box::new(output)
    }

    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-c")
        .arg(&parsed_args.input)
        .arg("-o")
        .arg(&out_file)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);
    Box::new(output.or_else(move |err| -> SFuture<_> {
        match err {
            // If compiling from the preprocessed source failed, try
            // again from the original source.
            Error(ErrorKind::ProcessError(_), _) => {
                Box::new(run_input_output(cmd, None).map(|output| {
                    (Cacheable::Yes, output)
                }))
            }
            e @ _ => f_err(e),
        }
    }))
}

#[cfg(test)]
mod test {
    use compiler::*;
    use compiler::gcc;
    use futures::Future;
    use futures_cpupool::CpuPool;
    use mock_command::*;
    use std::collections::HashMap;
    use super::*;
    use test::utils::*;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments> {
        Clang.parse_arguments(arguments, ".".as_ref())
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
        assert_eq!("foo.c", a.input);
        assert_eq!("c", a.extension);
        assert_map_contains!(a.outputs, ("obj", "foo.o"));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, a.outputs.len());
        assert!(a.preprocessor_args.is_empty());
        assert!(a.common_args.is_empty());
    }

    #[test]
    fn test_parse_arguments_values() {
        let a = parses!("-c", "foo.cxx", "-arch", "xyz", "-fabc","-I", "include", "-o", "foo.o", "-include", "file");
        assert_eq!("foo.cxx", a.input);
        assert_eq!("cxx", a.extension);
        assert_map_contains!(a.outputs, ("obj", "foo.o"));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, a.outputs.len());
        assert!(a.preprocessor_args.is_empty());
        assert_eq!(stringvec!["-arch", "xyz", "-fabc", "-I", "include", "-include", "file"], a.common_args);
    }

    #[test]
    fn test_parse_arguments_others() {
        parses!("-c", "foo.c", "-Xclang", "-load", "-Xclang", "moz-check", "-o", "foo.o");
        parses!("-c", "foo.c", "-B", "somewhere", "-o", "foo.o");
        parses!("-c", "foo.c", "-target", "x86_64-apple-darwin11", "-o", "foo.o");
    }

    #[test]
    fn test_compile_simple() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".to_owned(),
            extension: "c".to_owned(),
            depfile: None,
            outputs: vec![("obj", "foo.o".to_owned())].into_iter().collect::<HashMap<&'static str, String>>(),
            preprocessor_args: vec!(),
            common_args: vec!(),
            msvc_show_includes: false,
        };
        let compiler = f.bins[0].to_str().unwrap();
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     empty_output(),
                                     &parsed_args,
                                     f.tempdir.path().to_str().unwrap(),
                                     &[],
                                     &pool).wait().unwrap();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn test_compile_werror_fails() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".to_owned(),
            extension: "c".to_owned(),
            depfile: None,
            outputs: vec![("obj", "foo.o".to_owned())].into_iter().collect::<HashMap<&'static str, String>>(),
            preprocessor_args: vec!(),
            common_args: stringvec!("-c", "-o", "foo.o", "-Werror=blah", "foo.c"),
            msvc_show_includes: false,
        };
        let compiler = f.bins[0].to_str().unwrap();
        // First compiler invocation fails.
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        // Second compiler invocation succeeds.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, output) = compile(&creator,
                                          &compiler,
                                          empty_output(),
                                          &parsed_args,
                                          f.tempdir.path().to_str().unwrap(),
                                          &[],
                                          &pool).wait().unwrap();
        assert_eq!(Cacheable::Yes, cacheable);
        assert_eq!(exit_status(0), output.status);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
