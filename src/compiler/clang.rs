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
    CompilerKind,
    run_input_output,
    write_temp_file,
};
use compiler::c::{CCompilerImpl, ParsedArguments};
use futures::future::{self, Future};
use futures_cpupool::CpuPool;
use mock_command::{
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
};
use std::fs::File;
use std::io::{
    self,
    Write,
};
use std::path::Path;
use std::process;

use errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct Clang;

impl CCompilerImpl for Clang {
    fn kind(&self) -> CompilerKind { CompilerKind::Clang }
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
                     pool: &CpuPool)
                     -> SFuture<process::Output> where T: CommandCreatorSync
    {
        gcc::preprocess(creator, executable, parsed_args, cwd, pool)
    }

    fn compile<T>(&self,
                  creator: &T,
                  executable: &str,
                  preprocessor_output: Vec<u8>,
                  parsed_args: &ParsedArguments,
                  cwd: &str,
                  pool: &CpuPool)
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync
    {
        compile(creator, executable, preprocessor_output, parsed_args, cwd, pool)
    }
}

/// Arguments that take a value that aren't in `gcc::ARGS_WITH_VALUE`.
const ARGS_WITH_VALUE: &'static [&'static str] = &["-arch"];

/// Return true if `arg` is a clang commandline argument that takes a value.
pub fn argument_takes_value(arg: &str) -> bool {
    gcc::ARGS_WITH_VALUE.contains(&arg) || ARGS_WITH_VALUE.contains(&arg)
}

fn compile<T>(creator: &T,
              executable: &str,
              preprocessor_output: Vec<u8>,
              parsed_args: &ParsedArguments,
              cwd: &str,
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
        write_temp_file(pool, filename.as_ref(), preprocessor_output)
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
        .current_dir(&cwd);
    let output = write.and_then(move |(tempdir, input)| {
        attempt.arg(&input);
        run_input_output(attempt, None).map(|e| {
            drop(tempdir);
            e
        })
    });

    // clang may fail when compiling preprocessor output with -Werror,
    // so retry compilation from the original input file if it fails and
    // -Werror is in the commandline.
    //
    // Otherwise if -Werror is missing we can just use the first instance.
    if !parsed_args.common_args.iter().any(|a| a.starts_with("-Werror")) {
        return Box::new(output.map(|output| (Cacheable::Yes, output)))
    }

    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-c")
        .arg(&parsed_args.input)
        .arg("-o")
        .arg(&out_file)
        .args(&parsed_args.common_args)
        .current_dir(&cwd);
    Box::new(output.and_then(move |output| -> SFuture<_> {
        if !output.status.success() {
            Box::new(run_input_output(cmd, None).map(|output| {
                (Cacheable::Yes, output)
            }))
        } else {
            future::ok((Cacheable::Yes, output)).boxed()
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
        gcc::parse_arguments(arguments, ".".as_ref(), argument_takes_value)
    }

    #[test]
    fn test_parse_arguments_simple() {
        match _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, depfile: _depfile, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_eq!("c", extension);
                assert_map_contains!(outputs, ("obj", "foo.o"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(1, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert!(common_args.is_empty());
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    #[test]
    fn test_parse_arguments_values() {
        match _parse_arguments(&stringvec!["-c", "foo.cxx", "-arch", "xyz", "-fabc","-I", "include", "-o", "foo.o", "-include", "file"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, depfile: _depfile, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.cxx", input);
                assert_eq!("cxx", extension);
                assert_map_contains!(outputs, ("obj", "foo.o"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(1, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert_eq!(stringvec!["-arch", "xyz", "-fabc", "-I", "include", "-include", "file"], common_args);
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
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
        };
        let compiler = f.bins[0].to_str().unwrap();
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     vec!(),
                                     &parsed_args,
                                     f.tempdir.path().to_str().unwrap(),
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
        };
        let compiler = f.bins[0].to_str().unwrap();
        // First compiler invocation fails.
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        // Second compiler invocation succeeds.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, output) = compile(&creator,
                                          &compiler,
                                          vec!(),
                                          &parsed_args,
                                          f.tempdir.path().to_str().unwrap(),
                                          &pool).wait().unwrap();
        assert_eq!(Cacheable::Yes, cacheable);
        assert_eq!(exit_status(0), output.status);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
