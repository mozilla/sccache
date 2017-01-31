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
    Compiler,
    CompilerArguments,
    ParsedArguments,
    run_input_output,
};
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::{
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
};
use std::fs::File;
use std::io::{
    self,
    Error,
    ErrorKind,
    Write,
};
use std::path::Path;
use std::process;
use tempdir::TempDir;

/// Arguments that take a value that aren't in `gcc::ARGS_WITH_VALUE`.
const ARGS_WITH_VALUE: &'static [&'static str] = &["-arch"];

/// Return true if `arg` is a clang commandline argument that takes a value.
pub fn argument_takes_value(arg: &str) -> bool {
    gcc::ARGS_WITH_VALUE.contains(&arg) || ARGS_WITH_VALUE.contains(&arg)
}

pub fn compile<T>(creator: &T,
                  compiler: &Compiler,
                  preprocessor_output: Vec<u8>,
                  parsed_args: &ParsedArguments,
                  cwd: &str,
                  pool: &CpuPool)
                  -> Box<Future<Item=(Cacheable, process::Output), Error=io::Error>>
    where T: CommandCreatorSync,
{
    let mut creator = creator.clone();
    let compiler = compiler.clone();
    let parsed_args = parsed_args.clone();
    let cwd = cwd.to_string();

    pool.spawn_fn(move || {
        trace!("compile");
        // Clang needs a temporary file for compilation, otherwise debug info
        // doesn't have a reference to the input file.
        let tempdir = try!(TempDir::new("sccache"));
        let filename = try!(Path::new(&parsed_args.input).file_name().ok_or(Error::new(ErrorKind::Other, "Missing input filename")));
        let input = tempdir.path().join(filename);
        {
            try!(File::create(&input)
                 .and_then(|mut f| f.write_all(&preprocessor_output)))
        }
        let out_file = try!(parsed_args.outputs.get("obj").ok_or(Error::new(ErrorKind::Other, "Missing object file output")));
        let mut cmd = creator.new_command_sync(&compiler.executable);
        cmd.arg("-c")
            .arg(&input)
            .arg("-o")
            .arg(&out_file)
            .args(&parsed_args.common_args)
            .current_dir(&cwd);

        // clang may fail when compiling preprocessor output with -Werror,
        // so retry compilation from the original input file if it fails and
        // -Werror is in the commandline.
        let output = try!(run_input_output(cmd, None));
        if !output.status.success() && parsed_args.common_args.iter().any(|a| a.starts_with("-Werror")) {
            let mut cmd = creator.new_command_sync(&compiler.executable);
            cmd.arg("-c")
                .arg(&parsed_args.input)
                .arg("-o")
                .arg(&out_file)
                .args(&parsed_args.common_args)
                .current_dir(&cwd);
            let output = try!(run_input_output(cmd, None));
            Ok((Cacheable::Yes, output))
        } else {
            Ok((Cacheable::Yes, output))
        }
    }).boxed()
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

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments {
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
        let compiler = Compiler::new(f.bins[0].to_str().unwrap(),
                                     CompilerKind::Clang).unwrap();
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
        let compiler = Compiler::new(f.bins[0].to_str().unwrap(),
                                     CompilerKind::Clang).unwrap();
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
