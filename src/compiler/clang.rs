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
    Compiler,
    CompilerArguments,
    ParsedArguments,
    ProcessOutput,
    run_compiler,
};
use mock_command::{
    CommandCreator,
    CommandCreatorSync,
};
use std::io::{
    self,
    Error,
    ErrorKind,
};
use std::process;

/// Arguments that take a value that aren't in `gcc::ARGS_WITH_VALUE`.
const ARGS_WITH_VALUE: &'static [&'static str] = &["-arch"];

/// Return true if `arg` is a clang commandline argument that takes a value.
pub fn argument_takes_value(arg: &str) -> bool {
    gcc::ARGS_WITH_VALUE.contains(&arg) || ARGS_WITH_VALUE.contains(&arg)
}

pub fn compile<T : CommandCreatorSync>(creator: T, compiler: &Compiler, preprocessor_output: Vec<u8>, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
    trace!("compile");
    unimplemented!();
}

#[cfg(test)]
mod test {
    use super::*;
    use compiler::*;
    use compiler::gcc;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments {
        gcc::parse_arguments(arguments, argument_takes_value)
    }

    #[test]
    fn test_parse_arguments_simple() {
        match _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, outputs, preprocessor_args, common_args }) => {
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
            CompilerArguments::Ok(ParsedArguments { input, extension, outputs, preprocessor_args, common_args }) => {
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
}
