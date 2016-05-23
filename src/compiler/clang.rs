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

pub fn parse_arguments(_cmd : &[String]) -> CompilerArguments {
    //TODO
    CompilerArguments::CannotCache
}

pub fn preprocess<T : CommandCreatorSync>(creator: T, compiler: &Compiler, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
    trace!("preprocess");
    unimplemented!();
}

pub fn compile<T : CommandCreatorSync>(creator: T, compiler: &Compiler, preprocessor_output: Vec<u8>, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
    trace!("compile");
    unimplemented!();
}
