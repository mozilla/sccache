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

use cache::hash_key;
use compiler::{Cacheable, Compiler, CompilerArguments, CompilerKind, Compilation, HashResult, ParsedArguments};
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::CommandCreatorSync;
use std::path::Path;
use std::process;

use errors::*;

/// A generic implementation of the `Compiler` trait for C/C++ compilers.
#[derive(Clone)]
pub struct CCompiler<I: CCompilerImpl>(pub I);

/// A generic implementation of the `Compilation` trait for C/C++ compilers.
struct CCompilation<I: CCompilerImpl> {
    /// The output from running the preprocessor.
    preprocessor_output: Vec<u8>,
    compiler: I,
}

/// An interface to a specific C compiler.
pub trait CCompilerImpl: Clone + Send + 'static {
    /// Return the kind of compiler.
    fn kind(&self) -> CompilerKind;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(&self,
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments;
    /// Run the C preprocessor with the specified set of arguments.
    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &str,
                     parsed_args: &ParsedArguments,
                     cwd: &str,
                     pool: &CpuPool)
                     -> SFuture<process::Output> where T: CommandCreatorSync;
    /// Run the C compiler with the specified set of arguments, using the
    /// previously-generated `preprocessor_output` as input if possible.
    fn compile<T>(&self,
                  creator: &T,
                  executable: &str,
                  preprocessor_output: Vec<u8>,
                  parsed_args: &ParsedArguments,
                  cwd: &str,
                  pool: &CpuPool)
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync;
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compiler<T> for CCompiler<I> {
    fn kind(&self) -> CompilerKind { self.0.kind() }
    fn parse_arguments(&self,
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments {
        self.0.parse_arguments(arguments, cwd)
    }

    fn generate_hash_key(&self,
                         creator: &T,
                         executable: &str,
                         executable_digest: &str,
                         parsed_args: &ParsedArguments,
                         cwd: &str,
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>
    {
        let result = self.0.preprocess(creator, executable, parsed_args, cwd, pool);
        let parsed_args = parsed_args.clone();
        let out_file = parsed_args.output_file().into_owned();
        let result = result.map_err(move |e| {
            debug!("[{}]: preprocessor failed: {:?}", out_file, e);
            e
        });
        let executable_digest = executable_digest.to_string();
        let compiler = self.0.clone();

        Box::new(result.map(move |preprocessor_result| {
            // If the preprocessor failed, just return that result.
            if !preprocessor_result.status.success() {
                debug!("[{}]: preprocessor returned error status {:?}",
                       parsed_args.output_file(),
                       preprocessor_result.status.code());
                // Drop the stdout since it's the preprocessor output, just hand back stderr and the exit status.
                let output = process::Output {
                    stdout: vec!(),
                    .. preprocessor_result
                };
                return HashResult::Error { output: output };
            }
            trace!("[{}]: Preprocessor output is {} bytes",
                   parsed_args.output_file(),
                   preprocessor_result.stdout.len());

            // Remove object file from arguments before hash calculation
            let key = {
                let out_file = parsed_args.output_file();
                let arguments = parsed_args.common_args.iter()
                    .filter(|a| **a != out_file)
                    .map(|a| a.as_str())
                    .collect::<String>();
                hash_key(&executable_digest, &arguments, &preprocessor_result.stdout)
            };
            HashResult::Ok {
                key: key,
                compilation: Box::new(CCompilation {
                    preprocessor_output: preprocessor_result.stdout,
                    compiler: compiler,
                }),
            }
        }))
    }
    fn box_clone(&self) -> Box<Compiler<T>> {
        Box::new((*self).clone())
    }
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compilation<T> for CCompilation<I> {
    fn compile(self: Box<Self>,
               creator: &T,
               executable: &str,
               parsed_args: &ParsedArguments,
               cwd: &str,
               pool: &CpuPool)
               -> SFuture<(Cacheable, process::Output)>
    {
        let me = *self;
        let CCompilation { preprocessor_output, compiler } = me;
        compiler.compile(creator, executable, preprocessor_output, parsed_args, cwd, pool)
    }
}
