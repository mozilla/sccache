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

use compiler::{Cacheable, Compiler, CompilerArguments, CompilerKind, Compilation, HashResult, ParsedArguments};
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::CommandCreatorSync;
use sha1;
use std::env;
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

/// The cache is versioned by the inputs to `hash_key`.
pub const CACHE_VERSION : &'static [u8] = b"3";

/// Environment variables that are factored into the cache key.
pub const CACHED_ENV_VARS : &'static [&'static str] = &[
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
];

/// Compute the hash key of `compiler` compiling `preprocessor_output` with `args`.
pub fn hash_key(compiler_digest: &str, arguments: &str, preprocessor_output: &[u8]) -> String {
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    let mut m = sha1::Sha1::new();
    m.update(compiler_digest.as_bytes());
    m.update(CACHE_VERSION);
    m.update(arguments.as_bytes());
    //TODO: should propogate these over from the client.
    // https://github.com/glandium/sccache/issues/5
    for var in CACHED_ENV_VARS.iter() {
        if let Ok(val) = env::var(var) {
            m.update(var.as_bytes());
            m.update(&b"="[..]);
            m.update(val.as_bytes());
        }
    }
    m.update(preprocessor_output);
    m.digest().to_string()
}

#[cfg(test)]
mod test {
    use super::*;
    use compiler::{CompilerInfo, get_gcc};
    use std::env;
    use std::io::Write;
    use test::utils::*;

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let f = TestFixture::new();
        // Try to avoid testing exact hashes.
        let c1 = CompilerInfo::new(f.bins[0].to_str().unwrap(), get_gcc()).unwrap();
        // Overwrite the contents of the binary.
        mk_bin_contents(f.tempdir.path(), "a/bin", |mut f| f.write_all(b"hello")).unwrap();
        let c2 = CompilerInfo::new(f.bins[0].to_str().unwrap(), get_gcc()).unwrap();
        let args = "a b c";
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key(&c1.digest, &args, &PREPROCESSED),
                    hash_key(&c2.digest, &args, &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_args_differs() {
        let f = TestFixture::new();
        let c = CompilerInfo::new(f.bins[0].to_str().unwrap(), get_gcc()).unwrap();
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key(&c.digest, "a b c", &PREPROCESSED),
                    hash_key(&c.digest, "x y z", &PREPROCESSED));

        assert_neq!(hash_key(&c.digest, "a b c", &PREPROCESSED),
                    hash_key(&c.digest, "a b", &PREPROCESSED));

        assert_neq!(hash_key(&c.digest, "a b c", &PREPROCESSED),
                    hash_key(&c.digest, "a", &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let f = TestFixture::new();
        let c = CompilerInfo::new(f.bins[0].to_str().unwrap(), get_gcc()).unwrap();
        let args = "a b c";
        assert_neq!(hash_key(&c.digest, &args, &b"hello world"[..]),
                    hash_key(&c.digest, &args, &b"goodbye"[..]));
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let f = TestFixture::new();
        let c = CompilerInfo::new(f.bins[0].to_str().unwrap(), get_gcc()).unwrap();
        let args = "a b c";
        const PREPROCESSED : &'static [u8] = b"hello world";
        for var in CACHED_ENV_VARS.iter() {
            let old = env::var_os(var);
            env::remove_var(var);
            let h1 = hash_key(&c.digest, &args, &PREPROCESSED);
            env::set_var(var, "something");
            let h2 = hash_key(&c.digest, &args, &PREPROCESSED);
            env::set_var(var, "something else");
            let h3 = hash_key(&c.digest, &args, &PREPROCESSED);
            match old {
                Some(val) => env::set_var(var, val),
                None => env::remove_var(var),
            }
            assert_neq!(h1, h2);
            assert_neq!(h2, h3);
        }
    }
}
