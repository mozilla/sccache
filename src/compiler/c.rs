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

use compiler::{Cacheable, Compiler, CompilerArguments, CompilerHasher, CompilerKind, Compilation, HashResult};
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::CommandCreatorSync;
use sha1;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;
use std::process;
use util::{os_str_bytes, sha1_digest};

use errors::*;

/// A generic implementation of the `Compiler` trait for C/C++ compilers.
#[derive(Clone)]
pub struct CCompiler<I>
    where I: CCompilerImpl,
{
    executable: String,
    executable_digest: String,
    compiler: I,
}

/// A generic implementation of the `CompilerHasher` trait for C/C++ compilers.
#[derive(Debug, Clone)]
pub struct CCompilerHasher<I>
    where I: CCompilerImpl,
{
    parsed_args: ParsedArguments,
    executable: String,
    executable_digest: String,
    compiler: I,
}

/// The results of parsing a compiler commandline.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone)]
pub struct ParsedArguments {
    /// The input source file.
    pub input: String,
    /// The file extension of the input source file.
    pub extension: String,
    /// The file in which to generate dependencies.
    pub depfile: Option<String>,
    /// Output files, keyed by a simple name, like "obj".
    pub outputs: HashMap<&'static str, String>,
    /// Commandline arguments for the preprocessor.
    pub preprocessor_args: Vec<String>,
    /// Commandline arguments for the preprocessor or the compiler.
    pub common_args: Vec<String>,
    /// Whether or not the `-showIncludes` argument is passed on MSVC
    pub msvc_show_includes: bool,
}

impl ParsedArguments {
    pub fn output_file(&self) -> Cow<str> {
        self.outputs.get("obj").and_then(|o| Path::new(o).file_name().map(|f| f.to_string_lossy())).unwrap_or(Cow::Borrowed("Unknown filename"))
    }
}

/// A generic implementation of the `Compilation` trait for C/C++ compilers.
struct CCompilation<I: CCompilerImpl> {
    parsed_args: ParsedArguments,
    executable: String,
    /// The output from running the preprocessor.
    preprocessor_result: process::Output,
    compiler: I,
}

/// Supported C compilers.
#[derive(Debug, PartialEq, Clone)]
pub enum CCompilerKind {
    /// GCC
    GCC,
    /// clang
    Clang,
    /// Microsoft Visual C++
    MSVC,
}

/// An interface to a specific C compiler.
pub trait CCompilerImpl: Clone + fmt::Debug + Send + 'static {
    /// Return the kind of compiler.
    fn kind(&self) -> CCompilerKind;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(&self,
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>;
    /// Run the C preprocessor with the specified set of arguments.
    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &str,
                     parsed_args: &ParsedArguments,
                     cwd: &str,
                     env_vars: &[(OsString, OsString)],
                     pool: &CpuPool)
                     -> SFuture<process::Output> where T: CommandCreatorSync;
    /// Run the C compiler with the specified set of arguments, using the
    /// previously-generated `preprocessor_output` as input if possible.
    fn compile<T>(&self,
                  creator: &T,
                  executable: &str,
                  preprocessor_result: process::Output,
                  parsed_args: &ParsedArguments,
                  cwd: &str,
                  env_vars: &[(OsString, OsString)],
                  pool: &CpuPool)
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync;
}

impl <I> CCompiler<I>
    where I: CCompilerImpl,
{
    pub fn new(compiler: I, executable: String, pool: &CpuPool) -> SFuture<CCompiler<I>>
    {
        Box::new(sha1_digest(executable.clone(), &pool).map(move |digest| {
            CCompiler {
                executable: executable,
                executable_digest: digest,
                compiler: compiler,
            }
        }))
    }
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compiler<T> for CCompiler<I> {
    fn kind(&self) -> CompilerKind { CompilerKind::C(self.compiler.kind()) }
    fn parse_arguments(&self,
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments<Box<CompilerHasher<T> + 'static>> {
        match self.compiler.parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => {
                CompilerArguments::Ok(Box::new(CCompilerHasher {
                    parsed_args: args,
                    executable: self.executable.clone(),
                    executable_digest: self.executable_digest.clone(),
                    compiler: self.compiler.clone(),
                }))
            }
            CompilerArguments::CannotCache(why) => CompilerArguments::CannotCache(why),
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
        }
    }

    fn box_clone(&self) -> Box<Compiler<T>> {
        Box::new((*self).clone())
    }
}

impl<T, I> CompilerHasher<T> for CCompilerHasher<I>
    where T: CommandCreatorSync,
          I: CCompilerImpl,
{
    fn generate_hash_key(self: Box<Self>,
                         creator: &T,
                         cwd: &str,
                         env_vars: &[(OsString, OsString)],
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>
    {
        let me = *self;
        let CCompilerHasher { parsed_args, executable, executable_digest, compiler } = me;
        let result = compiler.preprocess(creator, &executable, &parsed_args, cwd, env_vars, pool);
        let out_file = parsed_args.output_file().into_owned();
        let env_vars = env_vars.to_vec();
        let result = result.map_err(move |e| {
            debug!("[{}]: preprocessor failed: {:?}", out_file, e);
            e
        });
        let out_file = parsed_args.output_file().into_owned();
        Box::new(result.or_else(move |err| {
            match err {
                Error(ErrorKind::ProcessError(output), _) => {
                    debug!("[{}]: preprocessor returned error status {:?}",
                           out_file,
                           output.status.code());
                    // Drop the stdout since it's the preprocessor output, just hand back stderr and
                    // the exit status.
                    bail!(ErrorKind::ProcessError(process::Output {
                        stdout: vec!(),
                        .. output
                    }))
                }
                e @ _ => Err(e),
            }
        }).and_then(move |preprocessor_result| {
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
                hash_key(&executable_digest, &arguments, &env_vars, &preprocessor_result.stdout)
            };
            Ok(HashResult {
                key: key,
                compilation: Box::new(CCompilation {
                    parsed_args: parsed_args,
                    executable: executable,
                    preprocessor_result: preprocessor_result,
                    compiler: compiler,
                }),
            })
        }))
    }

    fn output_file(&self) -> Cow<str>
    {
        self.parsed_args.output_file()
    }

    fn box_clone(&self) -> Box<CompilerHasher<T>>
    {
        Box::new((*self).clone())
    }
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compilation<T> for CCompilation<I> {
    fn compile(self: Box<Self>,
               creator: &T,
               cwd: &str,
               env_vars: &[(OsString, OsString)],
               pool: &CpuPool)
               -> SFuture<(Cacheable, process::Output)>
    {
        let me = *self;
        let CCompilation { parsed_args, executable, preprocessor_result, compiler } = me;
        compiler.compile(creator, &executable, preprocessor_result, &parsed_args, cwd, env_vars,
                         pool)
    }

    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a String)> + 'a>
    {
        Box::new(self.parsed_args.outputs.iter().map(|(k, v)| (*k, v)))
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
pub fn hash_key(compiler_digest: &str, arguments: &str, env_vars: &[(OsString, OsString)],
                preprocessor_output: &[u8]) -> String
{
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    let mut m = sha1::Sha1::new();
    m.update(compiler_digest.as_bytes());
    m.update(CACHE_VERSION);
    m.update(arguments.as_bytes());
    //TODO: use lazy_static.
    let cached_env_vars: HashSet<OsString> = CACHED_ENV_VARS.iter().map(|v| OsStr::new(v).to_os_string()).collect();
    for &(ref var, ref val) in env_vars.iter() {
        if cached_env_vars.contains(var) {
            m.update(os_str_bytes(var));
            m.update(&b"="[..]);
            m.update(os_str_bytes(val));
        }
    }
    m.update(preprocessor_output);
    m.digest().to_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let args = "a b c";
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key("abcd", &args, &[], &PREPROCESSED),
                    hash_key("wxyz", &args, &[], &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_args_differs() {
        let digest = "abcd";
        const PREPROCESSED: &'static [u8] = b"hello world";
        assert_neq!(hash_key(digest, "a b c", &[], &PREPROCESSED),
                    hash_key(digest, "x y z", &[], &PREPROCESSED));

        assert_neq!(hash_key(digest, "a b c", &[], &PREPROCESSED),
                    hash_key(digest, "a b", &[], &PREPROCESSED));

        assert_neq!(hash_key(digest, "a b c", &[], &PREPROCESSED),
                    hash_key(digest, "a", &[], &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let args = "a b c";
        assert_neq!(hash_key("abcd", &args, &[], &b"hello world"[..]),
                    hash_key("abcd", &args, &[], &b"goodbye"[..]));
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let args = "a b c";
        let digest = "abcd";
        const PREPROCESSED: &'static [u8] = b"hello world";
        for var in CACHED_ENV_VARS.iter() {
            let h1 = hash_key(digest, &args, &[], &PREPROCESSED);
            let vars = vec![(OsString::from(var), OsString::from("something"))];
            let h2 = hash_key(digest, &args, &vars, &PREPROCESSED);
            let vars = vec![(OsString::from(var), OsString::from("something else"))];
            let h3 = hash_key(digest, &args, &vars, &PREPROCESSED);
            assert_neq!(h1, h2);
            assert_neq!(h2, h3);
        }
    }
}
