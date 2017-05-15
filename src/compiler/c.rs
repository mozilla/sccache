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
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::process;
use util::{HashToDigest, Digest};

use errors::*;

/// A generic implementation of the `Compiler` trait for C/C++ compilers.
#[derive(Clone)]
pub struct CCompiler<I>
    where I: CCompilerImpl,
{
    executable: PathBuf,
    executable_digest: String,
    compiler: I,
}

/// A generic implementation of the `CompilerHasher` trait for C/C++ compilers.
#[derive(Debug, Clone)]
pub struct CCompilerHasher<I>
    where I: CCompilerImpl,
{
    parsed_args: ParsedArguments,
    executable: PathBuf,
    executable_digest: String,
    compiler: I,
}

/// The results of parsing a compiler commandline.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone)]
pub struct ParsedArguments {
    /// The input source file.
    pub input: PathBuf,
    /// The file extension of the input source file.
    pub extension: String,
    /// The file in which to generate dependencies.
    pub depfile: Option<PathBuf>,
    /// Output files, keyed by a simple name, like "obj".
    pub outputs: HashMap<&'static str, PathBuf>,
    /// Commandline arguments for the preprocessor.
    pub preprocessor_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor or the compiler.
    pub common_args: Vec<OsString>,
    /// Whether or not the `-showIncludes` argument is passed on MSVC
    pub msvc_show_includes: bool,
}

impl ParsedArguments {
    pub fn output_pretty(&self) -> Cow<str> {
        self.outputs.get("obj")
            .and_then(|o| o.file_name())
            .map(|s| s.to_string_lossy())
            .unwrap_or(Cow::Borrowed("Unknown filename"))
    }
}

/// A generic implementation of the `Compilation` trait for C/C++ compilers.
struct CCompilation<I: CCompilerImpl> {
    parsed_args: ParsedArguments,
    executable: PathBuf,
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
                       arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>;
    /// Run the C preprocessor with the specified set of arguments.
    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     pool: &CpuPool)
                     -> SFuture<process::Output> where T: CommandCreatorSync;
    /// Run the C compiler with the specified set of arguments, using the
    /// previously-generated `preprocessor_output` as input if possible.
    fn compile<T>(&self,
                  creator: &T,
                  executable: &Path,
                  preprocessor_result: process::Output,
                  parsed_args: &ParsedArguments,
                  cwd: &Path,
                  env_vars: &[(OsString, OsString)],
                  pool: &CpuPool)
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync;
}

impl <I> CCompiler<I>
    where I: CCompilerImpl,
{
    pub fn new(compiler: I, executable: PathBuf, pool: &CpuPool) -> SFuture<CCompiler<I>>
    {
        Box::new(Digest::file(executable.clone(), &pool).map(move |digest| {
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
                       arguments: &[OsString],
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
                         cwd: &Path,
                         env_vars: &[(OsString, OsString)],
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>
    {
        let me = *self;
        let CCompilerHasher { parsed_args, executable, executable_digest, compiler } = me;
        let result = compiler.preprocess(creator, &executable, &parsed_args, cwd, env_vars, pool);
        let out_pretty = parsed_args.output_pretty().into_owned();
        let env_vars = env_vars.to_vec();
        let result = result.map_err(move |e| {
            debug!("[{}]: preprocessor failed: {:?}", out_pretty, e);
            e
        });
        let out_pretty = parsed_args.output_pretty().into_owned();
        Box::new(result.or_else(move |err| {
            match err {
                Error(ErrorKind::ProcessError(output), _) => {
                    debug!("[{}]: preprocessor returned error status {:?}",
                           out_pretty,
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
                   parsed_args.output_pretty(),
                   preprocessor_result.stdout.len());

            let key = {
                hash_key(&executable_digest,
                         &parsed_args.common_args,
                         &env_vars,
                         &preprocessor_result.stdout)
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

    fn output_pretty(&self) -> Cow<str>
    {
        self.parsed_args.output_pretty()
    }

    fn box_clone(&self) -> Box<CompilerHasher<T>>
    {
        Box::new((*self).clone())
    }
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compilation<T> for CCompilation<I> {
    fn compile(self: Box<Self>,
               creator: &T,
               cwd: &Path,
               env_vars: &[(OsString, OsString)],
               pool: &CpuPool)
               -> SFuture<(Cacheable, process::Output)>
    {
        let me = *self;
        let CCompilation { parsed_args, executable, preprocessor_result, compiler } = me;
        compiler.compile(creator, &executable, preprocessor_result, &parsed_args, cwd, env_vars,
                         pool)
    }

    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a Path)> + 'a>
    {
        Box::new(self.parsed_args.outputs.iter().map(|(k, v)| (*k, &**v)))
    }
}

/// The cache is versioned by the inputs to `hash_key`.
pub const CACHE_VERSION : &'static [u8] = b"4";

/// Environment variables that are factored into the cache key.
pub const CACHED_ENV_VARS : &'static [&'static str] = &[
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
];

/// Compute the hash key of `compiler` compiling `preprocessor_output` with `args`.
pub fn hash_key(compiler_digest: &str,
                arguments: &[OsString],
                env_vars: &[(OsString, OsString)],
                preprocessor_output: &[u8]) -> String
{
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    let mut m = Digest::new();
    m.update(compiler_digest.as_bytes());
    m.update(CACHE_VERSION);
    for arg in arguments {
        arg.hash(&mut HashToDigest { digest: &mut m });
    }
    //TODO: use lazy_static.
    let cached_env_vars: HashSet<OsString> = CACHED_ENV_VARS.iter().map(|v| OsStr::new(v).to_os_string()).collect();
    for &(ref var, ref val) in env_vars.iter() {
        if cached_env_vars.contains(var) {
            var.hash(&mut HashToDigest { digest: &mut m });
            m.update(&b"="[..]);
            val.hash(&mut HashToDigest { digest: &mut m });
        }
    }
    m.update(preprocessor_output);
    m.finish()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key("abcd",&args, &[], &PREPROCESSED),
                    hash_key("wxyz",&args, &[], &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_args_differs() {
        let digest = "abcd";
        let abc = ovec!["a", "b", "c"];
        let xyz = ovec!["x", "y", "z"];
        let ab = ovec!["a", "b"];
        let a = ovec!["a"];
        const PREPROCESSED: &'static [u8] = b"hello world";
        assert_neq!(hash_key(digest, &abc, &[], &PREPROCESSED),
                    hash_key(digest, &xyz, &[], &PREPROCESSED));

        assert_neq!(hash_key(digest, &abc, &[], &PREPROCESSED),
                    hash_key(digest, &ab, &[], &PREPROCESSED));

        assert_neq!(hash_key(digest, &abc, &[], &PREPROCESSED),
                    hash_key(digest, &a, &[], &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let args = ovec!["a", "b", "c"];
        assert_neq!(hash_key("abcd", &args, &[], &b"hello world"[..]),
                    hash_key("abcd", &args, &[], &b"goodbye"[..]));
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let args = ovec!["a", "b", "c"];
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
