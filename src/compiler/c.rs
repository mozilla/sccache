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

use compiler::{Cacheable, ColorMode, Compiler, CompilerArguments, CompileCommand, CompilerHasher, CompilerKind,
               Compilation, HashResult};
use dist;
#[cfg(feature = "dist-client")]
use dist::pkg;
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::CommandCreatorSync;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
#[cfg(feature = "dist-client")]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::fs;
use std::hash::Hash;
#[cfg(feature = "dist-client")]
use std::io;
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

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Language {
    C,
    Cxx,
    ObjectiveC,
    ObjectiveCxx,
}

/// The results of parsing a compiler commandline.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone)]
pub struct ParsedArguments {
    /// The input source file.
    pub input: PathBuf,
    /// The type of language used in the input source file.
    pub language: Language,
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
    /// Whether the compilation is generating profiling or coverage data.
    pub profile_generate: bool,
}

impl ParsedArguments {
    pub fn output_pretty(&self) -> Cow<str> {
        self.outputs.get("obj")
            .and_then(|o| o.file_name())
            .map(|s| s.to_string_lossy())
            .unwrap_or(Cow::Borrowed("Unknown filename"))
    }
}

impl Language {
    pub fn from_file_name(file: &Path) -> Option<Self> {
        match file.extension().and_then(|e| e.to_str()) {
            Some("c") => Some(Language::C),
            Some("cc") | Some("cpp") | Some("cxx") => Some(Language::Cxx),
            Some("m") => Some(Language::ObjectiveC),
            Some("mm") => Some(Language::ObjectiveCxx),
            e => {
                trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
                None
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match *self {
            Language::C => "c",
            Language::Cxx => "c++",
            Language::ObjectiveC => "objc",
            Language::ObjectiveCxx => "objc++",
        }
    }
}

/// A generic implementation of the `Compilation` trait for C/C++ compilers.
struct CCompilation<I: CCompilerImpl> {
    parsed_args: ParsedArguments,
    #[cfg(feature = "dist-client")]
    preprocessed_input: Vec<u8>,
    executable: PathBuf,
    compiler: I,
    cwd: PathBuf,
    env_vars: Vec<(OsString, OsString)>,
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
                     may_dist: bool)
                     -> SFuture<process::Output> where T: CommandCreatorSync;
    /// Generate a command that can be used to invoke the C compiler to perform
    /// the compilation.
    fn generate_compile_commands(&self,
                                path_transformer: &mut dist::PathTransformer,
                                executable: &Path,
                                parsed_args: &ParsedArguments,
                                cwd: &Path,
                                env_vars: &[(OsString, OsString)])
                                -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>;
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
    #[cfg(feature = "dist-client")]
    fn get_toolchain_packager(&self) -> Box<pkg::ToolchainPackager> {
        Box::new(CToolchainPackager { executable: self.executable.clone() })
    }
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
            CompilerArguments::CannotCache(why, extra_info) => CompilerArguments::CannotCache(why, extra_info),
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
                         cwd: PathBuf,
                         env_vars: Vec<(OsString, OsString)>,
                         may_dist: bool,
                         _pool: &CpuPool)
                         -> SFuture<HashResult>
    {
        let me = *self;
        let CCompilerHasher { parsed_args, executable, executable_digest, compiler } = me;
        let result = compiler.preprocess(creator, &executable, &parsed_args, &cwd, &env_vars, may_dist);
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
                         parsed_args.language,
                         &parsed_args.common_args,
                         &env_vars,
                         &preprocessor_result.stdout)
            };
            // A compiler binary may be a symlink to another and so has the same digest, but that means
            // the toolchain will not contain the correct path to invoke the compiler! Add the compiler
            // executable path to try and prevent this
            let weak_toolchain_key = format!("{}-{}", executable.to_string_lossy(), executable_digest);
            Ok(HashResult {
                key: key,
                compilation: Box::new(CCompilation {
                    parsed_args: parsed_args,
                    #[cfg(feature = "dist-client")]
                    preprocessed_input: preprocessor_result.stdout,
                    executable: executable,
                    compiler: compiler,
                    cwd,
                    env_vars,
                }),
                weak_toolchain_key,
            })
        }))
    }

    fn color_mode(&self) -> ColorMode {
        //TODO: actually implement this for C compilers
        ColorMode::Auto
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

impl<I: CCompilerImpl> Compilation for CCompilation<I> {
    fn generate_compile_commands(&self, path_transformer: &mut dist::PathTransformer)
                                -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>
    {
        let CCompilation { ref parsed_args, ref executable, ref compiler, ref cwd, ref env_vars, .. } = *self;
        compiler.generate_compile_commands(path_transformer, executable, parsed_args, cwd, env_vars)
    }

    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(self: Box<Self>, path_transformer: dist::PathTransformer) -> Result<(Box<pkg::InputsPackager>, Box<pkg::ToolchainPackager>)> {
        let CCompilation { parsed_args, cwd, preprocessed_input, executable, .. } = *{self};
        trace!("Dist inputs: {:?}", parsed_args.input);

        let input_path = cwd.join(&parsed_args.input);
        let inputs_packager = Box::new(CInputsPackager { input_path, preprocessed_input, path_transformer });
        let toolchain_packager = Box::new(CToolchainPackager { executable });
        Ok((inputs_packager, toolchain_packager))
    }

    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a Path)> + 'a>
    {
        Box::new(self.parsed_args.outputs.iter().map(|(k, v)| (*k, &**v)))
    }
}

#[cfg(feature = "dist-client")]
struct CInputsPackager {
    input_path: PathBuf,
    path_transformer: dist::PathTransformer,
    preprocessed_input: Vec<u8>,
}

#[cfg(feature = "dist-client")]
impl pkg::InputsPackager for CInputsPackager {
    fn write_inputs(self: Box<Self>, wtr: &mut io::Write) -> Result<dist::PathTransformer> {
        use tar;

        let CInputsPackager { input_path, mut path_transformer, preprocessed_input } = *{self};

        let input_path = pkg::simplify_path(&input_path)?;
        let dist_input_path = path_transformer.to_dist(&input_path).unwrap();

        let mut builder = tar::Builder::new(wtr);

        let mut file_header = pkg::make_tar_header(&input_path, &dist_input_path)?;
        file_header.set_size(preprocessed_input.len() as u64); // The metadata is from non-preprocessed
        file_header.set_cksum();
        builder.append(&file_header, preprocessed_input.as_slice())?;

        // Finish archive
        let _ = builder.into_inner();
        Ok(path_transformer)
    }
}

#[cfg(feature = "dist-client")]
#[allow(unused)]
struct CToolchainPackager {
    executable: PathBuf,
}

#[cfg(feature = "dist-client")]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl pkg::ToolchainPackager for CToolchainPackager {
    fn write_pkg(self: Box<Self>, f: fs::File) -> Result<()> {
        use std::env;
        use std::os::unix::ffi::OsStrExt;

        info!("Packaging C compiler for executable {}", self.executable.display());
        // TODO: write our own, since this is GPL
        let curdir = env::current_dir().unwrap();
        env::set_current_dir("/tmp").unwrap();
        let output = process::Command::new("icecc-create-env").arg(&self.executable).output().unwrap();
        if !output.status.success() {
            println!("{:?}\n\n\n===========\n\n\n{:?}", output.stdout, output.stderr);
            panic!("failed to create toolchain")
        }
        let file_line = output.stdout.split(|&b| b == b'\n').find(|line| line.starts_with(b"creating ")).unwrap();
        let filename = &file_line[b"creating ".len()..];
        let filename = OsStr::from_bytes(filename);
        io::copy(&mut fs::File::open(filename).unwrap(), &mut {f}).unwrap();
        fs::remove_file(filename).unwrap();
        env::set_current_dir(curdir).unwrap();
        Ok(())
    }
}

/// The cache is versioned by the inputs to `hash_key`.
pub const CACHE_VERSION: &[u8] = b"6";

lazy_static! {
    /// Environment variables that are factored into the cache key.
    static ref CACHED_ENV_VARS: HashSet<&'static OsStr> = [
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
    ].iter().map(OsStr::new).collect();
}

/// Compute the hash key of `compiler` compiling `preprocessor_output` with `args`.
pub fn hash_key(compiler_digest: &str,
                language: Language,
                arguments: &[OsString],
                env_vars: &[(OsString, OsString)],
                preprocessor_output: &[u8]) -> String
{
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    let mut m = Digest::new();
    m.update(compiler_digest.as_bytes());
    m.update(CACHE_VERSION);
    m.update(language.as_str().as_bytes());
    for arg in arguments {
        arg.hash(&mut HashToDigest { digest: &mut m });
    }
    for &(ref var, ref val) in env_vars.iter() {
        if CACHED_ENV_VARS.contains(var.as_os_str()) {
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
        assert_neq!(hash_key("abcd", Language::C, &args, &[], &PREPROCESSED),
                    hash_key("wxyz", Language::C, &args, &[], &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_args_differs() {
        let digest = "abcd";
        let abc = ovec!["a", "b", "c"];
        let xyz = ovec!["x", "y", "z"];
        let ab = ovec!["a", "b"];
        let a = ovec!["a"];
        const PREPROCESSED: &'static [u8] = b"hello world";
        assert_neq!(hash_key(digest, Language::C, &abc, &[], &PREPROCESSED),
                    hash_key(digest, Language::C, &xyz, &[], &PREPROCESSED));

        assert_neq!(hash_key(digest, Language::C, &abc, &[], &PREPROCESSED),
                    hash_key(digest, Language::C, &ab, &[], &PREPROCESSED));

        assert_neq!(hash_key(digest, Language::C, &abc, &[], &PREPROCESSED),
                    hash_key(digest, Language::C, &a, &[], &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let args = ovec!["a", "b", "c"];
        assert_neq!(hash_key("abcd", Language::C, &args, &[], &b"hello world"[..]),
                    hash_key("abcd", Language::C, &args, &[], &b"goodbye"[..]));
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let args = ovec!["a", "b", "c"];
        let digest = "abcd";
        const PREPROCESSED: &'static [u8] = b"hello world";
        for var in CACHED_ENV_VARS.iter() {
            let h1 = hash_key(digest, Language::C, &args, &[], &PREPROCESSED);
            let vars = vec![(OsString::from(var), OsString::from("something"))];
            let h2 = hash_key(digest, Language::C, &args, &vars, &PREPROCESSED);
            let vars = vec![(OsString::from(var), OsString::from("something else"))];
            let h3 = hash_key(digest, Language::C, &args, &vars, &PREPROCESSED);
            assert_neq!(h1, h2);
            assert_neq!(h2, h3);
        }
    }
}
