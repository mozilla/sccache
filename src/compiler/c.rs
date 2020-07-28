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

use crate::compiler::{
    Cacheable, ColorMode, Compilation, CompileCommand, Compiler, CompilerArguments, CompilerHasher,
    CompilerKind, HashResult,
};
#[cfg(feature = "dist-client")]
use crate::compiler::{DistPackagers, NoopOutputsRewriter};
use crate::dist;
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
use crate::mock_command::CommandCreatorSync;
use crate::util::{hash_all, Digest, HashToDigest};
use futures::Future;
use futures_03::executor::ThreadPool;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::hash::Hash;
#[cfg(feature = "dist-client")]
use std::io;
use std::path::{Path, PathBuf};
use std::process;

use crate::errors::*;

/// A generic implementation of the `Compiler` trait for C/C++ compilers.
#[derive(Clone)]
pub struct CCompiler<I>
where
    I: CCompilerImpl,
{
    executable: PathBuf,
    executable_digest: String,
    compiler: I,
}

/// A generic implementation of the `CompilerHasher` trait for C/C++ compilers.
#[derive(Debug, Clone)]
pub struct CCompilerHasher<I>
where
    I: CCompilerImpl,
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
    Cuda,
}

/// The results of parsing a compiler commandline.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone)]
pub struct ParsedArguments {
    /// The input source file.
    pub input: PathBuf,
    /// The type of language used in the input source file.
    pub language: Language,
    /// The flag required to compile for the given language
    pub compilation_flag: OsString,
    /// The file in which to generate dependencies.
    pub depfile: Option<PathBuf>,
    /// Output files, keyed by a simple name, like "obj".
    pub outputs: HashMap<&'static str, PathBuf>,
    /// Commandline arguments for dependency generation.
    pub dependency_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor (not including common_args).
    pub preprocessor_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor or the compiler.
    pub common_args: Vec<OsString>,
    /// Extra files that need to have their contents hashed.
    pub extra_hash_files: Vec<PathBuf>,
    /// Whether or not the `-showIncludes` argument is passed on MSVC
    pub msvc_show_includes: bool,
    /// Whether the compilation is generating profiling or coverage data.
    pub profile_generate: bool,
    /// The color mode.
    pub color_mode: ColorMode,
}

impl ParsedArguments {
    pub fn output_pretty(&self) -> Cow<'_, str> {
        self.outputs
            .get("obj")
            .and_then(|o| o.file_name())
            .map(|s| s.to_string_lossy())
            .unwrap_or(Cow::Borrowed("Unknown filename"))
    }
}

impl Language {
    pub fn from_file_name(file: &Path) -> Option<Self> {
        match file.extension().and_then(|e| e.to_str()) {
            Some("c") => Some(Language::C),
            Some("C") | Some("cc") | Some("cpp") | Some("cxx") => Some(Language::Cxx),
            Some("m") => Some(Language::ObjectiveC),
            Some("mm") => Some(Language::ObjectiveCxx),
            Some("cu") => Some(Language::Cuda),
            e => {
                trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
                None
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::C => "c",
            Language::Cxx => "c++",
            Language::ObjectiveC => "objc",
            Language::ObjectiveCxx => "objc++",
            Language::Cuda => "cuda",
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
    /// Diab
    Diab,
    /// Microsoft Visual C++
    MSVC,
    /// NVIDIA cuda compiler
    NVCC,
    /// Tasking VX
    TaskingVX,
}

/// An interface to a specific C compiler.
pub trait CCompilerImpl: Clone + fmt::Debug + Send + 'static {
    /// Return the kind of compiler.
    fn kind(&self) -> CCompilerKind;
    /// Return true iff this is g++ or clang++.
    fn plusplus(&self) -> bool;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
    ) -> CompilerArguments<ParsedArguments>;
    /// Run the C preprocessor with the specified set of arguments.
    #[allow(clippy::too_many_arguments)]
    fn preprocess<T>(
        &self,
        creator: &T,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        may_dist: bool,
        rewrite_includes_only: bool,
    ) -> SFuture<process::Output>
    where
        T: CommandCreatorSync;
    /// Generate a command that can be used to invoke the C compiler to perform
    /// the compilation.
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        rewrite_includes_only: bool,
    ) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>;
}

impl<I> CCompiler<I>
where
    I: CCompilerImpl,
{
    pub fn new(
        compiler: I,
        executable: PathBuf,
        version: Option<String>,
        pool: &ThreadPool,
    ) -> SFuture<CCompiler<I>> {
        Box::new(
            Digest::file(executable.clone(), &pool).map(move |digest| CCompiler {
                executable,
                executable_digest: {
                    if let Some(version) = version {
                        let mut m = Digest::new();
                        m.update(digest.as_bytes());
                        m.update(version.as_bytes());
                        m.finish()
                    } else {
                        digest
                    }
                },
                compiler,
            }),
        )
    }
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compiler<T> for CCompiler<I> {
    fn kind(&self) -> CompilerKind {
        CompilerKind::C(self.compiler.kind())
    }
    #[cfg(feature = "dist-client")]
    fn get_toolchain_packager(&self) -> Box<dyn pkg::ToolchainPackager> {
        Box::new(CToolchainPackager {
            executable: self.executable.clone(),
            kind: self.compiler.kind(),
        })
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
    ) -> CompilerArguments<Box<dyn CompilerHasher<T> + 'static>> {
        match self.compiler.parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => CompilerArguments::Ok(Box::new(CCompilerHasher {
                parsed_args: args,
                executable: self.executable.clone(),
                executable_digest: self.executable_digest.clone(),
                compiler: self.compiler.clone(),
            })),
            CompilerArguments::CannotCache(why, extra_info) => {
                CompilerArguments::CannotCache(why, extra_info)
            }
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
        }
    }

    fn box_clone(&self) -> Box<dyn Compiler<T>> {
        Box::new((*self).clone())
    }
}

impl<T, I> CompilerHasher<T> for CCompilerHasher<I>
where
    T: CommandCreatorSync,
    I: CCompilerImpl,
{
    fn generate_hash_key(
        self: Box<Self>,
        creator: &T,
        cwd: PathBuf,
        env_vars: Vec<(OsString, OsString)>,
        may_dist: bool,
        pool: &ThreadPool,
        rewrite_includes_only: bool,
    ) -> SFuture<HashResult> {
        let me = *self;
        let CCompilerHasher {
            parsed_args,
            executable,
            executable_digest,
            compiler,
        } = me;
        let result = compiler.preprocess(
            creator,
            &executable,
            &parsed_args,
            &cwd,
            &env_vars,
            may_dist,
            rewrite_includes_only,
        );
        let out_pretty = parsed_args.output_pretty().into_owned();
        let result = result.map_err(move |e| {
            debug!("[{}]: preprocessor failed: {:?}", out_pretty, e);
            e
        });
        let out_pretty = parsed_args.output_pretty().into_owned();
        let extra_hashes = hash_all(&parsed_args.extra_hash_files, &pool.clone());
        let outputs = parsed_args.outputs.clone();
        let args_cwd = cwd.clone();

        Box::new(
            result
                .or_else(move |err| {
                    // Errors remove all traces of potential output.
                    debug!("removing files {:?}", &outputs);

                    let v: std::result::Result<(), std::io::Error> =
                        outputs.values().fold(Ok(()), |r, f| {
                            r.and_then(|_| {
                                let mut path = (&args_cwd).clone();
                                path.push(&f);
                                match fs::metadata(&path) {
                                    // File exists, remove it.
                                    Ok(_) => fs::remove_file(&path),
                                    _ => Ok(()),
                                }
                            })
                        });
                    if v.is_err() {
                        warn!("Could not remove files after preprocessing failed!\n");
                    }

                    match err.downcast::<ProcessError>() {
                        Ok(ProcessError(output)) => {
                            debug!(
                                "[{}]: preprocessor returned error status {:?}",
                                out_pretty,
                                output.status.code()
                            );
                            // Drop the stdout since it's the preprocessor output,
                            // just hand back stderr and the exit status.
                            bail!(ProcessError(process::Output {
                                stdout: vec!(),
                                ..output
                            }))
                        }
                        Err(err) => Err(err),
                    }
                })
                .and_then(move |preprocessor_result| {
                    trace!(
                        "[{}]: Preprocessor output is {} bytes",
                        parsed_args.output_pretty(),
                        preprocessor_result.stdout.len()
                    );

                    Box::new(extra_hashes.and_then(move |extra_hashes| {
                        let key = {
                            hash_key(
                                &executable_digest,
                                parsed_args.language,
                                &parsed_args.common_args,
                                &extra_hashes,
                                &env_vars,
                                &preprocessor_result.stdout,
                                compiler.plusplus(),
                            )
                        };
                        // A compiler binary may be a symlink to another and so has the same digest, but that means
                        // the toolchain will not contain the correct path to invoke the compiler! Add the compiler
                        // executable path to try and prevent this
                        let weak_toolchain_key =
                            format!("{}-{}", executable.to_string_lossy(), executable_digest);
                        Ok(HashResult {
                            key,
                            compilation: Box::new(CCompilation {
                                parsed_args,
                                #[cfg(feature = "dist-client")]
                                preprocessed_input: preprocessor_result.stdout,
                                executable,
                                compiler,
                                cwd,
                                env_vars,
                            }),
                            weak_toolchain_key,
                        })
                    }))
                }),
        )
    }

    fn color_mode(&self) -> ColorMode {
        self.parsed_args.color_mode
    }

    fn output_pretty(&self) -> Cow<'_, str> {
        self.parsed_args.output_pretty()
    }

    fn box_clone(&self) -> Box<dyn CompilerHasher<T>> {
        Box::new((*self).clone())
    }
}

impl<I: CCompilerImpl> Compilation for CCompilation<I> {
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        rewrite_includes_only: bool,
    ) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
        let CCompilation {
            ref parsed_args,
            ref executable,
            ref compiler,
            ref cwd,
            ref env_vars,
            ..
        } = *self;
        compiler.generate_compile_commands(
            path_transformer,
            executable,
            parsed_args,
            cwd,
            env_vars,
            rewrite_includes_only,
        )
    }

    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(
        self: Box<Self>,
        path_transformer: dist::PathTransformer,
    ) -> Result<DistPackagers> {
        let CCompilation {
            parsed_args,
            cwd,
            preprocessed_input,
            executable,
            compiler,
            ..
        } = *self;
        trace!("Dist inputs: {:?}", parsed_args.input);

        let input_path = cwd.join(&parsed_args.input);
        let inputs_packager = Box::new(CInputsPackager {
            input_path,
            preprocessed_input,
            path_transformer,
            extra_hash_files: parsed_args.extra_hash_files,
        });
        let toolchain_packager = Box::new(CToolchainPackager {
            executable,
            kind: compiler.kind(),
        });
        let outputs_rewriter = Box::new(NoopOutputsRewriter);
        Ok((inputs_packager, toolchain_packager, outputs_rewriter))
    }

    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = (&'a str, &'a Path)> + 'a> {
        Box::new(self.parsed_args.outputs.iter().map(|(k, v)| (*k, &**v)))
    }
}

#[cfg(feature = "dist-client")]
struct CInputsPackager {
    input_path: PathBuf,
    path_transformer: dist::PathTransformer,
    preprocessed_input: Vec<u8>,
    extra_hash_files: Vec<PathBuf>,
}

#[cfg(feature = "dist-client")]
impl pkg::InputsPackager for CInputsPackager {
    fn write_inputs(self: Box<Self>, wtr: &mut dyn io::Write) -> Result<dist::PathTransformer> {
        let CInputsPackager {
            input_path,
            mut path_transformer,
            preprocessed_input,
            extra_hash_files,
        } = *self;

        let mut builder = tar::Builder::new(wtr);

        {
            let input_path = pkg::simplify_path(&input_path)?;
            let dist_input_path = path_transformer.as_dist(&input_path).with_context(|| {
                format!("unable to transform input path {}", input_path.display())
            })?;

            let mut file_header = pkg::make_tar_header(&input_path, &dist_input_path)?;
            file_header.set_size(preprocessed_input.len() as u64); // The metadata is from non-preprocessed
            file_header.set_cksum();
            builder.append(&file_header, preprocessed_input.as_slice())?;
        }

        for input_path in extra_hash_files {
            let input_path = pkg::simplify_path(&input_path)?;

            if !super::CAN_DIST_DYLIBS
                && input_path
                    .extension()
                    .map_or(false, |ext| ext == std::env::consts::DLL_EXTENSION)
            {
                bail!(
                    "Cannot distribute dylib input {} on this platform",
                    input_path.display()
                )
            }

            let dist_input_path = path_transformer.as_dist(&input_path).with_context(|| {
                format!("unable to transform input path {}", input_path.display())
            })?;

            let mut file = io::BufReader::new(fs::File::open(&input_path)?);
            let mut output = vec![];
            io::copy(&mut file, &mut output)?;

            let mut file_header = pkg::make_tar_header(&input_path, &dist_input_path)?;
            file_header.set_size(output.len() as u64);
            file_header.set_cksum();
            builder.append(&file_header, &*output)?;
        }

        // Finish archive
        let _ = builder.into_inner();
        Ok(path_transformer)
    }
}

#[cfg(feature = "dist-client")]
#[allow(unused)]
struct CToolchainPackager {
    executable: PathBuf,
    kind: CCompilerKind,
}

#[cfg(feature = "dist-client")]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl pkg::ToolchainPackager for CToolchainPackager {
    fn write_pkg(self: Box<Self>, f: fs::File) -> Result<()> {
        use std::os::unix::ffi::OsStringExt;

        info!("Generating toolchain {}", self.executable.display());
        let mut package_builder = pkg::ToolchainPackageBuilder::new();
        package_builder.add_common()?;
        package_builder.add_executable_and_deps(self.executable.clone())?;

        // Helper to use -print-file-name and -print-prog-name to look up
        // files by path.
        let named_file = |kind: &str, name: &str| -> Option<PathBuf> {
            let mut output = process::Command::new(&self.executable)
                .arg(&format!("-print-{}-name={}", kind, name))
                .output()
                .ok()?;
            debug!(
                "find named {} {} output:\n{}\n===\n{}",
                kind,
                name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            if !output.status.success() {
                debug!("exit failure");
                return None;
            }

            // Remove the trailing newline (if present)
            if output.stdout.last() == Some(&b'\n') {
                output.stdout.pop();
            }

            // Create our PathBuf from the raw bytes.  Assume that relative
            // paths can be found via PATH.
            let path: PathBuf = OsString::from_vec(output.stdout).into();
            if path.is_absolute() {
                Some(path)
            } else {
                which::which(path).ok()
            }
        };

        // Helper to add a named file/program by to the package.
        // We ignore the case where the file doesn't exist, as we don't need it.
        let add_named_prog =
            |builder: &mut pkg::ToolchainPackageBuilder, name: &str| -> Result<()> {
                if let Some(path) = named_file("prog", name) {
                    builder.add_executable_and_deps(path)?;
                }
                Ok(())
            };
        let add_named_file =
            |builder: &mut pkg::ToolchainPackageBuilder, name: &str| -> Result<()> {
                if let Some(path) = named_file("file", name) {
                    builder.add_file(path)?;
                }
                Ok(())
            };

        // Add basic |as| and |objcopy| programs.
        add_named_prog(&mut package_builder, "as")?;
        add_named_prog(&mut package_builder, "objcopy")?;

        // Linker configuration.
        if Path::new("/etc/ld.so.conf").is_file() {
            package_builder.add_file("/etc/ld.so.conf".into())?;
        }

        // Compiler-specific handling
        match self.kind {
            CCompilerKind::Clang => {
                // Clang uses internal header files, so add them.
                if let Some(limits_h) = named_file("file", "include/limits.h") {
                    info!("limits_h = {}", limits_h.display());
                    package_builder.add_dir_contents(limits_h.parent().unwrap())?;
                }
            }

            CCompilerKind::GCC => {
                // Various external programs / files which may be needed by gcc
                add_named_prog(&mut package_builder, "cc1")?;
                add_named_prog(&mut package_builder, "cc1plus")?;
                add_named_file(&mut package_builder, "specs")?;
                add_named_file(&mut package_builder, "liblto_plugin.so")?;
            }

            CCompilerKind::NVCC => {
                // Various programs called by the nvcc front end.
                // presumes the underlying host compiler is consistent
                add_named_file(&mut package_builder, "cudafe++")?;
                add_named_file(&mut package_builder, "fatbinary")?;
                add_named_prog(&mut package_builder, "nvlink")?;
                add_named_prog(&mut package_builder, "ptxas")?;
            }

            _ => unreachable!(),
        }

        // Bundle into a compressed tarfile.
        package_builder.into_compressed_tar(f)
    }
}

/// The cache is versioned by the inputs to `hash_key`.
pub const CACHE_VERSION: &[u8] = b"10";

lazy_static! {
    /// Environment variables that are factored into the cache key.
    static ref CACHED_ENV_VARS: HashSet<&'static OsStr> = [
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
    ].iter().map(OsStr::new).collect();
}

/// Compute the hash key of `compiler` compiling `preprocessor_output` with `args`.
pub fn hash_key(
    compiler_digest: &str,
    language: Language,
    arguments: &[OsString],
    extra_hashes: &[String],
    env_vars: &[(OsString, OsString)],
    preprocessor_output: &[u8],
    plusplus: bool,
) -> String {
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    let mut m = Digest::new();
    m.update(compiler_digest.as_bytes());
    // clang and clang++ have different behavior despite being byte-for-byte identical binaries, so
    // we have to incorporate that into the hash as well.
    m.update(&[plusplus as u8]);
    m.update(CACHE_VERSION);
    m.update(language.as_str().as_bytes());
    for arg in arguments {
        arg.hash(&mut HashToDigest { digest: &mut m });
    }
    for hash in extra_hashes {
        m.update(hash.as_bytes());
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
    fn test_same_content() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_eq!(
            hash_key("abcd", Language::C, &args, &[], &[], &PREPROCESSED, false),
            hash_key("abcd", Language::C, &args, &[], &[], &PREPROCESSED, false)
        );
    }

    #[test]
    fn test_plusplus_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key("abcd", Language::C, &args, &[], &[], &PREPROCESSED, false),
            hash_key("abcd", Language::C, &args, &[], &[], &PREPROCESSED, true)
        );
    }

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key("abcd", Language::C, &args, &[], &[], &PREPROCESSED, false),
            hash_key("wxyz", Language::C, &args, &[], &[], &PREPROCESSED, false)
        );
    }

    #[test]
    fn test_hash_key_args_differs() {
        let digest = "abcd";
        let abc = ovec!["a", "b", "c"];
        let xyz = ovec!["x", "y", "z"];
        let ab = ovec!["a", "b"];
        let a = ovec!["a"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key(digest, Language::C, &abc, &[], &[], &PREPROCESSED, false),
            hash_key(digest, Language::C, &xyz, &[], &[], &PREPROCESSED, false)
        );

        assert_neq!(
            hash_key(digest, Language::C, &abc, &[], &[], &PREPROCESSED, false),
            hash_key(digest, Language::C, &ab, &[], &[], &PREPROCESSED, false)
        );

        assert_neq!(
            hash_key(digest, Language::C, &abc, &[], &[], &PREPROCESSED, false),
            hash_key(digest, Language::C, &a, &[], &[], &PREPROCESSED, false)
        );
    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let args = ovec!["a", "b", "c"];
        assert_neq!(
            hash_key(
                "abcd",
                Language::C,
                &args,
                &[],
                &[],
                &b"hello world"[..],
                false
            ),
            hash_key("abcd", Language::C, &args, &[], &[], &b"goodbye"[..], false)
        );
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let args = ovec!["a", "b", "c"];
        let digest = "abcd";
        const PREPROCESSED: &[u8] = b"hello world";
        for var in CACHED_ENV_VARS.iter() {
            let h1 = hash_key(digest, Language::C, &args, &[], &[], &PREPROCESSED, false);
            let vars = vec![(OsString::from(var), OsString::from("something"))];
            let h2 = hash_key(digest, Language::C, &args, &[], &vars, &PREPROCESSED, false);
            let vars = vec![(OsString::from(var), OsString::from("something else"))];
            let h3 = hash_key(digest, Language::C, &args, &[], &vars, &PREPROCESSED, false);
            assert_neq!(h1, h2);
            assert_neq!(h2, h3);
        }
    }

    #[test]
    fn test_extra_hash_data() {
        let args = ovec!["a", "b", "c"];
        let digest = "abcd";
        const PREPROCESSED: &[u8] = b"hello world";
        let extra_data = stringvec!["hello", "world"];

        assert_neq!(
            hash_key(
                digest,
                Language::C,
                &args,
                &extra_data,
                &[],
                &PREPROCESSED,
                false
            ),
            hash_key(digest, Language::C, &args, &[], &[], &PREPROCESSED, false)
        );
    }
}
