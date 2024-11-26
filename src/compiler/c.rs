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

use crate::cache::{FileObjectSource, PreprocessorCacheModeConfig, Storage};
use crate::compiler::preprocessor_cache::preprocessor_cache_entry_hash_key;
use crate::compiler::{
    Cacheable, ColorMode, Compilation, CompileCommand, Compiler, CompilerArguments, CompilerHasher,
    CompilerKind, HashResult, Language,
};
#[cfg(feature = "dist-client")]
use crate::compiler::{DistPackagers, NoopOutputsRewriter};
use crate::dist;
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
use crate::mock_command::CommandCreatorSync;
use crate::util::{
    decode_path, encode_path, hash_all, Digest, HashToDigest, MetadataCtimeExt, TimeMacroFinder,
    Timestamp,
};
use async_trait::async_trait;
use fs_err as fs;
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::hash::Hash;
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use crate::errors::*;

use super::preprocessor_cache::PreprocessorCacheEntry;
use super::CacheControl;

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

/// Artifact produced by a C/C++ compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDescriptor {
    /// Path to the artifact.
    pub path: PathBuf,
    /// Whether the artifact is an optional object file.
    pub optional: bool,
}

/// The results of parsing a compiler commandline.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedArguments {
    /// The input source file.
    pub input: PathBuf,
    /// Whether to prepend the input with `--`
    pub double_dash_input: bool,
    /// The type of language used in the input source file.
    pub language: Language,
    /// The flag required to compile for the given language
    pub compilation_flag: OsString,
    /// The file in which to generate dependencies.
    pub depfile: Option<PathBuf>,
    /// Output files and whether it's optional, keyed by a simple name, like "obj".
    pub outputs: HashMap<&'static str, ArtifactDescriptor>,
    /// Commandline arguments for dependency generation.
    pub dependency_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor (not including common_args).
    pub preprocessor_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor or the compiler.
    pub common_args: Vec<OsString>,
    /// Commandline arguments for the compiler that specify the architecture given
    pub arch_args: Vec<OsString>,
    /// Commandline arguments for the preprocessor or the compiler that don't affect the computed hash.
    pub unhashed_args: Vec<OsString>,
    /// Extra unhashed files that need to be sent along with dist compiles.
    pub extra_dist_files: Vec<PathBuf>,
    /// Extra files that need to have their contents hashed.
    pub extra_hash_files: Vec<PathBuf>,
    /// Whether or not the `-showIncludes` argument is passed on MSVC
    pub msvc_show_includes: bool,
    /// Whether the compilation is generating profiling or coverage data.
    pub profile_generate: bool,
    /// The color mode.
    pub color_mode: ColorMode,
    /// arguments are incompatible with rewrite_includes_only
    pub suppress_rewrite_includes_only: bool,
    /// Arguments are incompatible with preprocessor cache mode
    pub too_hard_for_preprocessor_cache_mode: Option<OsString>,
}

impl ParsedArguments {
    pub fn output_pretty(&self) -> Cow<'_, str> {
        self.outputs
            .get("obj")
            .and_then(|o| o.path.file_name())
            .map(|s| s.to_string_lossy())
            .unwrap_or(Cow::Borrowed("Unknown filename"))
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CCompilerKind {
    /// GCC
    Gcc,
    /// clang
    Clang,
    /// Diab
    Diab,
    /// Microsoft Visual C++
    Msvc,
    /// NVIDIA CUDA compiler
    Nvcc,
    /// NVIDIA CUDA optimizer and PTX generator
    Cicc,
    /// NVIDIA CUDA PTX assembler
    Ptxas,
    /// NVIDIA hpc c, c++ compiler
    Nvhpc,
    /// Tasking VX
    TaskingVX,
}

/// An interface to a specific C compiler.
#[async_trait]
pub trait CCompilerImpl: Clone + fmt::Debug + Send + Sync + 'static {
    /// Return the kind of compiler.
    fn kind(&self) -> CCompilerKind;
    /// Return true iff this is g++ or clang++.
    fn plusplus(&self) -> bool;
    /// Return the compiler version reported by the compiler executable.
    fn version(&self) -> Option<String>;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments>;
    /// Run the C preprocessor with the specified set of arguments.
    #[allow(clippy::too_many_arguments)]
    async fn preprocess<T>(
        &self,
        creator: &T,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        may_dist: bool,
        rewrite_includes_only: bool,
        preprocessor_cache_mode: bool,
    ) -> Result<process::Output>
    where
        T: CommandCreatorSync;
    /// Generate a command that can be used to invoke the C compiler to perform
    /// the compilation.
    fn generate_compile_commands<T>(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        rewrite_includes_only: bool,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )>
    where
        T: CommandCreatorSync;
}

impl<I> CCompiler<I>
where
    I: CCompilerImpl,
{
    pub async fn new(
        compiler: I,
        executable: PathBuf,
        pool: &tokio::runtime::Handle,
    ) -> Result<CCompiler<I>> {
        let digest = Digest::file(executable.clone(), pool).await?;

        Ok(CCompiler {
            executable,
            executable_digest: {
                if let Some(version) = compiler.version() {
                    let mut m = Digest::new();
                    m.update(digest.as_bytes());
                    m.update(version.as_bytes());
                    m.finish()
                } else {
                    digest
                }
            },
            compiler,
        })
    }

    fn extract_rocm_arg(args: &ParsedArguments, flag: &str) -> Option<PathBuf> {
        args.common_args.iter().find_map(|arg| match arg.to_str() {
            Some(sarg) if sarg.starts_with(flag) => {
                Some(PathBuf::from(sarg[arg.len()..].to_string()))
            }
            _ => None,
        })
    }

    fn extract_rocm_env(env_vars: &[(OsString, OsString)], name: &str) -> Option<PathBuf> {
        env_vars.iter().find_map(|(k, v)| match v.to_str() {
            Some(path) if k == name => Some(PathBuf::from(path.to_string())),
            _ => None,
        })
    }

    // See https://clang.llvm.org/docs/HIPSupport.html for details regarding the
    // order in which the environment variables and command-line arguments control the
    // directory to search for bitcode libraries.
    fn search_hip_device_libs(
        args: &ParsedArguments,
        env_vars: &[(OsString, OsString)],
    ) -> Vec<PathBuf> {
        let rocm_path_arg: Option<PathBuf> = Self::extract_rocm_arg(args, "--rocm-path=");
        let hip_device_lib_path_arg: Option<PathBuf> =
            Self::extract_rocm_arg(args, "--hip-device-lib-path=");
        let rocm_path_env: Option<PathBuf> = Self::extract_rocm_env(env_vars, "ROCM_PATH");
        let hip_device_lib_path_env: Option<PathBuf> =
            Self::extract_rocm_env(env_vars, "HIP_DEVICE_LIB_PATH");

        let hip_device_lib_path: PathBuf = hip_device_lib_path_arg
            .or(hip_device_lib_path_env)
            .or(rocm_path_arg.map(|path| path.join("amdgcn").join("bitcode")))
            .or(rocm_path_env.map(|path| path.join("amdgcn").join("bitcode")))
            // This is the default location in official AMD packages and containers.
            .unwrap_or(PathBuf::from("/opt/rocm/amdgcn/bitcode"));

        hip_device_lib_path
            .read_dir()
            .ok()
            .map(|f| {
                f.flatten()
                    .filter(|f| f.path().extension().map_or(false, |ext| ext == "bc"))
                    .map(|f| f.path())
                    .collect()
            })
            .unwrap_or_default()
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
        env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<Box<dyn CompilerHasher<T> + 'static>> {
        match self.compiler.parse_arguments(arguments, cwd, env_vars) {
            CompilerArguments::Ok(mut args) => {
                // Handle SCCACHE_EXTRAFILES
                for (k, v) in env_vars.iter() {
                    if k.as_os_str() == OsStr::new("SCCACHE_EXTRAFILES") {
                        args.extra_hash_files.extend(std::env::split_paths(&v))
                    }
                }

                // Handle cache invalidation for the ROCm device bitcode libraries. Every HIP
                // object links in some LLVM bitcode libraries (.bc files), so in some sense
                // every HIP object compilation has an direct dependency on those bitcode
                // libraries.
                //
                // The bitcode libraries are unlikely to change **except** when a ROCm version
                // changes, so for correctness we should take these bitcode libraries into
                // account by adding them to `extra_hash_files`.
                //
                // In reality, not every available bitcode library is needed, but that is
                // too much to handle on our side so we just hash every bitcode library we find.
                if args.language == Language::Hip {
                    args.extra_hash_files
                        .extend(Self::search_hip_device_libs(&args, env_vars))
                }

                CompilerArguments::Ok(Box::new(CCompilerHasher {
                    parsed_args: args,
                    executable: self.executable.clone(),
                    executable_digest: self.executable_digest.clone(),
                    compiler: self.compiler.clone(),
                }))
            }
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

#[async_trait]
impl<T, I> CompilerHasher<T> for CCompilerHasher<I>
where
    T: CommandCreatorSync,
    I: CCompilerImpl,
{
    async fn generate_hash_key(
        self: Box<Self>,
        creator: &T,
        cwd: PathBuf,
        env_vars: Vec<(OsString, OsString)>,
        may_dist: bool,
        pool: &tokio::runtime::Handle,
        rewrite_includes_only: bool,
        storage: Arc<dyn Storage>,
        cache_control: CacheControl,
    ) -> Result<HashResult<T>> {
        let start_of_compilation = std::time::SystemTime::now();
        let CCompilerHasher {
            parsed_args,
            executable,
            executable_digest,
            compiler,
        } = *self;

        let extra_hashes = hash_all(&parsed_args.extra_hash_files, &pool.clone()).await?;
        // Create an argument vector containing both preprocessor and arch args, to
        // use in creating a hash key
        let mut preprocessor_and_arch_args = parsed_args.preprocessor_args.clone();
        preprocessor_and_arch_args.extend(parsed_args.arch_args.to_vec());
        // common_args is used in preprocessing too
        preprocessor_and_arch_args.extend(parsed_args.common_args.to_vec());

        let absolute_input_path: Cow<'_, _> = if parsed_args.input.is_absolute() {
            Cow::Borrowed(&parsed_args.input)
        } else {
            Cow::Owned(cwd.join(&parsed_args.input))
        };

        // Try to look for a cached preprocessing step for this compilation
        // request.
        let preprocessor_cache_mode_config = storage.preprocessor_cache_mode_config();
        let too_hard_for_preprocessor_cache_mode =
            parsed_args.too_hard_for_preprocessor_cache_mode.is_some();
        if let Some(arg) = &parsed_args.too_hard_for_preprocessor_cache_mode {
            debug!(
                "parse_arguments: Cannot use preprocessor cache because of {:?}",
                arg
            );
        }

        let use_preprocessor_cache_mode = {
            let can_use_preprocessor_cache_mode = !may_dist
                && preprocessor_cache_mode_config.use_preprocessor_cache_mode
                && !too_hard_for_preprocessor_cache_mode;

            let mut use_preprocessor_cache_mode = can_use_preprocessor_cache_mode;

            // Allow overrides from the env
            for (key, val) in env_vars.iter() {
                if key == "SCCACHE_DIRECT" {
                    if let Some(val) = val.to_str() {
                        use_preprocessor_cache_mode = match val.to_lowercase().as_str() {
                            "false" | "off" | "0" => false,
                            _ => can_use_preprocessor_cache_mode,
                        };
                    }
                    break;
                }
            }

            if can_use_preprocessor_cache_mode && !use_preprocessor_cache_mode {
                debug!(
                    "parse_arguments: Disabling preprocessor cache because SCCACHE_DIRECT=false"
                );
            }

            use_preprocessor_cache_mode
        };

        // Disable preprocessor cache when doing distributed compilation
        let mut preprocessor_key = if use_preprocessor_cache_mode {
            preprocessor_cache_entry_hash_key(
                &executable_digest,
                parsed_args.language,
                &preprocessor_and_arch_args,
                &extra_hashes,
                &env_vars,
                &absolute_input_path,
                compiler.plusplus(),
                preprocessor_cache_mode_config,
            )?
        } else {
            None
        };
        if let Some(preprocessor_key) = &preprocessor_key {
            if cache_control == CacheControl::Default {
                if let Some(mut seekable) = storage
                    .get_preprocessor_cache_entry(preprocessor_key)
                    .await?
                {
                    let mut buf = vec![];
                    seekable.read_to_end(&mut buf)?;
                    let mut preprocessor_cache_entry = PreprocessorCacheEntry::read(&buf)?;
                    let mut updated = false;
                    let hit = preprocessor_cache_entry
                        .lookup_result_digest(preprocessor_cache_mode_config, &mut updated);

                    let mut update_failed = false;
                    if updated {
                        // Time macros have been found, we need to update
                        // the preprocessor cache entry. See [`PreprocessorCacheEntry::result_matches`].
                        debug!(
                            "Preprocessor cache updated because of time macros: {preprocessor_key}"
                        );

                        if let Err(e) = storage
                            .put_preprocessor_cache_entry(
                                preprocessor_key,
                                preprocessor_cache_entry,
                            )
                            .await
                        {
                            debug!("Failed to update preprocessor cache: {}", e);
                            update_failed = true;
                        }
                    }

                    if !update_failed {
                        if let Some(key) = hit {
                            debug!("Preprocessor cache hit: {preprocessor_key}");
                            // A compiler binary may be a symlink to another and
                            // so has the same digest, but that means
                            // the toolchain will not contain the correct path
                            // to invoke the compiler! Add the compiler
                            // executable path to try and prevent this
                            let weak_toolchain_key =
                                format!("{}-{}", executable.to_string_lossy(), executable_digest);
                            return Ok(HashResult {
                                key,
                                compilation: Box::new(CCompilation {
                                    parsed_args: parsed_args.to_owned(),
                                    #[cfg(feature = "dist-client")]
                                    // TODO or is it never relevant since dist?
                                    preprocessed_input: vec![],
                                    executable: executable.to_owned(),
                                    compiler: compiler.to_owned(),
                                    cwd: cwd.to_owned(),
                                    env_vars: env_vars.to_owned(),
                                }),
                                weak_toolchain_key,
                            });
                        } else {
                            debug!("Preprocessor cache miss: {preprocessor_key}");
                        }
                    }
                }
            }
        }

        let result = compiler
            .preprocess(
                creator,
                &executable,
                &parsed_args,
                &cwd,
                &env_vars,
                may_dist,
                rewrite_includes_only,
                use_preprocessor_cache_mode,
            )
            .await;
        let out_pretty = parsed_args.output_pretty().into_owned();
        let result = result.map_err(|e| {
            debug!("[{}]: preprocessor failed: {:?}", out_pretty, e);
            e
        });

        let outputs = parsed_args.outputs.clone();
        let args_cwd = cwd.clone();

        let mut preprocessor_result = result.or_else(move |err| {
            // Errors remove all traces of potential output.
            debug!("removing files {:?}", &outputs);

            let v: std::result::Result<(), std::io::Error> =
                outputs.values().try_for_each(|output| {
                    let mut path = args_cwd.clone();
                    path.push(&output.path);
                    match fs::metadata(&path) {
                        // File exists, remove it.
                        Ok(_) => fs::remove_file(&path),
                        _ => Ok(()),
                    }
                });
            if v.is_err() {
                warn!("Could not remove files after preprocessing failed!");
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
        })?;

        // Remember include files needed in this preprocessing step
        let mut include_files = HashMap::new();
        if preprocessor_key.is_some() {
            // TODO how to propagate stats and which stats?
            if !process_preprocessed_file(
                &absolute_input_path,
                &cwd,
                &mut preprocessor_result.stdout,
                &mut include_files,
                preprocessor_cache_mode_config,
                start_of_compilation,
                StandardFsAbstraction,
            )? {
                debug!("Disabling preprocessor cache mode");
                preprocessor_key = None;
            }
        }

        trace!(
            "[{}]: Preprocessor output is {} bytes",
            parsed_args.output_pretty(),
            preprocessor_result.stdout.len()
        );

        // Create an argument vector containing both common and arch args, to
        // use in creating a hash key
        let mut common_and_arch_args = parsed_args.common_args.clone();
        common_and_arch_args.extend(parsed_args.arch_args.to_vec());

        let key = {
            hash_key(
                &executable_digest,
                parsed_args.language,
                &common_and_arch_args,
                &extra_hashes,
                &env_vars,
                &preprocessor_result.stdout,
                compiler.plusplus(),
            )
        };

        // Cache the preprocessing step
        if let Some(preprocessor_key) = preprocessor_key {
            if !include_files.is_empty() {
                let mut preprocessor_cache_entry = PreprocessorCacheEntry::new();
                let mut files: Vec<_> = include_files
                    .into_iter()
                    .map(|(path, digest)| (digest, path))
                    .collect();
                files.sort_unstable_by(|a, b| a.1.cmp(&b.1));
                preprocessor_cache_entry.add_result(start_of_compilation, &key, files);

                if let Err(e) = storage
                    .put_preprocessor_cache_entry(&preprocessor_key, preprocessor_cache_entry)
                    .await
                {
                    debug!("Failed to update preprocessor cache: {}", e);
                }
            }
        }

        // A compiler binary may be a symlink to another and so has the same digest, but that means
        // the toolchain will not contain the correct path to invoke the compiler! Add the compiler
        // executable path to try and prevent this
        let weak_toolchain_key = format!("{}-{}", executable.to_string_lossy(), executable_digest);
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

    fn language(&self) -> Language {
        self.parsed_args.language
    }
}

const PRAGMA_GCC_PCH_PREPROCESS: &[u8] = b"pragma GCC pch_preprocess";
const HASH_31_COMMAND_LINE_NEWLINE: &[u8] = b"# 31 \"<command-line>\"\n";
const HASH_32_COMMAND_LINE_2_NEWLINE: &[u8] = b"# 32 \"<command-line>\" 2\n";
const INCBIN_DIRECTIVE: &[u8] = b".incbin";

/// Remember the include files in the preprocessor output if it can be cached.
/// Returns `false` if preprocessor cache mode should be disabled.
fn process_preprocessed_file(
    input_file: &Path,
    cwd: &Path,
    bytes: &mut [u8],
    included_files: &mut HashMap<PathBuf, String>,
    config: PreprocessorCacheModeConfig,
    time_of_compilation: std::time::SystemTime,
    fs_impl: impl PreprocessorFSAbstraction,
) -> Result<bool> {
    let mut start = 0;
    let mut hash_start = 0;
    let total_len = bytes.len();
    let mut digest = Digest::new();
    let mut normalized_include_paths: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();
    // There must be at least 7 characters (# 1 "x") left to potentially find an
    // include file path.
    while start < total_len.saturating_sub(7) {
        let mut slice = &bytes[start..];
        // Check if we look at a line containing the file name of an included file.
        // At least the following formats exist (where N is a positive integer):
        //
        // GCC:
        //
        //   # N "file"
        //   # N "file" N
        //   #pragma GCC pch_preprocess "file"
        //
        // HP's compiler:
        //
        //   #line N "file"
        //
        // AIX's compiler:
        //
        //   #line N "file"
        //   #line N
        //
        // Note that there may be other lines starting with '#' left after
        // preprocessing as well, for instance "#    pragma".
        if slice[0] == b'#'
        // GCC:
        && ((slice[1] == b' ' && slice[2] >= b'0' && slice[2] <= b'9')
            // GCC precompiled header:
            || slice[1..].starts_with(PRAGMA_GCC_PCH_PREPROCESS)
            // HP/AIX:
            || (&slice[1..5] == b"line "))
        && (start == 0 || bytes[start - 1] == b'\n')
        {
            match process_preprocessor_line(
                input_file,
                cwd,
                included_files,
                config,
                time_of_compilation,
                bytes,
                start,
                hash_start,
                &mut digest,
                total_len,
                &mut normalized_include_paths,
                &fs_impl,
            )? {
                ControlFlow::Continue((s, h)) => {
                    start = s;
                    hash_start = h;
                }
                ControlFlow::Break((s, h, continue_preprocessor_cache_mode)) => {
                    if !continue_preprocessor_cache_mode {
                        return Ok(false);
                    }
                    start = s;
                    hash_start = h;
                    continue;
                }
            };
        } else if slice
            .strip_prefix(INCBIN_DIRECTIVE)
            .filter(|slice| {
                slice.starts_with(b"\"") || slice.starts_with(b" \"") || slice.starts_with(b" \\\"")
            })
            .is_some()
        {
            // An assembler .inc bin (without the space) statement, which could be
            // part of inline assembly, refers to an external file. If the file
            // changes, the hash should change as well, but finding out what file to
            // hash is too hard for sccache, so just bail out.
            debug!("Found potential unsupported .inc bin directive in source code");
            return Ok(false);
        } else if slice.starts_with(b"___________") && (start == 0 || bytes[start - 1] == b'\n') {
            // Unfortunately the distcc-pump wrapper outputs standard output lines:
            // __________Using distcc-pump from /usr/bin
            // __________Using # distcc servers in pump mode
            // __________Shutting down distcc-pump include server
            digest.update(&bytes[hash_start..start]);
            while start < total_len && slice[0] != b'\n' {
                start += 1;
                if start < total_len {
                    slice = &bytes[start..];
                }
            }
            slice = &bytes[start..];
            if slice[0] == b'\n' {
                start += 1;
            }
            hash_start = start;
            continue;
        } else {
            start += 1;
        }
    }
    digest.update(&bytes[hash_start..]);

    Ok(true)
}

/// What to do after handling a preprocessor number line.
/// The `Break` variant is `(start, hash_start, continue_preprocessor_cache_mode)`.
/// The `Continue` variant is `(start, hash_start)`.
type PreprocessedLineAction = ControlFlow<(usize, usize, bool), (usize, usize)>;

#[allow(clippy::too_many_arguments)]
fn process_preprocessor_line(
    input_file: &Path,
    cwd: &Path,
    included_files: &mut HashMap<PathBuf, String>,
    config: PreprocessorCacheModeConfig,
    time_of_compilation: std::time::SystemTime,
    bytes: &mut [u8],
    mut start: usize,
    mut hash_start: usize,
    digest: &mut Digest,
    total_len: usize,
    normalized_include_paths: &mut HashMap<Vec<u8>, Option<Vec<u8>>>,
    fs_impl: &impl PreprocessorFSAbstraction,
) -> Result<PreprocessedLineAction> {
    let mut slice = &bytes[start..];
    // Workarounds for preprocessor linemarker bugs in GCC version 6.
    if slice.get(2) == Some(&b'3') {
        if slice.starts_with(HASH_31_COMMAND_LINE_NEWLINE) {
            // Bogus extra line with #31, after the regular #1:
            // Ignore the whole line, and continue parsing.
            digest.update(&bytes[hash_start..start]);
            while start < hash_start && slice[0] != b'\n' {
                start += 1;
            }
            start += 1;
            hash_start = start;
            return Ok(ControlFlow::Break((start, hash_start, true)));
        } else if slice.starts_with(HASH_32_COMMAND_LINE_2_NEWLINE) {
            // Bogus wrong line with #32, instead of regular #1:
            // Replace the line number with the usual one.
            digest.update(&bytes[hash_start..start]);
            start += 1;
            bytes[start..=start + 2].copy_from_slice(b"# 1");
            hash_start = start;
            slice = &bytes[start..];
        }
    }
    while start < total_len && slice[0] != b'"' && slice[0] != b'\n' {
        start += 1;
        if start < total_len {
            slice = &bytes[start..];
        }
    }
    slice = &bytes[start..];
    if start < total_len && slice[0] == b'\n' {
        // a newline before the quotation mark -> no match
        return Ok(ControlFlow::Break((start, hash_start, true)));
    }
    start += 1;
    if start >= total_len {
        bail!("Failed to parse included file path");
    }
    // `start` points to the beginning of an include file path
    digest.update(&bytes[hash_start..start]);
    hash_start = start;
    slice = &bytes[start..];
    while start < total_len && slice[0] != b'"' {
        start += 1;
        if start < total_len {
            slice = &bytes[start..];
        }
    }
    if start == hash_start {
        // Skip empty file name.
        return Ok(ControlFlow::Break((start, hash_start, true)));
    }
    // Look for preprocessor flags, after the "filename".
    let mut system = false;
    let mut pointer = start + 1;
    while pointer < total_len && bytes[pointer] != b'\n' {
        if bytes[pointer] == b'3' {
            // System header.
            system = true;
        }
        pointer += 1;
    }

    // `hash_start` and `start` span the include file path.
    let include_path = &bytes[hash_start..start];
    // We need to normalize the path now since it's part of the
    // hash and since we need to deduplicate the include files.
    // We cache the results since they are often quite a bit repeated.
    let include_path: &[u8] = if let Some(opt) = normalized_include_paths.get(include_path) {
        match opt {
            Some(normalized) => normalized,
            None => include_path,
        }
    } else {
        let path_buf = decode_path(include_path)?;
        let normalized = normalize_path(&path_buf);
        if normalized == path_buf {
            // `None` is a marker that the normalization is the same
            normalized_include_paths.insert(include_path.to_owned(), None);
            include_path
        } else {
            let mut encoded = Vec::with_capacity(include_path.len());
            encode_path(&mut encoded, &normalized)?;
            normalized_include_paths.insert(include_path.to_owned(), Some(encoded));
            // No entry API on hashmaps, so we need to query again
            normalized_include_paths
                .get(include_path)
                .unwrap()
                .as_ref()
                .unwrap()
        }
    };

    if !remember_include_file(
        include_path,
        input_file,
        cwd,
        included_files,
        digest,
        system,
        config,
        time_of_compilation,
        fs_impl,
    )? {
        return Ok(ControlFlow::Break((start, hash_start, false)));
    };
    // Everything of interest between hash_start and start has been hashed now.
    hash_start = start;
    Ok(ControlFlow::Continue((start, hash_start)))
}

/// Copied from cargo.
///
/// Normalize a path, removing things like `.` and `..`.
///
/// CAUTION: This does not resolve symlinks (unlike
/// [`std::fs::canonicalize`]).
pub fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

/// Limited abstraction of `std::fs::Metadata`, allowing us to create fake
/// values during testing.
#[derive(Debug, Eq, PartialEq, Clone)]
struct PreprocessorFileMetadata {
    is_dir: bool,
    is_file: bool,
    modified: Option<Timestamp>,
    ctime_or_creation: Option<Timestamp>,
}

impl From<std::fs::Metadata> for PreprocessorFileMetadata {
    fn from(meta: std::fs::Metadata) -> Self {
        Self {
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            modified: meta.modified().ok().map(Into::into),
            ctime_or_creation: meta.ctime_or_creation().ok(),
        }
    }
}

/// An abstraction to filesystem access for use during the preprocessor
/// caching phase, to make testing easier.
///
/// This may help non-local preprocessor caching in the future, if it ends up
/// being viable.
trait PreprocessorFSAbstraction {
    fn metadata(&self, path: impl AsRef<Path>) -> io::Result<PreprocessorFileMetadata> {
        std::fs::metadata(path).map(Into::into)
    }

    fn open(&self, path: impl AsRef<Path>) -> io::Result<Box<dyn std::io::Read>> {
        Ok(Box::new(std::fs::File::open(path)?))
    }
}

/// Provides filesystem access with the expected standard library functions.
struct StandardFsAbstraction;

impl PreprocessorFSAbstraction for StandardFsAbstraction {}

// Returns false if the include file was "too new" (meaning modified during or
// after the start of the compilation) and therefore should disable
// the preprocessor cache mode, otherwise true.
#[allow(clippy::too_many_arguments)]
fn remember_include_file(
    mut path: &[u8],
    input_file: &Path,
    cwd: &Path,
    included_files: &mut HashMap<PathBuf, String>,
    digest: &mut Digest,
    system: bool,
    config: PreprocessorCacheModeConfig,
    time_of_compilation: std::time::SystemTime,
    fs_impl: &impl PreprocessorFSAbstraction,
) -> Result<bool> {
    // TODO if precompiled header.
    if path.len() >= 2 && path[0] == b'<' && path[path.len() - 1] == b'>' {
        // Typically <built-in> or <command-line>.
        digest.update(path);
        return Ok(true);
    }

    if system && config.skip_system_headers {
        // Don't remember this system header, only hash its path.
        digest.update(path);
        return Ok(true);
    }

    let original_path = path;
    // Canonicalize path for comparison; Clang uses ./header.h.
    #[cfg(windows)]
    {
        if path.starts_with(br".\") || path.starts_with(b"./") {
            path = &path[2..];
        }
    }
    #[cfg(not(windows))]
    {
        if path.starts_with(b"./") {
            path = &path[2..];
        }
    }
    let mut path = decode_path(path).context("failed to decode path")?;
    if path.is_relative() {
        path = cwd.join(path);
    }
    if path != cwd || config.hash_working_directory {
        digest.update(original_path);
    }

    if included_files.contains_key(&path) {
        // Already known include file
        return Ok(true);
    }

    if path == input_file {
        // Don't remember the input file.
        return Ok(true);
    }
    let meta = match fs_impl.metadata(&path) {
        Ok(meta) => meta,
        Err(e) => {
            debug!("Failed to stat include file {}: {}", path.display(), e);
            return Ok(false);
        }
    };
    if meta.is_dir {
        // Ignore directory, typically $PWD.
        return Ok(true);
    }
    if !meta.is_file {
        // Device, pipe, socket or other strange creature.
        debug!("Non-regular include file {}", path.display());
        return Ok(false);
    }

    // TODO add an option to ignore some header files?
    if include_is_too_new(&path, &meta, time_of_compilation) {
        return Ok(false);
    }

    // Let's hash the include file content.
    let file = match fs_impl.open(&path) {
        Ok(file) => file,
        Err(e) => {
            debug!("Failed to open header file {}: {}", path.display(), e);
            return Ok(false);
        }
    };

    let (file_digest, finder) = if config.ignore_time_macros {
        match Digest::reader_sync(file) {
            Ok(file_digest) => (file_digest, TimeMacroFinder::new()),
            Err(e) => {
                debug!("Failed to read header file {}: {}", path.display(), e);
                return Ok(false);
            }
        }
    } else {
        match Digest::reader_sync_time_macros(file) {
            Ok((file_digest, finder)) => (file_digest, finder),
            Err(e) => {
                debug!("Failed to read header file {}: {}", path.display(), e);
                return Ok(false);
            }
        }
    };

    if finder.found_time() {
        debug!("Found __TIME__ in header file {}", path.display());
        return Ok(false);
    }

    included_files.insert(path, file_digest);

    Ok(true)
}

/// Opt out of preprocessor cache mode because of a race condition.
///
/// The race condition consists of these events:
///
/// - the preprocessor is run
/// - an include file is modified by someone
/// - the new include file is hashed by sccache
/// - the real compiler is run on the preprocessor's output, which contains
///   data from the old header file
/// - the wrong object file is stored in the cache.
fn include_is_too_new(
    path: &Path,
    meta: &PreprocessorFileMetadata,
    time_of_compilation: std::time::SystemTime,
) -> bool {
    // The comparison using >= is intentional, due to a possible race between
    // starting compilation and writing the include file.
    if let Some(mtime) = meta.modified {
        if mtime >= time_of_compilation.into() {
            debug!("Include file {} is too new", path.display());
            return true;
        }
    }

    // The same >= logic as above applies to the change time of the file.
    if let Some(ctime) = meta.ctime_or_creation {
        if ctime >= time_of_compilation.into() {
            debug!("Include file {} is too new", path.display());
            return true;
        }
    }

    false
}

impl<T: CommandCreatorSync, I: CCompilerImpl> Compilation<T> for CCompilation<I> {
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        rewrite_includes_only: bool,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )> {
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
            extra_dist_files: parsed_args.extra_dist_files,
            extra_hash_files: parsed_args.extra_hash_files,
        });
        let toolchain_packager = Box::new(CToolchainPackager {
            executable,
            kind: compiler.kind(),
        });
        let outputs_rewriter = Box::new(NoopOutputsRewriter);
        Ok((inputs_packager, toolchain_packager, outputs_rewriter))
    }

    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = FileObjectSource> + 'a> {
        Box::new(
            self.parsed_args
                .outputs
                .iter()
                .map(|(k, output)| FileObjectSource {
                    key: k.to_string(),
                    path: output.path.clone(),
                    optional: output.optional,
                }),
        )
    }
}

#[cfg(feature = "dist-client")]
struct CInputsPackager {
    input_path: PathBuf,
    path_transformer: dist::PathTransformer,
    preprocessed_input: Vec<u8>,
    extra_dist_files: Vec<PathBuf>,
    extra_hash_files: Vec<PathBuf>,
}

#[cfg(feature = "dist-client")]
impl pkg::InputsPackager for CInputsPackager {
    fn write_inputs(self: Box<Self>, wtr: &mut dyn io::Write) -> Result<dist::PathTransformer> {
        let CInputsPackager {
            input_path,
            mut path_transformer,
            preprocessed_input,
            extra_dist_files,
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

        for input_path in extra_hash_files.iter().chain(extra_dist_files.iter()) {
            let input_path = pkg::simplify_path(input_path)?;

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
                .arg(format!("-print-{}-name={}", kind, name))
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

            CCompilerKind::Gcc => {
                // Various external programs / files which may be needed by gcc
                add_named_prog(&mut package_builder, "cc1")?;
                add_named_prog(&mut package_builder, "cc1plus")?;
                add_named_file(&mut package_builder, "specs")?;
                add_named_file(&mut package_builder, "liblto_plugin.so")?;
            }

            CCompilerKind::Cicc => {}

            CCompilerKind::Ptxas => {}

            CCompilerKind::Nvcc => {
                // Various programs called by the nvcc front end.
                // presumes the underlying host compiler is consistent
                add_named_file(&mut package_builder, "cudafe++")?;
                add_named_file(&mut package_builder, "fatbinary")?;
                add_named_prog(&mut package_builder, "nvlink")?;
                add_named_prog(&mut package_builder, "ptxas")?;
            }

            CCompilerKind::Nvhpc => {
                // Various programs called by the nvc nvc++ front end.
                add_named_file(&mut package_builder, "cpp1")?;
                add_named_file(&mut package_builder, "cpp2")?;
                add_named_file(&mut package_builder, "opt")?;
                add_named_prog(&mut package_builder, "llc")?;
                add_named_prog(&mut package_builder, "acclnk")?;
            }

            _ => unreachable!(),
        }

        // Bundle into a compressed tarfile.
        package_builder.into_compressed_tar(f)
    }
}

/// The cache is versioned by the inputs to `hash_key`.
pub const CACHE_VERSION: &[u8] = b"11";

/// Environment variables that are factored into the cache key.
static CACHED_ENV_VARS: Lazy<HashSet<&'static OsStr>> = Lazy::new(|| {
    [
        // SCCACHE_C_CUSTOM_CACHE_BUSTER has no particular meaning behind it,
        // serving as a way for the user to factor custom data into the hash.
        // One can set it to different values for different invocations
        // to prevent cache reuse between them.
        "SCCACHE_C_CUSTOM_CACHE_BUSTER",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "TVOS_DEPLOYMENT_TARGET",
        "WATCHOS_DEPLOYMENT_TARGET",
        "SDKROOT",
        "CCC_OVERRIDE_OPTIONS",
    ]
    .iter()
    .map(OsStr::new)
    .collect()
});

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

    for (var, val) in env_vars.iter() {
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
    use std::{collections::VecDeque, sync::Mutex};

    use super::*;

    #[test]
    fn test_same_content() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_eq!(
            hash_key("abcd", Language::C, &args, &[], &[], PREPROCESSED, false),
            hash_key("abcd", Language::C, &args, &[], &[], PREPROCESSED, false)
        );
    }

    #[test]
    fn test_plusplus_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key("abcd", Language::C, &args, &[], &[], PREPROCESSED, false),
            hash_key("abcd", Language::C, &args, &[], &[], PREPROCESSED, true)
        );
    }

    #[test]
    fn test_header_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key("abcd", Language::C, &args, &[], &[], PREPROCESSED, false),
            hash_key(
                "abcd",
                Language::CHeader,
                &args,
                &[],
                &[],
                PREPROCESSED,
                false
            )
        );
    }

    #[test]
    fn test_plusplus_header_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key("abcd", Language::Cxx, &args, &[], &[], PREPROCESSED, true),
            hash_key(
                "abcd",
                Language::CxxHeader,
                &args,
                &[],
                &[],
                PREPROCESSED,
                true
            )
        );
    }

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let args = ovec!["a", "b", "c"];
        const PREPROCESSED: &[u8] = b"hello world";
        assert_neq!(
            hash_key("abcd", Language::C, &args, &[], &[], PREPROCESSED, false),
            hash_key("wxyz", Language::C, &args, &[], &[], PREPROCESSED, false)
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
            hash_key(digest, Language::C, &abc, &[], &[], PREPROCESSED, false),
            hash_key(digest, Language::C, &xyz, &[], &[], PREPROCESSED, false)
        );

        assert_neq!(
            hash_key(digest, Language::C, &abc, &[], &[], PREPROCESSED, false),
            hash_key(digest, Language::C, &ab, &[], &[], PREPROCESSED, false)
        );

        assert_neq!(
            hash_key(digest, Language::C, &abc, &[], &[], PREPROCESSED, false),
            hash_key(digest, Language::C, &a, &[], &[], PREPROCESSED, false)
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
            let h1 = hash_key(digest, Language::C, &args, &[], &[], PREPROCESSED, false);
            let vars = vec![(OsString::from(var), OsString::from("something"))];
            let h2 = hash_key(digest, Language::C, &args, &[], &vars, PREPROCESSED, false);
            let vars = vec![(OsString::from(var), OsString::from("something else"))];
            let h3 = hash_key(digest, Language::C, &args, &[], &vars, PREPROCESSED, false);
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
                PREPROCESSED,
                false
            ),
            hash_key(digest, Language::C, &args, &[], &[], PREPROCESSED, false)
        );
    }

    #[test]
    fn test_language_from_file_name() {
        fn t(extension: &str, expected: Language) {
            let path_str = format!("input.{}", extension);
            let path = Path::new(&path_str);
            let actual = Language::from_file_name(path);
            assert_eq!(actual, Some(expected));
        }

        t("c", Language::C);

        t("C", Language::Cxx);
        t("cc", Language::Cxx);
        t("cp", Language::Cxx);
        t("cpp", Language::Cxx);
        t("CPP", Language::Cxx);
        t("cxx", Language::Cxx);
        t("c++", Language::Cxx);

        t("h", Language::GenericHeader);

        t("hh", Language::CxxHeader);
        t("H", Language::CxxHeader);
        t("hp", Language::CxxHeader);
        t("hxx", Language::CxxHeader);
        t("hpp", Language::CxxHeader);
        t("HPP", Language::CxxHeader);
        t("h++", Language::CxxHeader);
        t("tcc", Language::CxxHeader);

        t("m", Language::ObjectiveC);

        t("M", Language::ObjectiveCxx);
        t("mm", Language::ObjectiveCxx);

        t("cu", Language::Cuda);
        t("hip", Language::Hip);
    }

    #[test]
    fn test_language_from_file_name_none() {
        fn t(extension: &str) {
            let path_str = format!("input.{}", extension);
            let path = Path::new(&path_str);
            let actual = Language::from_file_name(path);
            let expected = None;
            assert_eq!(actual, expected);
        }

        // gcc parses file-extensions as case-sensitive
        t("Cp");
        t("Cpp");
        t("Hp");
        t("Hpp");
        t("Mm");
        t("Cu");
    }

    #[test]
    fn test_process_preprocessed_file() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();
        let input_file = Path::new("tests/test.c");
        let path = Path::new(file!())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        // This should be portable since the only headers present in this
        // output are system headers, which aren't interacted with
        // on the filesystem if configured.
        let path = path.join("tests/test.c.gcc-13.2.0-preproc");
        let mut bytes = std::fs::read(path).unwrap();
        let original_bytes = bytes.clone();
        let mut include_files = HashMap::new();

        let config = PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: true,
            skip_system_headers: true,
            ..Default::default()
        };
        let success = process_preprocessed_file(
            input_file,
            Path::new(""),
            &mut bytes,
            &mut include_files,
            config,
            std::time::SystemTime::now(),
            StandardFsAbstraction,
        )
        .unwrap();
        assert_eq!(&bytes, &original_bytes);
        assert!(success);
        assert_eq!(include_files.len(), 0);
    }

    /// A filesystem interface that only panics to test that we don't access it.
    struct PanicFs;

    impl PreprocessorFSAbstraction for PanicFs {
        fn metadata(&self, path: impl AsRef<Path>) -> io::Result<PreprocessorFileMetadata> {
            panic!("called metadata at {}", path.as_ref().display());
        }

        fn open(&self, path: impl AsRef<Path>) -> io::Result<Box<dyn std::io::Read>> {
            panic!("called open at {}", path.as_ref().display());
        }
    }

    /// A filesystem interface that gives back expected values.
    struct TestFs {
        metadata_results: Mutex<VecDeque<(PathBuf, PreprocessorFileMetadata)>>,
        open_results: Mutex<VecDeque<(PathBuf, Box<dyn std::io::Read>)>>,
    }

    impl PreprocessorFSAbstraction for TestFs {
        fn metadata(&self, path: impl AsRef<Path>) -> io::Result<PreprocessorFileMetadata> {
            let (expected_path, meta) = self
                .metadata_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("not enough 'metadata' results");
            assert_eq!(expected_path, path.as_ref(), "{}", path.as_ref().display());
            Ok(meta)
        }

        fn open(&self, path: impl AsRef<Path>) -> io::Result<Box<dyn std::io::Read>> {
            let (expected_path, impls_read) = self
                .open_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("not enough 'open' results");
            assert_eq!(expected_path, path.as_ref(), "{}", path.as_ref().display());
            Ok(impls_read)
        }
    }

    // Short-circuit the parameters we don't need to change during tests
    fn do_single_preprocessor_line_call(
        line: &[u8],
        include_files: &mut HashMap<PathBuf, String>,
        fs_impl: &impl PreprocessorFSAbstraction,
        skip_system_headers: bool,
    ) -> PreprocessedLineAction {
        let input_file = Path::new("tests/test.c");

        let config = PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: true,
            skip_system_headers,
            ..Default::default()
        };

        let mut bytes = line.to_vec();
        let total_len = bytes.len();
        process_preprocessor_line(
            input_file,
            Path::new(""),
            include_files,
            config,
            std::time::SystemTime::now(),
            &mut bytes,
            0,
            0,
            &mut Digest::new(),
            total_len,
            &mut HashMap::new(),
            fs_impl,
        )
        .unwrap()
    }

    /// Test cases where we don't access the filesystem
    #[test]
    fn test_process_preprocessor_line_simple() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        let mut include_files = HashMap::new();
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "tests/test.c""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((20, 20)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "<built-in>""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((18, 18)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "<command-line>""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((22, 22)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 0 "<command-line>" 2"#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((22, 22)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 1 "tests/test.c""#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((20, 20)),
        );
        assert_eq!(include_files.len(), 0);

        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 1 "/usr/include/stdc-predef.h" 1 3 4"#,
                &mut include_files,
                &PanicFs,
                true,
            ),
            ControlFlow::Continue((34, 34)),
        );
        assert_eq!(include_files.len(), 0);
    }

    /// Test cases where we test our tests...
    #[test]
    fn test_test_helpers() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        // Test PanicFs
        let res = std::panic::catch_unwind(|| {
            let mut include_files = HashMap::new();
            assert_eq!(
                do_single_preprocessor_line_call(
                    br#"// # 1 "/usr/include/stdc-predef.h" 1 3 4"#,
                    &mut include_files,
                    &PanicFs,
                    false,
                ),
                ControlFlow::Continue((34, 34)),
            );
        });
        assert_eq!(
            res.unwrap_err().downcast_ref::<String>().unwrap(),
            "called metadata at /usr/include/stdc-predef.h"
        );

        // Test TestFs's safeguard
        let res = std::panic::catch_unwind(|| {
            let mut include_files = HashMap::new();
            let fs_impl = TestFs {
                metadata_results: Mutex::new(VecDeque::new()),
                open_results: Mutex::new(VecDeque::new()),
            };
            assert_eq!(
                do_single_preprocessor_line_call(
                    br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                    &mut include_files,
                    &fs_impl,
                    false,
                ),
                ControlFlow::Continue((34, 34)),
            );
        });
        assert_eq!(
            res.unwrap_err().downcast_ref::<String>().unwrap(),
            "not enough 'metadata' results"
        );
    }

    /// Test cases where we test filesystem access
    #[test]
    fn test_process_preprocessor_line_fs_access() {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        // Test "too new" include file
        let mut include_files = HashMap::new();
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    PreprocessorFileMetadata {
                        is_dir: false,
                        is_file: true,
                        modified: Some(Timestamp::new(i64::MAX - 1, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(VecDeque::new()),
        };
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                &mut include_files,
                &fs_impl,
                false,
            ),
            // preprocessor cache mode is disabled
            ControlFlow::Break((63, 9, false)),
        );

        // Test invalid include file is actually a dir
        let mut include_files = HashMap::new();
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    PreprocessorFileMetadata {
                        is_dir: true,
                        is_file: false,
                        modified: Some(Timestamp::new(12341234, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(VecDeque::new()),
        };
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                &mut include_files,
                &fs_impl,
                false,
            ),
            // preprocessor cache mode is *not* disabled,
            ControlFlow::Continue((63, 63)),
        );
        assert_eq!(include_files.len(), 0);

        // Test correct include file
        let mut include_files = HashMap::new();
        let fs_impl = TestFs {
            metadata_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    PreprocessorFileMetadata {
                        is_dir: false,
                        is_file: true,
                        modified: Some(Timestamp::new(12341234, 0)),
                        ctime_or_creation: None,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            open_results: Mutex::new(
                [(
                    PathBuf::from("/usr/include/x86_64-linux-gnu/bits/libc-header-start.h"),
                    Box::new(&b"contents"[..]) as Box<dyn std::io::Read>,
                )]
                .into_iter()
                .collect(),
            ),
        };
        assert_eq!(
            do_single_preprocessor_line_call(
                br#"// # 33 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 3 4"#,
                &mut include_files,
                &fs_impl,
                false,
            ),
            ControlFlow::Continue((63, 63)),
        );
        assert_eq!(include_files.len(), 1);
        assert_eq!(
            include_files
                .get(Path::new(
                    "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h",
                ))
                .unwrap(),
            // hash of `b"contents"`
            "a93900c371d997927c5bc568ea538bed59ae5c960021dcfe7b0b369da5267528",
        );
    }
}
