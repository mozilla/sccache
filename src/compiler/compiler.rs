// Copyright 2016 Mozilla Foundation
// SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::cache::{Cache, CacheWrite, DecompressionFailure, FileObjectSource, Storage};
use crate::compiler::args::*;
use crate::compiler::c::{CCompiler, CCompilerKind};
use crate::compiler::cicc::Cicc;
use crate::compiler::clang::Clang;
use crate::compiler::diab::Diab;
use crate::compiler::gcc::Gcc;
use crate::compiler::msvc;
use crate::compiler::msvc::Msvc;
use crate::compiler::nvcc::Nvcc;
use crate::compiler::nvcc::NvccHostCompiler;
use crate::compiler::nvhpc::Nvhpc;
use crate::compiler::ptxas::Ptxas;
use crate::compiler::rust::{Rust, RustupProxy};
use crate::compiler::tasking_vx::TaskingVX;
#[cfg(feature = "dist-client")]
use crate::dist::pkg;
#[cfg(feature = "dist-client")]
use crate::lru_disk_cache;
use crate::mock_command::{exit_status, CommandChild, CommandCreatorSync, RunCommand};
use crate::server;
use crate::util::{fmt_duration_as_secs, run_input_output};
use crate::{counted_array, dist};
use async_trait::async_trait;
use filetime::FileTime;
use fs::File;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::future::Future;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{self, Stdio};
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use crate::errors::*;

/// Can dylibs (shared libraries or proc macros) be distributed on this platform?
#[cfg(all(
    feature = "dist-client",
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        target_os = "freebsd"
    )
))]
pub const CAN_DIST_DYLIBS: bool = true;
#[cfg(all(
    feature = "dist-client",
    not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        target_os = "freebsd"
    ))
))]
pub const CAN_DIST_DYLIBS: bool = false;

#[async_trait]
pub trait CompileCommand<T>: Send + Sync + 'static
where
    T: CommandCreatorSync,
{
    async fn execute(
        &self,
        service: &server::SccacheService<T>,
        creator: &T,
    ) -> Result<process::Output>;

    fn get_executable(&self) -> PathBuf;
    fn get_arguments(&self) -> Vec<OsString>;
    fn get_env_vars(&self) -> Vec<(OsString, OsString)>;
    fn get_cwd(&self) -> PathBuf;
}

#[derive(Debug)]
pub struct CCompileCommand<I>
where
    I: CompileCommandImpl,
{
    cmd: I,
}

impl<I> CCompileCommand<I>
where
    I: CompileCommandImpl,
{
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>(cmd: I) -> Box<dyn CompileCommand<T>>
    where
        T: CommandCreatorSync,
    {
        Box::new(CCompileCommand { cmd }) as Box<dyn CompileCommand<T>>
    }
}

#[async_trait]
impl<T, I> CompileCommand<T> for CCompileCommand<I>
where
    T: CommandCreatorSync,
    I: CompileCommandImpl,
{
    fn get_executable(&self) -> PathBuf {
        self.cmd.get_executable()
    }
    fn get_arguments(&self) -> Vec<OsString> {
        self.cmd.get_arguments()
    }
    fn get_env_vars(&self) -> Vec<(OsString, OsString)> {
        self.cmd.get_env_vars()
    }
    fn get_cwd(&self) -> PathBuf {
        self.cmd.get_cwd()
    }

    async fn execute(
        &self,
        service: &server::SccacheService<T>,
        creator: &T,
    ) -> Result<process::Output> {
        self.cmd.execute(service, creator).await
    }
}

#[async_trait]
pub trait CompileCommandImpl: Send + Sync + 'static {
    fn get_executable(&self) -> PathBuf;
    fn get_arguments(&self) -> Vec<OsString>;
    fn get_env_vars(&self) -> Vec<(OsString, OsString)>;
    fn get_cwd(&self) -> PathBuf;

    async fn execute<T>(
        &self,
        service: &server::SccacheService<T>,
        creator: &T,
    ) -> Result<process::Output>
    where
        T: CommandCreatorSync;
}

#[derive(Debug)]
pub struct SingleCompileCommand {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub env_vars: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
}

#[async_trait]
impl CompileCommandImpl for SingleCompileCommand {
    fn get_executable(&self) -> PathBuf {
        self.executable.clone()
    }
    fn get_arguments(&self) -> Vec<OsString> {
        self.arguments.clone()
    }
    fn get_env_vars(&self) -> Vec<(OsString, OsString)> {
        self.env_vars.clone()
    }
    fn get_cwd(&self) -> PathBuf {
        self.cwd.clone()
    }

    async fn execute<T>(
        &self,
        _: &server::SccacheService<T>,
        creator: &T,
    ) -> Result<process::Output>
    where
        T: CommandCreatorSync,
    {
        let SingleCompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = self;
        let mut cmd = creator.clone().new_command_sync(executable);
        cmd.args(arguments)
            .env_clear()
            .envs(env_vars.to_vec())
            .current_dir(cwd);
        run_input_output(cmd, None).await
    }
}

/// Supported compilers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CompilerKind {
    /// A C compiler.
    C(CCompilerKind),
    /// A Rust compiler.
    Rust,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Language {
    C,
    Cxx,
    GenericHeader,
    CHeader,
    CxxHeader,
    ObjectiveC,
    ObjectiveCxx,
    ObjectiveCxxHeader,
    Cuda,
    Ptx,
    Cubin,
    Rust,
    Hip,
}

impl Language {
    pub fn from_file_name(file: &Path) -> Option<Self> {
        match file.extension().and_then(|e| e.to_str()) {
            // gcc: https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html
            Some("c") => Some(Language::C),
            // Could be C or C++
            Some("h") => Some(Language::GenericHeader),
            // TODO i
            Some("C") | Some("cc") | Some("cp") | Some("cpp") | Some("CPP") | Some("cxx")
            | Some("c++") => Some(Language::Cxx),
            // TODO ii
            Some("H") | Some("hh") | Some("hp") | Some("hpp") | Some("HPP") | Some("hxx")
            | Some("h++") | Some("tcc") => Some(Language::CxxHeader),
            Some("m") => Some(Language::ObjectiveC),
            // TODO mi
            Some("M") | Some("mm") => Some(Language::ObjectiveCxx),
            // TODO mii
            Some("cu") => Some(Language::Cuda),
            Some("ptx") => Some(Language::Ptx),
            Some("cubin") => Some(Language::Cubin),
            // TODO cy
            Some("rs") => Some(Language::Rust),
            Some("hip") => Some(Language::Hip),
            e => {
                trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
                None
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::C => "c",
            Language::CHeader => "cHeader",
            Language::Cxx => "c++",
            Language::CxxHeader => "c++Header",
            Language::GenericHeader => "c/c++",
            Language::ObjectiveC => "objc",
            Language::ObjectiveCxx | Language::ObjectiveCxxHeader => "objc++",
            Language::Cuda => "cuda",
            Language::Ptx => "ptx",
            Language::Cubin => "cubin",
            Language::Rust => "rust",
            Language::Hip => "hip",
        }
    }
}

impl CompilerKind {
    pub fn lang_kind(&self, lang: &Language) -> String {
        match lang {
            Language::C
            | Language::CHeader
            | Language::Cxx
            | Language::CxxHeader
            | Language::GenericHeader
            | Language::ObjectiveC
            | Language::ObjectiveCxx
            | Language::ObjectiveCxxHeader => "C/C++",
            Language::Cuda => "CUDA",
            Language::Ptx => "PTX",
            Language::Cubin => "CUBIN",
            Language::Rust => "Rust",
            Language::Hip => "HIP",
        }
        .to_string()
    }
    pub fn lang_comp_kind(&self, lang: &Language) -> String {
        let textual_lang = lang.as_str().to_owned();
        match self {
            CompilerKind::C(CCompilerKind::Clang) => textual_lang + " [clang]",
            CompilerKind::C(CCompilerKind::Diab) => textual_lang + " [diab]",
            CompilerKind::C(CCompilerKind::Gcc) => textual_lang + " [gcc]",
            CompilerKind::C(CCompilerKind::Msvc) => textual_lang + " [msvc]",
            CompilerKind::C(CCompilerKind::Nvcc) => textual_lang + " [nvcc]",
            CompilerKind::C(CCompilerKind::Cicc) => textual_lang + " [cicc]",
            CompilerKind::C(CCompilerKind::Ptxas) => textual_lang + " [ptxas]",
            CompilerKind::C(CCompilerKind::Nvhpc) => textual_lang + " [nvhpc]",
            CompilerKind::C(CCompilerKind::TaskingVX) => textual_lang + " [taskingvx]",
            CompilerKind::Rust => textual_lang,
        }
    }
}

#[cfg(feature = "dist-client")]
pub type DistPackagers = (
    Box<dyn pkg::InputsPackager>,
    Box<dyn pkg::ToolchainPackager>,
    Box<dyn OutputsRewriter>,
);

enum CacheLookupResult {
    Success(CompileResult, process::Output),
    Miss(MissType),
}

/// An interface to a compiler for argument parsing.
pub trait Compiler<T>: Send + Sync + 'static
where
    T: CommandCreatorSync,
{
    /// Return the kind of compiler.
    fn kind(&self) -> CompilerKind;
    /// Retrieve a packager
    #[cfg(feature = "dist-client")]
    fn get_toolchain_packager(&self) -> Box<dyn pkg::ToolchainPackager>;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<Box<dyn CompilerHasher<T> + 'static>>;
    fn box_clone(&self) -> Box<dyn Compiler<T>>;
}

impl<T: CommandCreatorSync> Clone for Box<dyn Compiler<T>> {
    fn clone(&self) -> Box<dyn Compiler<T>> {
        self.box_clone()
    }
}

pub trait CompilerProxy<T>: Send + Sync + 'static
where
    T: CommandCreatorSync + Sized,
{
    /// Maps the executable to be used in `cwd` to the true, proxied compiler.
    ///
    /// Returns the absolute path to the true compiler and the timestamp of
    /// timestamp of the true compiler. Iff the resolution fails,
    /// the returned future resolves to an error with more information.
    fn resolve_proxied_executable(
        &self,
        creator: T,
        cwd: PathBuf,
        env_vars: &[(OsString, OsString)],
    ) -> Pin<Box<dyn Future<Output = Result<(PathBuf, FileTime)>> + Send + 'static>>;

    /// Create a clone of `Self` and puts it in a `Box`
    fn box_clone(&self) -> Box<dyn CompilerProxy<T>>;
}

impl<T: CommandCreatorSync> Clone for Box<dyn CompilerProxy<T>> {
    fn clone(&self) -> Box<dyn CompilerProxy<T>> {
        self.box_clone()
    }
}

/// An interface to a compiler for hash key generation, the result of
/// argument parsing.
#[async_trait]
pub trait CompilerHasher<T>: fmt::Debug + Send + 'static
where
    T: CommandCreatorSync,
{
    /// Given information about a compiler command, generate a hash key
    /// that can be used for cache lookups, as well as any additional
    /// information that can be reused for compilation if necessary.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<HashResult<T>>;

    /// Return the state of any `--color` option passed to the compiler.
    fn color_mode(&self) -> ColorMode;

    /// Look up a cached compile result in `storage`. If not found, run the
    /// compile and store the result.
    #[allow(clippy::too_many_arguments)]
    async fn get_cached_or_compile(
        self: Box<Self>,
        service: &server::SccacheService<T>,
        dist_client: Option<Arc<dyn dist::Client>>,
        creator: T,
        storage: Arc<dyn Storage>,
        arguments: Vec<OsString>,
        cwd: PathBuf,
        env_vars: Vec<(OsString, OsString)>,
        cache_control: CacheControl,
        pool: tokio::runtime::Handle,
    ) -> Result<(CompileResult, process::Output)> {
        let out_pretty = self.output_pretty().into_owned();
        debug!("[{}]: get_cached_or_compile: {:?}", out_pretty, arguments);
        let start = Instant::now();
        let may_dist = dist_client.is_some();
        let rewrite_includes_only = match dist_client {
            Some(ref client) => client.rewrite_includes_only(),
            _ => false,
        };
        let result = self
            .generate_hash_key(
                &creator,
                cwd.clone(),
                env_vars,
                may_dist,
                &pool,
                rewrite_includes_only,
                storage.clone(),
                cache_control,
            )
            .await;
        debug!(
            "[{}]: generate_hash_key took {}",
            out_pretty,
            fmt_duration_as_secs(&start.elapsed())
        );
        let (key, compilation, weak_toolchain_key) = match result {
            Err(e) => {
                return match e.downcast::<ProcessError>() {
                    Ok(ProcessError(output)) => Ok((CompileResult::Error, output)),
                    Err(e) => Err(e),
                };
            }
            Ok(HashResult {
                key,
                compilation,
                weak_toolchain_key,
            }) => (key, compilation, weak_toolchain_key),
        };
        debug!("[{}]: Hash key: {}", out_pretty, key);
        // If `ForceRecache` is enabled, we won't check the cache.
        let start = Instant::now();
        let cache_status = async {
            if cache_control == CacheControl::ForceNoCache {
                Ok(Cache::None)
            } else if cache_control == CacheControl::ForceRecache {
                Ok(Cache::Recache)
            } else {
                storage.get(&key).await
            }
        };

        // Set a maximum time limit for the cache to respond before we forge
        // ahead ourselves with a compilation.
        let timeout = Duration::new(60, 0);
        let cache_status = async {
            let res = tokio::time::timeout(timeout, cache_status).await;
            let duration = start.elapsed();
            (res, duration)
        };

        // Check the result of the cache lookup.
        let outputs = compilation
            .outputs()
            .map(|output| FileObjectSource {
                path: cwd.join(output.path),
                ..output
            })
            .collect::<Vec<_>>();

        let lookup = match cache_status.await {
            (Ok(Ok(Cache::Hit(mut entry))), duration) => {
                debug!(
                    "[{}]: Cache hit in {}",
                    out_pretty,
                    fmt_duration_as_secs(&duration)
                );
                let stdout = entry.get_stdout();
                let stderr = entry.get_stderr();
                let output = process::Output {
                    status: exit_status(0),
                    stdout,
                    stderr,
                };
                let hit = CompileResult::CacheHit(duration);
                match entry.extract_objects(outputs.clone(), &pool).await {
                    Ok(()) => Ok(CacheLookupResult::Success(hit, output)),
                    Err(e) => {
                        if e.downcast_ref::<DecompressionFailure>().is_some() {
                            debug!("[{}]: Failed to decompress object", out_pretty);
                            Ok(CacheLookupResult::Miss(MissType::CacheReadError))
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            (Ok(Ok(Cache::Miss)), duration) => {
                debug!(
                    "[{}]: Cache miss in {}",
                    out_pretty,
                    fmt_duration_as_secs(&duration)
                );
                Ok(CacheLookupResult::Miss(MissType::Normal))
            }
            (Ok(Ok(Cache::None)), duration) => {
                debug!(
                    "[{}]: Cache none in {}",
                    out_pretty,
                    fmt_duration_as_secs(&duration)
                );
                Ok(CacheLookupResult::Miss(MissType::ForcedNoCache))
            }
            (Ok(Ok(Cache::Recache)), duration) => {
                debug!(
                    "[{}]: Cache recache in {}",
                    out_pretty,
                    fmt_duration_as_secs(&duration)
                );
                Ok(CacheLookupResult::Miss(MissType::ForcedRecache))
            }
            (Ok(Err(err)), duration) => {
                error!(
                    "[{}]: Cache read error: {:?} in {}",
                    out_pretty,
                    err,
                    fmt_duration_as_secs(&duration)
                );
                Ok(CacheLookupResult::Miss(MissType::CacheReadError))
            }
            (Err(_), duration) => {
                debug!(
                    "[{}]: Cache timed out {}",
                    out_pretty,
                    fmt_duration_as_secs(&duration)
                );
                Ok(CacheLookupResult::Miss(MissType::TimedOut))
            }
        }?;

        match lookup {
            CacheLookupResult::Success(compile_result, output) => {
                Ok::<_, Error>((compile_result, output))
            }
            CacheLookupResult::Miss(miss_type) => {
                // Cache miss, so compile it.
                let start = Instant::now();

                let (cacheable, dist_type, compiler_result) = dist_or_local_compile(
                    service,
                    dist_client,
                    creator,
                    cwd,
                    compilation,
                    weak_toolchain_key,
                    out_pretty.clone(),
                )
                .await?;
                let duration_compilation = start.elapsed();
                if !compiler_result.status.success() {
                    debug!(
                        "[{}]: Compiled in {}, but failed, not storing in cache",
                        out_pretty,
                        fmt_duration_as_secs(&duration_compilation)
                    );
                    return Ok((
                        CompileResult::CompileFailed(dist_type, duration_compilation),
                        compiler_result,
                    ));
                }
                if miss_type == MissType::ForcedNoCache {
                    // Do not cache
                    debug!(
                        "[{}]: Compiled in {}, but not caching",
                        out_pretty,
                        fmt_duration_as_secs(&duration_compilation)
                    );
                    return Ok((
                        CompileResult::NotCached(dist_type, duration_compilation),
                        compiler_result,
                    ));
                }
                if cacheable != Cacheable::Yes {
                    // Not cacheable
                    debug!(
                        "[{}]: Compiled in {}, but not cacheable",
                        out_pretty,
                        fmt_duration_as_secs(&duration_compilation)
                    );
                    return Ok((
                        CompileResult::NotCacheable(dist_type, duration_compilation),
                        compiler_result,
                    ));
                }
                debug!(
                    "[{}]: Compiled in {}, storing in cache",
                    out_pretty,
                    fmt_duration_as_secs(&duration_compilation)
                );
                let start_create_artifact = Instant::now();
                let mut entry = CacheWrite::from_objects(outputs, &pool)
                    .await
                    .context("failed to zip up compiler outputs")?;

                entry.put_stdout(&compiler_result.stdout)?;
                entry.put_stderr(&compiler_result.stderr)?;
                debug!(
                    "[{}]: Created cache artifact in {}",
                    out_pretty,
                    fmt_duration_as_secs(&start_create_artifact.elapsed())
                );

                let out_pretty2 = out_pretty.clone();
                // Try to finish storing the newly-written cache
                // entry. We'll get the result back elsewhere.
                let future = async move {
                    let start = Instant::now();
                    match storage.put(&key, entry).await {
                        Ok(_) => {
                            debug!("[{}]: Stored in cache successfully!", out_pretty2);
                            Ok(CacheWriteInfo {
                                object_file_pretty: out_pretty2,
                                duration: start.elapsed(),
                            })
                        }
                        Err(e) => Err(e),
                    }
                };
                let future = Box::pin(future);
                Ok((
                    CompileResult::CacheMiss(miss_type, dist_type, duration_compilation, future),
                    compiler_result,
                ))
            }
        }
        .with_context(|| format!("failed to store `{}` to cache", out_pretty))
    }

    /// A descriptive string about the file that we're going to be producing.
    ///
    /// This is primarily intended for debug logging and such, not for actual
    /// artifact generation.
    fn output_pretty(&self) -> Cow<'_, str>;

    fn box_clone(&self) -> Box<dyn CompilerHasher<T>>;

    fn language(&self) -> Language;
}

#[cfg(not(feature = "dist-client"))]
async fn dist_or_local_compile<T>(
    service: &server::SccacheService<T>,
    _dist_client: Option<Arc<dyn dist::Client>>,
    creator: T,
    _cwd: PathBuf,
    compilation: Box<dyn Compilation<T>>,
    _weak_toolchain_key: String,
    out_pretty: String,
) -> Result<(Cacheable, DistType, process::Output)>
where
    T: CommandCreatorSync,
{
    let mut path_transformer = dist::PathTransformer::new();
    let (compile_cmd, _dist_compile_cmd, cacheable) = compilation
        .generate_compile_commands(&mut path_transformer, true)
        .context("Failed to generate compile commands")?;

    debug!("[{}]: Compiling locally", out_pretty);
    compile_cmd
        .execute(&service, &creator)
        .await
        .map(move |o| (cacheable, DistType::NoDist, o))
}

#[cfg(feature = "dist-client")]
async fn dist_or_local_compile<T>(
    service: &server::SccacheService<T>,
    dist_client: Option<Arc<dyn dist::Client>>,
    creator: T,
    cwd: PathBuf,
    compilation: Box<dyn Compilation<T>>,
    weak_toolchain_key: String,
    out_pretty: String,
) -> Result<(Cacheable, DistType, process::Output)>
where
    T: CommandCreatorSync,
{
    use std::io;

    let rewrite_includes_only = match dist_client {
        Some(ref client) => client.rewrite_includes_only(),
        _ => false,
    };
    let mut path_transformer = dist::PathTransformer::new();
    let (compile_cmd, dist_compile_cmd, cacheable) = compilation
        .generate_compile_commands(&mut path_transformer, rewrite_includes_only)
        .context("Failed to generate compile commands")?;

    let dist_client = match dist_compile_cmd.clone().and(dist_client) {
        Some(dc) => dc,
        None => {
            debug!("[{}]: Compiling locally", out_pretty);
            return compile_cmd
                .execute(service, &creator)
                .await
                .map(move |o| (cacheable, DistType::NoDist, o));
        }
    };

    debug!("[{}]: Attempting distributed compilation", out_pretty);
    let out_pretty2 = out_pretty.clone();

    let local_executable = compile_cmd.get_executable();
    let local_executable2 = compile_cmd.get_executable();

    let do_dist_compile = async move {
        let mut dist_compile_cmd =
            dist_compile_cmd.context("Could not create distributed compile command")?;
        debug!("[{}]: Creating distributed compile request", out_pretty);
        let dist_output_paths = compilation
            .outputs()
            .map(|output| path_transformer.as_dist_abs(&cwd.join(output.path)))
            .collect::<Option<_>>()
            .context("Failed to adapt an output path for distributed compile")?;
        let (inputs_packager, toolchain_packager, outputs_rewriter) =
            compilation.into_dist_packagers(path_transformer)?;

        debug!(
            "[{}]: Identifying dist toolchain for {:?}",
            out_pretty, local_executable
        );
        let (dist_toolchain, maybe_dist_compile_executable) = dist_client
            .put_toolchain(local_executable, weak_toolchain_key, toolchain_packager)
            .await?;
        let mut tc_archive = None;
        if let Some((dist_compile_executable, archive_path)) = maybe_dist_compile_executable {
            dist_compile_cmd.executable = dist_compile_executable;
            tc_archive = Some(archive_path);
        }

        debug!("[{}]: Requesting allocation", out_pretty);
        let jares = dist_client.do_alloc_job(dist_toolchain.clone()).await?;
        let job_alloc = match jares {
            dist::AllocJobResult::Success {
                job_alloc,
                need_toolchain: true,
            } => {
                debug!(
                    "[{}]: Sending toolchain {} for job {}",
                    out_pretty, dist_toolchain.archive_id, job_alloc.job_id
                );

                match dist_client
                    .do_submit_toolchain(job_alloc.clone(), dist_toolchain)
                    .await
                    .map_err(|e| e.context("Could not submit toolchain"))?
                {
                    dist::SubmitToolchainResult::Success => Ok(job_alloc),
                    dist::SubmitToolchainResult::JobNotFound => {
                        bail!("Job {} not found on server", job_alloc.job_id)
                    }
                    dist::SubmitToolchainResult::CannotCache => bail!(
                        "Toolchain for job {} could not be cached by server",
                        job_alloc.job_id
                    ),
                }
            }
            dist::AllocJobResult::Success {
                job_alloc,
                need_toolchain: false,
            } => Ok(job_alloc),
            dist::AllocJobResult::Fail { msg } => {
                Err(anyhow!("Failed to allocate job").context(msg))
            }
        }?;
        let job_id = job_alloc.job_id;
        let server_id = job_alloc.server_id;
        debug!("[{}]: Running job", out_pretty);
        let ((job_id, server_id), (jres, path_transformer)) = dist_client
            .do_run_job(
                job_alloc,
                dist_compile_cmd,
                dist_output_paths,
                inputs_packager,
            )
            .await
            .map(move |res| ((job_id, server_id), res))
            .with_context(|| {
                format!(
                    "could not run distributed compilation job on {:?}",
                    server_id
                )
            })?;

        let jc = match jres {
            dist::RunJobResult::Complete(jc) => jc,
            dist::RunJobResult::JobNotFound => bail!("Job {} not found on server", job_id),
        };
        debug!(
            "fetched {:?}",
            jc.outputs
                .iter()
                .map(|(p, bs)| (p, bs.lens().to_string()))
                .collect::<Vec<_>>()
        );
        let mut output_paths: Vec<PathBuf> = vec![];
        macro_rules! try_or_cleanup {
            ($v:expr) => {{
                match $v {
                    Ok(v) => v,
                    Err(e) => {
                        // Do our best to clear up. We may end up deleting a file that we just wrote over
                        // the top of, but it's better to clear up too much than too little
                        for local_path in output_paths.iter() {
                            if let Err(e) = fs::remove_file(local_path) {
                                if e.kind() != io::ErrorKind::NotFound {
                                    warn!("{} while attempting to clear up {}", e, local_path.display())
                                }
                            }
                        }
                        return Err(e)
                    },
                }
            }};
        }

        for (path, output_data) in jc.outputs {
            let len = output_data.lens().actual;
            let local_path = try_or_cleanup!(path_transformer
                .to_local(&path)
                .with_context(|| format!("unable to transform output path {}", path)));
            output_paths.push(local_path);
            // Do this first so cleanup works correctly
            let local_path = output_paths.last().expect("nothing in vec after push");

            let mut file = try_or_cleanup!(File::create(local_path)
                .with_context(|| format!("Failed to create output file {}", local_path.display())));
            let count = try_or_cleanup!(io::copy(&mut output_data.into_reader(), &mut file)
                .with_context(|| format!("Failed to write output to {}", local_path.display())));

            assert!(count == len);
        }
        let extra_inputs = match tc_archive {
            Some(p) => vec![p],
            None => vec![],
        };
        try_or_cleanup!(outputs_rewriter
            .handle_outputs(&path_transformer, &output_paths, &extra_inputs)
            .with_context(|| "failed to rewrite outputs from compile"));
        Ok((DistType::Ok(server_id), jc.output.into()))
    };

    use futures::TryFutureExt;
    do_dist_compile
        .or_else(move |e| async move {
            if let Some(HttpClientError(_)) = e.downcast_ref::<HttpClientError>() {
                Err(e)
            } else if let Some(lru_disk_cache::Error::FileTooLarge) =
                e.downcast_ref::<lru_disk_cache::Error>()
            {
                Err(anyhow!(
                    "Could not cache dist toolchain for {:?} locally.
                 Increase `toolchain_cache_size` or decrease the toolchain archive size.",
                    local_executable2
                ))
            } else {
                // `{:#}` prints the error and the causes in a single line.
                let errmsg = format!("{:#}", e);
                warn!(
                    "[{}]: Could not perform distributed compile, falling back to local: {}",
                    out_pretty2, errmsg
                );

                compile_cmd
                    .execute(service, &creator)
                    .await
                    .map(|o| (DistType::Error, o))
            }
        })
        .map_ok(move |(dt, o)| (cacheable, dt, o))
        .await
}

impl<T: CommandCreatorSync> Clone for Box<dyn CompilerHasher<T>> {
    fn clone(&self) -> Box<dyn CompilerHasher<T>> {
        self.box_clone()
    }
}

/// An interface to a compiler for actually invoking compilation.
pub trait Compilation<T>: Send
where
    T: CommandCreatorSync,
{
    /// Given information about a compiler command, generate a command that can
    /// execute the compiler.
    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        rewrite_includes_only: bool,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )>;

    /// Create a function that will create the inputs used to perform a distributed compilation
    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(
        self: Box<Self>,
        _path_transformer: dist::PathTransformer,
    ) -> Result<DistPackagers>;

    /// Returns an iterator over the results of this compilation.
    ///
    /// Each item is a descriptive (and unique) name of the output paired with
    /// the path where it'll show up.
    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = FileObjectSource> + 'a>;
}

#[cfg(feature = "dist-client")]
pub trait OutputsRewriter: Send {
    /// Perform any post-compilation handling of outputs, given a Vec of the dist_path and local_path
    fn handle_outputs(
        self: Box<Self>,
        path_transformer: &dist::PathTransformer,
        output_paths: &[PathBuf],
        extra_inputs: &[PathBuf],
    ) -> Result<()>;
}

#[cfg(feature = "dist-client")]
pub struct NoopOutputsRewriter;
#[cfg(feature = "dist-client")]
impl OutputsRewriter for NoopOutputsRewriter {
    fn handle_outputs(
        self: Box<Self>,
        _path_transformer: &dist::PathTransformer,
        _output_paths: &[PathBuf],
        _extra_inputs: &[PathBuf],
    ) -> Result<()> {
        Ok(())
    }
}

/// Result of generating a hash from a compiler command.
pub struct HashResult<T>
where
    T: CommandCreatorSync,
{
    /// The hash key of the inputs.
    pub key: String,
    /// An object to use for the actual compilation, if necessary.
    pub compilation: Box<dyn Compilation<T> + 'static>,
    /// A weak key that may be used to identify the toolchain
    pub weak_toolchain_key: String,
}

/// Possible results of parsing compiler arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum CompilerArguments<T> {
    /// Commandline can be handled.
    Ok(T),
    /// Cannot cache this compilation.
    CannotCache(&'static str, Option<String>),
    /// This commandline is not a compile.
    NotCompilation,
}

macro_rules! cannot_cache {
    ($why:expr) => {
        return CompilerArguments::CannotCache($why, None)
    };
    ($why:expr, $extra_info:expr) => {
        return CompilerArguments::CannotCache($why, Some($extra_info))
    };
}

macro_rules! try_or_cannot_cache {
    ($arg:expr, $why:expr) => {{
        match $arg {
            Ok(arg) => arg,
            Err(e) => cannot_cache!($why, e.to_string()),
        }
    }};
}

/// Specifics about distributed compilation.
#[derive(Debug, PartialEq, Eq)]
pub enum DistType {
    /// Distribution was not enabled.
    NoDist,
    /// Distributed compile success.
    Ok(dist::ServerId),
    /// Distributed compile failed.
    Error,
}

/// Specifics about cache misses.
#[derive(Debug, PartialEq, Eq)]
pub enum MissType {
    /// The compilation was not found in the cache, nothing more.
    Normal,
    /// Do not cache the results of the compilation.
    ForcedNoCache,
    /// Cache lookup was overridden, recompilation was forced.
    ForcedRecache,
    /// Cache took too long to respond.
    TimedOut,
    /// Error reading from cache
    CacheReadError,
}

/// Information about a successful cache write.
pub struct CacheWriteInfo {
    pub object_file_pretty: String,
    pub duration: Duration,
}

/// The result of a compilation or cache retrieval.
pub enum CompileResult {
    /// An error made the compilation not possible.
    Error,
    /// Result was found in cache.
    CacheHit(Duration),
    /// Result was not found in cache.
    ///
    /// The `CacheWriteFuture` will resolve when the result is finished
    /// being stored in the cache.
    CacheMiss(
        MissType,
        DistType,
        Duration, // Compilation time
        Pin<Box<dyn Future<Output = Result<CacheWriteInfo>> + Send>>,
    ),
    /// Not in cache and do not cache the results of the compilation.
    NotCached(DistType, Duration),
    /// Not in cache, but the compilation result was determined to be not cacheable.
    NotCacheable(DistType, Duration),
    /// Not in cache, but compilation failed.
    CompileFailed(DistType, Duration),
}

/// The state of `--color` options passed to a compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ColorMode {
    Off,
    On,
    #[default]
    Auto,
}

/// Can't derive(Debug) because of `CacheWriteFuture`.
impl fmt::Debug for CompileResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CompileResult::Error => write!(f, "CompileResult::Error"),
            CompileResult::CacheHit(ref d) => write!(f, "CompileResult::CacheHit({:?})", d),
            CompileResult::CacheMiss(ref m, ref dt, ref d, _) => {
                write!(f, "CompileResult::CacheMiss({:?}, {:?}, {:?}, _)", d, m, dt)
            }
            CompileResult::NotCached(ref dt, ref d) => {
                write!(f, "CompileResult::NotCached({:?}, {:?}_", dt, d)
            }
            CompileResult::NotCacheable(ref dt, ref d) => {
                write!(f, "CompileResult::NotCacheable({:?}, {:?}_", dt, d)
            }
            CompileResult::CompileFailed(ref dt, ref d) => {
                write!(f, "CompileResult::CompileFailed({:?}, {:?})", dt, d)
            }
        }
    }
}

/// Can't use derive(PartialEq) because of the `CacheWriteFuture`.
impl PartialEq<CompileResult> for CompileResult {
    fn eq(&self, other: &CompileResult) -> bool {
        match (self, other) {
            (&CompileResult::Error, &CompileResult::Error) => true,
            (&CompileResult::CacheHit(_), &CompileResult::CacheHit(_)) => true,
            (CompileResult::CacheMiss(m, dt, _, _), CompileResult::CacheMiss(n, dt2, _, _)) => {
                m == n && dt == dt2
            }
            (CompileResult::NotCached(dt, _), CompileResult::NotCached(dt2, _)) => dt == dt2,
            (CompileResult::NotCacheable(dt, _), CompileResult::NotCacheable(dt2, _)) => dt == dt2,
            (CompileResult::CompileFailed(dt, _), CompileResult::CompileFailed(dt2, _)) => {
                dt == dt2
            }
            _ => false,
        }
    }
}

/// Can this result be stored in cache?
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cacheable {
    Yes,
    No,
}

/// Control of caching behavior.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheControl {
    /// Default caching behavior.
    Default,
    /// Do not cache the results of the compilation.
    ForceNoCache,
    /// Ignore existing cache entries, force recompilation.
    ForceRecache,
}

/// Creates a future that will write `contents` to `path` inside of a temporary
/// directory.
///
/// The future will resolve to the temporary directory and an absolute path
/// inside that temporary directory with a file that has the same filename as
/// `path` contains the `contents` specified.
///
/// Note that when the `TempDir` is dropped it will delete all of its contents
/// including the path returned.
pub async fn write_temp_file(
    pool: &tokio::runtime::Handle,
    path: &Path,
    contents: Vec<u8>,
) -> Result<(TempDir, PathBuf)> {
    let path = path.to_owned();
    pool.spawn_blocking(move || {
        let dir = tempfile::Builder::new().prefix("sccache").tempdir()?;
        let src = dir.path().join(path);
        let mut file = File::create(&src)?;
        file.write_all(&contents)?;
        Ok::<_, anyhow::Error>((dir, src))
    })
    .await?
    .context("failed to write temporary file")
}

/// Returns true if the given path looks like a program known to have
/// a rustc compatible interface.
fn is_rustc_like<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("rustc") | Some("clippy-driver")
    )
}

/// Returns true if the given path looks like cicc
fn is_nvidia_cicc<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("cicc")
    )
}

/// Returns true if the given path looks like ptxas
fn is_nvidia_ptxas<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("ptxas")
    )
}

/// Returns true if the given path looks like a c compiler program
///
/// This does not check c compilers, it only report programs that are definitely not rustc
fn is_known_c_compiler<P: AsRef<Path>>(p: P) -> bool {
    matches!(
        p.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .as_deref(),
        Some(
            "cc" | "c++"
                | "gcc"
                | "g++"
                | "clang"
                | "clang++"
                | "clang-cl"
                | "cl"
                | "nvc"
                | "nvc++"
                | "nvcc"
        )
    )
}

/// If `executable` is a known compiler, return `Some(Box<Compiler>)`.
async fn detect_compiler<T>(
    creator: T,
    executable: &Path,
    cwd: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    pool: &tokio::runtime::Handle,
    dist_archive: Option<PathBuf>,
) -> Result<(Box<dyn Compiler<T>>, Option<Box<dyn CompilerProxy<T>>>)>
where
    T: CommandCreatorSync,
{
    trace!("detect_compiler: {}", executable.display());
    // First, see if this looks like rustc.

    let maybe_rustc_executable = if is_rustc_like(executable) {
        Some(executable.to_path_buf())
    } else if env.iter().any(|(k, _)| k == OsStr::new("CARGO")) {
        // If not, detect the scenario where cargo is configured to wrap rustc with something other than sccache.
        // This happens when sccache is used as a `RUSTC_WRAPPER` and another tool is used as a
        // `RUSTC_WORKSPACE_WRAPPER`. In that case rustc will be the first argument rather than the command.
        //
        // The check for the `CARGO` env acts as a guardrail against false positives.
        // https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-reads
        args.iter()
            .next()
            .filter(|arg1| is_rustc_like(arg1))
            .map(PathBuf::from)
    } else {
        None
    };

    let pool = pool.clone();

    let rustc_executable = if let Some(ref rustc_executable) = maybe_rustc_executable {
        rustc_executable
    } else if is_nvidia_cicc(executable) {
        debug!("Found cicc");
        return CCompiler::new(
            Cicc {
                // TODO: Use nvcc --version
                version: Some(String::new()),
            },
            executable.to_owned(),
            &pool,
        )
        .await
        .map(|c| (Box::new(c) as Box<dyn Compiler<T>>, None));
    } else if is_nvidia_ptxas(executable) {
        debug!("Found ptxas");
        return CCompiler::new(
            Ptxas {
                // TODO: Use nvcc --version
                version: Some(String::new()),
            },
            executable.to_owned(),
            &pool,
        )
        .await
        .map(|c| (Box::new(c) as Box<dyn Compiler<T>>, None));
    } else if is_known_c_compiler(executable) {
        let cc = detect_c_compiler(creator, executable, args, env.to_vec(), pool).await;
        return cc.map(|c| (c, None));
    } else {
        // Even if it does not look like rustc like it might still be rustc driver
        // so we do full check
        executable
    };

    match resolve_rust_compiler(
        creator.clone(),
        executable,
        rustc_executable.to_path_buf(),
        env,
        cwd.to_path_buf(),
        dist_archive,
        pool.clone(),
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(e) => {
            // in case we attempted to test for rustc while it didn't look like it, fallback to c compiler detection one lat time
            if maybe_rustc_executable.is_none() {
                let executable = executable.to_path_buf();
                let cc = detect_c_compiler(creator, executable, args, env.to_vec(), pool).await;
                cc.map(|c| (c, None))
            } else {
                Err(e)
            }
        }
    }
}

/// Tries to verify that provided executable is really rust compiler
/// or rust driver
async fn resolve_rust_compiler<T>(
    creator: T,
    executable: &Path,
    rustc_executable: PathBuf,
    env: &[(OsString, OsString)],
    cwd: PathBuf,
    dist_archive: Option<PathBuf>,
    pool: tokio::runtime::Handle,
) -> Result<(Box<dyn Compiler<T>>, Option<Box<dyn CompilerProxy<T>>>)>
where
    T: CommandCreatorSync,
{
    let mut child = creator.clone().new_command_sync(executable);
    // We're wrapping rustc if the executable doesn't match the detected rustc_executable. In this case the wrapper
    // expects rustc as the first argument.
    if rustc_executable != executable {
        child.arg(&rustc_executable);
    }

    child.env_clear().envs(env.to_vec()).args(&["-vV"]);

    let rustc_vv = run_input_output(child, None).await.map(|output| {
        if let Ok(stdout) = String::from_utf8(output.stdout.clone()) {
            if stdout.starts_with("rustc ") {
                return Ok(stdout);
            }
        }
        Err(ProcessError(output))
    })?;

    // rustc -vV verification status
    match rustc_vv {
        Ok(rustc_verbose_version) => {
            let rustc_executable2 = rustc_executable.clone();

            let proxy = RustupProxy::find_proxy_executable::<T>(
                &rustc_executable2,
                "rustup",
                creator.clone(),
                env,
            );
            use futures::TryFutureExt;
            let creator1 = creator.clone();
            let res = proxy.and_then(move |proxy| async move {
                match proxy {
                    Ok(Some(proxy)) => {
                        trace!("Found rustup proxy executable");
                        // take the pathbuf for rustc as resolved by the proxy
                        match proxy.resolve_proxied_executable(creator1, cwd, env).await {
                            Ok((resolved_path, _time)) => {
                                trace!("Resolved path with rustup proxy {:?}", &resolved_path);
                                Ok((Some(proxy), resolved_path))
                            }
                            Err(e) => {
                                trace!("Could not resolve compiler with rustup proxy: {}", e);
                                Ok((None, rustc_executable))
                            }
                        }
                    }
                    Ok(None) => {
                        trace!("Did not find rustup");
                        Ok((None, rustc_executable))
                    }
                    Err(e) => {
                        trace!("Did not find rustup due to {}, compiling without proxy", e);
                        Ok((None, rustc_executable))
                    }
                }
            });

            let (proxy, resolved_rustc) = res
                .await
                .map(|(proxy, resolved_compiler_executable)| {
                    (
                        proxy
                            .map(Box::new)
                            .map(|x: Box<RustupProxy>| x as Box<dyn CompilerProxy<T>>),
                        resolved_compiler_executable,
                    )
                })
                .unwrap_or_else(|_e| {
                    trace!("Compiling rust without proxy");
                    (None, rustc_executable2)
                });

            debug!("Using rustc at path: {resolved_rustc:?}");

            Rust::new(
                creator,
                resolved_rustc,
                env,
                &rustc_verbose_version,
                dist_archive,
                pool,
            )
            .await
            .map(|c| {
                (
                    Box::new(c) as Box<dyn Compiler<T>>,
                    proxy as Option<Box<dyn CompilerProxy<T>>>,
                )
            })
        }
        Err(e) => Err(e).context("Failed to launch subprocess for compiler determination"),
    }
}

ArgData! {
    PassThrough(OsString),
}
use self::ArgData::PassThrough as Detect_PassThrough;

// Establish a set of compiler flags that are required for
// valid execution of the compiler even in preprocessor mode.
// If the requested compiler invocatiomn has any of these arguments
// propagate them when doing our compiler vendor detection
//
// Current known required flags:
// ccbin/compiler-bindir needed for nvcc
//  This flag specifies the host compiler to use otherwise
//  gcc is expected to exist on the PATH. So if gcc doesn't exist
//  compiler detection fails if we don't pass along the ccbin arg
counted_array!(static ARGS: [ArgInfo<ArgData>; _] = [
    take_arg!("--compiler-bindir", OsString, CanBeSeparated('='), Detect_PassThrough),
    take_arg!("-ccbin", OsString, CanBeSeparated('='), Detect_PassThrough),
]);

async fn detect_c_compiler<T, P>(
    creator: T,
    executable: P,
    arguments: &[OsString],
    env: Vec<(OsString, OsString)>,
    pool: tokio::runtime::Handle,
) -> Result<Box<dyn Compiler<T>>>
where
    T: CommandCreatorSync,
    P: AsRef<Path>,
{
    trace!("detect_c_compiler");

    // NVCC needs to be first as msvc, clang, or gcc could
    // be the underlying host compiler for nvcc
    // Both clang and clang-cl define _MSC_VER on Windows, so we first
    // check for MSVC, then check whether _MT is defined, which is the
    // difference between clang and clang-cl.
    // NVHPC needs a custom version line since `__VERSION__` evaluates
    // to the EDG version.
    //
    // We prefix the information we need with `compiler_id` and `compiler_version`
    // so that we can support compilers that insert pre-amble code even in `-E` mode
    let test = b"
#if defined(__NVCC__) && defined(__NVCOMPILER)
compiler_id=nvcc-nvhpc
compiler_version=__CUDACC_VER_MAJOR__.__CUDACC_VER_MINOR__.__CUDACC_VER_BUILD__
#elif defined(__NVCC__) && defined(_MSC_VER)
compiler_id=nvcc-msvc
compiler_version=__CUDACC_VER_MAJOR__.__CUDACC_VER_MINOR__.__CUDACC_VER_BUILD__
#elif defined(__NVCC__)
compiler_id=nvcc
compiler_version=__CUDACC_VER_MAJOR__.__CUDACC_VER_MINOR__.__CUDACC_VER_BUILD__
#elif defined(_MSC_VER) && !defined(__clang__)
compiler_id=msvc
#elif defined(_MSC_VER) && defined(_MT)
compiler_id=msvc-clang
#elif defined(__NVCOMPILER)
compiler_id=nvhpc
compiler_version=__NVCOMPILER_MAJOR__.__NVCOMPILER_MINOR__.__NVCOMPILER_PATCHLEVEL__
#elif defined(__clang__) && defined(__cplusplus) && defined(__apple_build_version__)
compiler_id=apple-clang++
#elif defined(__clang__) && defined(__cplusplus)
compiler_id=clang++
#elif defined(__clang__) && defined(__apple_build_version__)
compiler_id=apple-clang
#elif defined(__clang__)
compiler_id=clang
#elif defined(__GNUC__) && defined(__cplusplus)
compiler_id=g++
#elif defined(__GNUC__)
compiler_id=gcc
#elif defined(__DCC__)
compiler_id=diab
#elif defined(__CTC__)
compiler_id=tasking_vx
#else
compiler_id=unknown
#endif
compiler_version=__VERSION__
"
    .to_vec();
    let (tempdir, src) = write_temp_file(&pool, "testfile.c".as_ref(), test).await?;

    let executable = executable.as_ref();
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(env.iter().map(|s| (&s.0, &s.1)));

    // Iterate over all the arguments for compilation and extract
    // any that are required for any valid execution of the compiler.
    // Allowing our compiler vendor detection to always properly execute
    for arg in ArgsIter::new(arguments.iter().cloned(), &ARGS[..]) {
        let arg = arg.unwrap_or_else(|_| Argument::Raw(OsString::from("")));
        if let Some(Detect_PassThrough(_)) = arg.get_data() {
            let required_arg = arg.normalize(NormalizedDisposition::Concatenated);
            cmd.args(&Vec::from_iter(required_arg.iter_os_strings()));
        }
    }

    cmd.arg("-E").arg(src);
    trace!("compiler {:?}", cmd);
    let child = cmd.spawn().await?;
    let output = child
        .wait_with_output()
        .await
        .context("failed to read child output")?;

    drop(tempdir);

    let stdout = match str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(_) => bail!("Failed to parse output"),
    };
    let mut lines = stdout.lines().filter_map(|line| {
        let line = line.trim();
        if line.starts_with("compiler_id=") {
            Some(line.strip_prefix("compiler_id=").unwrap())
        } else if line.starts_with("compiler_version=") {
            Some(line.strip_prefix("compiler_version=").unwrap())
        } else {
            None
        }
    });
    if let Some(kind) = lines.next() {
        let executable = executable.to_owned();
        let version = lines
            .next()
            // In case the compiler didn't expand the macro.
            .filter(|&line| line != "__VERSION__")
            .map(str::to_owned);
        match kind {
            "clang" | "clang++" | "apple-clang" | "apple-clang++" => {
                debug!("Found {}", kind);
                return CCompiler::new(
                    Clang {
                        clangplusplus: kind.ends_with("++"),
                        is_appleclang: kind.starts_with("apple-"),
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "diab" => {
                debug!("Found diab");
                return CCompiler::new(
                    Diab {
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "gcc" | "g++" => {
                debug!("Found {}", kind);
                return CCompiler::new(
                    Gcc {
                        gplusplus: kind == "g++",
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "msvc" | "msvc-clang" => {
                let is_clang = kind == "msvc-clang";
                debug!("Found MSVC (is clang: {})", is_clang);
                let prefix = msvc::detect_showincludes_prefix(
                    &creator,
                    executable.as_ref(),
                    is_clang,
                    env,
                    &pool,
                )
                .await?;
                trace!("showIncludes prefix: '{}'", prefix);

                return CCompiler::new(
                    Msvc {
                        includes_prefix: prefix,
                        is_clang,
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "nvcc" | "nvcc-msvc" | "nvcc-nvhpc" => {
                let host_compiler = match kind {
                    "nvcc-nvhpc" => NvccHostCompiler::Nvhpc,
                    "nvcc-msvc" => NvccHostCompiler::Msvc,
                    "nvcc" => NvccHostCompiler::Gcc,
                    &_ => NvccHostCompiler::Gcc,
                };
                let host_compiler_version = lines
                    .next()
                    // In case the compiler didn't expand the macro.
                    .filter(|&line| line != "__VERSION__")
                    .map(str::to_owned);

                return CCompiler::new(
                    Nvcc {
                        host_compiler,
                        version,
                        host_compiler_version,
                    },
                    executable,
                    &pool,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "nvhpc" => {
                debug!("Found NVHPC");
                return CCompiler::new(
                    Nvhpc {
                        nvcplusplus: kind == "nvc++",
                        version: version.clone(),
                    },
                    executable,
                    &pool,
                )
                .await
                .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            "tasking_vx" => {
                debug!("Found Tasking VX");
                return CCompiler::new(TaskingVX, executable, &pool)
                    .await
                    .map(|c| Box::new(c) as Box<dyn Compiler<T>>);
            }
            _ => (),
        }
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!("nothing useful in detection output {:?}", stdout);
    debug!("compiler status: {}", output.status);
    debug!("compiler stderr:\n{}", stderr);

    bail!(stderr.into_owned())
}

/// If `executable` is a known compiler, return a `Box<Compiler>` containing information about it.
pub async fn get_compiler_info<T>(
    creator: T,
    executable: &Path,
    cwd: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    pool: &tokio::runtime::Handle,
    dist_archive: Option<PathBuf>,
) -> Result<(Box<dyn Compiler<T>>, Option<Box<dyn CompilerProxy<T>>>)>
where
    T: CommandCreatorSync,
{
    let pool = pool.clone();
    detect_compiler(creator, executable, cwd, args, env, &pool, dist_archive).await
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::disk::DiskCache;
    use crate::cache::{CacheMode, CacheRead, PreprocessorCacheModeConfig};
    use crate::mock_command::*;
    use crate::test::mock_storage::MockStorage;
    use crate::test::utils::*;
    use fs::File;
    use std::io::{Cursor, Write};
    use std::sync::Arc;
    use std::time::Duration;
    use test_case::test_case;
    use tokio::runtime::Runtime;

    #[test]
    fn test_detect_compiler_kind_gcc() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(
            &creator,
            Ok(MockChild::new(
                exit_status(1),
                "",
                "gcc: error: unrecognized command-line option '-vV'; did you mean '-v'?",
            )),
        );
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "\n\ncompiler_id=gcc", "")),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Gcc), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_clang() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(
            &creator,
            Ok(MockChild::new(
                exit_status(1),
                "",
                "clang: error: unknown argument: '-vV'",
            )),
        );
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=clang\n", "")),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
    }

    #[test]
    fn test_detect_compiler_must_be_clang() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let clang = f.mk_bin("clang").unwrap();
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=clang\n", "")),
        );
        let c = detect_compiler(creator, &clang, f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
    }

    #[test]
    fn test_detect_compiler_vv_clang() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "clang: 13\n", "")),
        );
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=clang\n", "")),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_msvc() {
        drop(env_logger::try_init());
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let f = TestFixture::new();
        let srcfile = f.touch("test.h").unwrap();
        let mut s = srcfile.to_str().unwrap();
        if s.starts_with("\\\\?\\") {
            s = &s[4..];
        }
        let prefix = String::from("blah: ");
        let stdout = format!("{}{}\r\n", prefix, s);
        // Compiler detection output
        next_command(
            &creator,
            Ok(MockChild::new(
                exit_status(1),
                "",
                "msvc-error: unknown argument: '-vV'",
            )),
        );
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "\ncompiler_id=msvc\n", "")),
        );
        // showincludes prefix detection output
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), stdout, String::new())),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Msvc), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_nvcc() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=nvcc\n", "")),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Nvcc), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_nvhpc() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=nvhpc\n", "")),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Nvhpc), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_rustc() {
        let f = TestFixture::new();
        // Windows uses bin, everything else uses lib. Just create both.
        fs::create_dir(f.tempdir.path().join("lib")).unwrap();
        fs::create_dir(f.tempdir.path().join("bin")).unwrap();
        let rustc = f.mk_bin("rustc.exe").unwrap();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        populate_rustc_command_mock(&creator, &f);
        let c = detect_compiler(creator, &rustc, f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::Rust, c.kind());
    }

    #[test]
    fn test_is_rustc_like() {
        assert!(is_rustc_like("rustc"));
        assert!(is_rustc_like("rustc.exe"));
        assert!(is_rustc_like("/path/to/rustc.exe"));
        assert!(is_rustc_like("/path/to/rustc"));
        assert!(is_rustc_like("/PATH/TO/RUSTC.EXE"));
        assert!(is_rustc_like("/Path/To/RustC.Exe"));
        assert!(is_rustc_like("/path/to/clippy-driver"));
        assert!(is_rustc_like("/path/to/clippy-driver.exe"));
        assert!(is_rustc_like("/PATH/TO/CLIPPY-DRIVER.EXE"));
        assert!(is_rustc_like("/Path/To/Clippy-Driver.Exe"));
        assert!(!is_rustc_like("rust"));
        assert!(!is_rustc_like("RUST"));
    }

    fn populate_rustc_command_mock(
        creator: &Arc<std::sync::Mutex<MockCommandCreator>>,
        f: &TestFixture,
    ) {
        // rustc --vV
        next_command(
            creator,
            Ok(MockChild::new(
                exit_status(0),
                "\
rustc 1.27.0 (3eda71b00 2018-06-19)
binary: rustc
commit-hash: 3eda71b00ad48d7bf4eef4c443e7f611fd061418
commit-date: 2018-06-19
host: x86_64-unknown-linux-gnu
release: 1.27.0
LLVM version: 6.0",
                "",
            )),
        );
        // rustc --print=sysroot
        let sysroot = f.tempdir.path().to_str().unwrap();
        next_command(creator, Ok(MockChild::new(exit_status(0), sysroot, "")));
        next_command(creator, Ok(MockChild::new(exit_status(0), sysroot, "")));
        next_command(creator, Ok(MockChild::new(exit_status(0), sysroot, "")));
    }

    #[test]
    fn test_detect_compiler_kind_rustc_workspace_wrapper() {
        let f = TestFixture::new();
        // Windows uses bin, everything else uses lib. Just create both.
        fs::create_dir(f.tempdir.path().join("lib")).unwrap();
        fs::create_dir(f.tempdir.path().join("bin")).unwrap();
        let rustc = f.mk_bin("rustc-workspace-wrapper").unwrap();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        populate_rustc_command_mock(&creator, &f);
        let c = detect_compiler(
            creator,
            &rustc,
            f.tempdir.path(),
            // Specifying an extension tests the ignoring
            &[OsString::from("rustc.exe")],
            &[(OsString::from("CARGO"), OsString::from("CARGO"))],
            pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        assert_eq!(CompilerKind::Rust, c.kind());

        // Test we don't detect rustc if the first arg is not rustc
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        populate_rustc_command_mock(&creator, &f);
        assert!(detect_compiler(
            creator,
            &rustc,
            f.tempdir.path(),
            &[OsString::from("not-rustc")],
            &[(OsString::from("CARGO"), OsString::from("CARGO"))],
            pool,
            None,
        )
        .wait()
        .is_err());

        // Test we detect rustc if the CARGO env is not defined
        let creator = new_creator();
        populate_rustc_command_mock(&creator, &f);
        assert!(detect_compiler(
            creator,
            &rustc,
            f.tempdir.path(),
            &[OsString::from("rustc")],
            &[],
            pool,
            None,
        )
        .wait()
        .is_ok());
    }

    #[test]
    fn test_detect_compiler_kind_diab() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "\ncompiler_id=diab\n", "")),
        );
        let c = detect_compiler(creator, &f.bins[0], f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        assert_eq!(CompilerKind::C(CCompilerKind::Diab), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_unknown() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "something", "")),
        );
        assert!(detect_compiler(
            creator,
            "/foo/bar".as_ref(),
            f.tempdir.path(),
            &[],
            &[],
            pool,
            None
        )
        .wait()
        .is_err());
    }

    #[test]
    fn test_detect_compiler_kind_process_fail() {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "no -vV")));
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert!(detect_compiler(
            creator,
            "/foo/bar".as_ref(),
            f.tempdir.path(),
            &[],
            &[],
            pool,
            None
        )
        .wait()
        .is_err());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_compiler_version_affects_hash(preprocessor_cache_mode: bool) {
        let f = TestFixture::new();
        let clang = f.mk_bin("clang").unwrap();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let cwd = f.tempdir.path();
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();

        let results: Vec<_> = [11, 12]
            .iter()
            .map(|version| {
                let output = format!("compiler_id=clang\ncompiler_version=\"{}.0.0\"", version);
                next_command(&creator, Ok(MockChild::new(exit_status(0), output, "")));
                let c = detect_compiler(
                    creator.clone(),
                    &clang,
                    f.tempdir.path(),
                    &[],
                    &[],
                    pool,
                    None,
                )
                .wait()
                .unwrap()
                .0;
                next_command(
                    &creator,
                    Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
                );
                let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
                    CompilerArguments::Ok(h) => h,
                    o => panic!("Bad result from parse_arguments: {:?}", o),
                };
                hasher
                    .generate_hash_key(
                        &creator,
                        cwd.to_path_buf(),
                        vec![],
                        false,
                        pool,
                        false,
                        Arc::new(MockStorage::new(None, preprocessor_cache_mode)),
                        CacheControl::Default,
                    )
                    .wait()
                    .unwrap()
            })
            .collect();
        assert_eq!(results.len(), 2);
        assert_ne!(results[0].key, results[1].key);
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_common_args_affects_hash(preprocessor_cache_mode: bool) {
        let f = TestFixture::new();
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let output = "compiler_id=clang\ncompiler_version=\"16.0.0\"";
        let arguments = [
            ovec!["-c", "foo.c", "-o", "foo.o", "-DHELLO"],
            ovec!["-c", "foo.c", "-o", "foo.o", "-DHI"],
            ovec!["-c", "foo.c", "-o", "foo.o"],
        ];
        let cwd = f.tempdir.path();
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();

        let results: Vec<_> = arguments
            .iter()
            .map(|argument| {
                next_command(
                    &creator,
                    Ok(MockChild::new(
                        exit_status(1),
                        "",
                        "clang: error: unknown argument: '-vV'",
                    )),
                );
                next_command(&creator, Ok(MockChild::new(exit_status(0), output, "")));
                let c = detect_compiler(
                    creator.clone(),
                    &f.bins[0],
                    f.tempdir.path(),
                    &[],
                    &[],
                    pool,
                    None,
                )
                .wait()
                .unwrap()
                .0;
                next_command(
                    &creator,
                    Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
                );
                let hasher = match c.parse_arguments(argument, ".".as_ref(), &[]) {
                    CompilerArguments::Ok(h) => h,
                    o => panic!("Bad result from parse_arguments: {:?}", o),
                };
                hasher
                    .generate_hash_key(
                        &creator,
                        cwd.to_path_buf(),
                        vec![],
                        false,
                        pool,
                        false,
                        Arc::new(MockStorage::new(None, preprocessor_cache_mode)),
                        CacheControl::Default,
                    )
                    .wait()
                    .unwrap()
            })
            .collect();

        assert_eq!(results.len(), 3);
        assert_ne!(results[0].key, results[1].key);
        assert_ne!(results[1].key, results[2].key);
        assert_ne!(results[0].key, results[2].key);
    }

    #[test]
    fn test_get_compiler_info() {
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle();
        let f = TestFixture::new();
        // Pretend to be GCC.
        let gcc = f.mk_bin("gcc").unwrap();
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(creator, &gcc, f.tempdir.path(), &[], &[], pool, None)
            .wait()
            .unwrap()
            .0;
        // digest of an empty file.
        assert_eq!(CompilerKind::C(CCompilerKind::Gcc), c.kind());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_compiler_get_cached_or_compile(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = Runtime::new().unwrap();
        let pool = runtime.handle().clone();
        let storage = DiskCache::new(
            f.tempdir.path().join("cache"),
            u64::MAX,
            &pool,
            PreprocessorCacheModeConfig {
                use_preprocessor_cache_mode: preprocessor_cache_mode,
                ..Default::default()
            },
            CacheMode::ReadWrite,
        );
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        let storage = Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage.clone(), pool.clone());

        // Pretend to be GCC.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        // The preprocessor invocation.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
        );
        // The compiler invocation.
        const COMPILER_STDOUT: &[u8] = b"compiler stdout";
        const COMPILER_STDERR: &[u8] = b"compiler stderr";
        let obj = f.tempdir.path().join("foo.o");
        let o = obj.clone();
        next_command_calls(&creator, move |_| {
            // Pretend to compile something.
            let mut f = File::create(&o)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(
                exit_status(0),
                COMPILER_STDOUT,
                COMPILER_STDERR,
            ))
        });
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let hasher2 = hasher.clone();
        let (cached, res) = runtime
            .block_on(async {
                hasher
                    .get_cached_or_compile(
                        &service,
                        None,
                        creator.clone(),
                        storage.clone(),
                        arguments.clone(),
                        cwd.to_path_buf(),
                        vec![],
                        CacheControl::Default,
                        pool.clone(),
                    )
                    .await
            })
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::Normal, DistType::NoDist, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => panic!("Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, which should be a cache hit.
        fs::remove_file(&obj).unwrap();
        // The preprocessor invocation.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
        );
        // There should be no actual compiler invocation.
        let (cached, res) = runtime
            .block_on(async {
                hasher2
                    .get_cached_or_compile(
                        &service,
                        None,
                        creator,
                        storage,
                        arguments,
                        cwd.to_path_buf(),
                        vec![],
                        CacheControl::Default,
                        pool,
                    )
                    .await
            })
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        assert_eq!(CompileResult::CacheHit(Duration::new(0, 0)), cached);
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    #[cfg(feature = "dist-client")]
    fn test_compiler_get_cached_or_compile_dist(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = Runtime::new().unwrap();
        let pool = runtime.handle().clone();
        let storage = DiskCache::new(
            f.tempdir.path().join("cache"),
            u64::MAX,
            &pool,
            PreprocessorCacheModeConfig {
                use_preprocessor_cache_mode: preprocessor_cache_mode,
                ..Default::default()
            },
            CacheMode::ReadWrite,
        );
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        let storage = Arc::new(storage);
        // Pretend to be GCC.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        // The preprocessor invocation.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
        );
        // The compiler invocation.
        const COMPILER_STDOUT: &[u8] = b"compiler stdout";
        const COMPILER_STDERR: &[u8] = b"compiler stderr";
        let obj = f.tempdir.path().join("foo.o");
        // Dist client will do the compilation
        let dist_client = test_dist::OneshotClient::new(
            0,
            COMPILER_STDOUT.to_owned(),
            COMPILER_STDERR.to_owned(),
        );
        let service = server::SccacheService::mock_with_dist_client(
            dist_client.clone(),
            storage.clone(),
            pool.clone(),
        );

        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let hasher2 = hasher.clone();
        let (cached, res) = runtime
            .block_on(async {
                hasher
                    .get_cached_or_compile(
                        &service,
                        Some(dist_client.clone()),
                        creator.clone(),
                        storage.clone(),
                        arguments.clone(),
                        cwd.to_path_buf(),
                        vec![],
                        CacheControl::Default,
                        pool.clone(),
                    )
                    .await
            })
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::Normal, DistType::Ok(_), _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => panic!("Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, which should be a cache hit.
        fs::remove_file(&obj).unwrap();
        // The preprocessor invocation.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
        );
        // There should be no actual compiler invocation.
        let (cached, res) = runtime
            .block_on(async {
                hasher2
                    .get_cached_or_compile(
                        &service,
                        Some(dist_client.clone()),
                        creator,
                        storage,
                        arguments,
                        cwd.to_path_buf(),
                        vec![],
                        CacheControl::Default,
                        pool,
                    )
                    .await
            })
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        assert_eq!(CompileResult::CacheHit(Duration::new(0, 0)), cached);
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    /// Test that a cache read that results in an error is treated as a cache
    /// miss.
    fn test_compiler_get_cached_or_compile_cache_error(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = Runtime::new().unwrap();
        let pool = runtime.handle().clone();
        let storage = MockStorage::new(None, preprocessor_cache_mode);
        let storage: Arc<MockStorage> = Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage.clone(), pool.clone());

        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        // Pretend to be GCC.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        // The preprocessor invocation.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
        );
        // The compiler invocation.
        const COMPILER_STDOUT: &[u8] = b"compiler stdout";
        const COMPILER_STDERR: &[u8] = b"compiler stderr";
        let obj = f.tempdir.path().join("foo.o");
        let o = obj.clone();
        next_command_calls(&creator, move |_| {
            // Pretend to compile something.
            let mut f = File::create(&o)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(
                exit_status(0),
                COMPILER_STDOUT,
                COMPILER_STDERR,
            ))
        });
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        // The cache will return an error.
        storage.next_get(Err(anyhow!("Some Error")));
        let (cached, res) = runtime
            .block_on(hasher.get_cached_or_compile(
                &service,
                None,
                creator,
                storage,
                arguments.clone(),
                cwd.to_path_buf(),
                vec![],
                CacheControl::Default,
                pool,
            ))
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::CacheReadError, DistType::NoDist, _, f) => {
                // wait on cache write future so we don't race with it!
                let _ = f.wait();
            }
            _ => panic!("Unexpected compile result: {:?}", cached),
        }

        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    /// Test that cache read timing is recorded.
    fn test_compiler_get_cached_or_compile_cache_get_timing(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = Runtime::new().unwrap();
        let pool = runtime.handle().clone();
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        // Make our storage wait 2ms for each get/put operation.
        let storage_delay = Duration::from_millis(2);
        let storage = MockStorage::new(Some(storage_delay), preprocessor_cache_mode);
        let storage: Arc<MockStorage> = Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage.clone(), pool.clone());
        // Pretend to be GCC.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        // The preprocessor invocation.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
        );
        // The compiler invocation.
        const COMPILER_STDOUT: &[u8] = b"compiler stdout";
        const COMPILER_STDERR: &[u8] = b"compiler stderr";
        let obj_file: &[u8] = &[1, 2, 3, 4];
        // A cache entry to hand out
        let mut cachewrite = CacheWrite::new();
        cachewrite
            .put_stdout(COMPILER_STDOUT)
            .expect("Failed to store stdout");
        cachewrite
            .put_stderr(COMPILER_STDERR)
            .expect("Failed to store stderr");
        cachewrite
            .put_object("obj", &mut Cursor::new(obj_file), None)
            .expect("Failed to store cache object");
        let entry = cachewrite.finish().expect("Failed to finish cache entry");
        let entry = CacheRead::from(Cursor::new(entry)).expect("Failed to re-read cache entry");

        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        storage.next_get(Ok(Cache::Hit(entry)));
        let (cached, _res) = runtime
            .block_on(hasher.get_cached_or_compile(
                &service,
                None,
                creator,
                storage,
                arguments.clone(),
                cwd.to_path_buf(),
                vec![],
                CacheControl::Default,
                pool,
            ))
            .unwrap();
        match cached {
            CompileResult::CacheHit(duration) => {
                assert!(duration >= storage_delay);
            }
            _ => panic!("Unexpected compile result: {:?}", cached),
        }
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_compiler_get_cached_or_compile_force_recache(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let storage = DiskCache::new(
            f.tempdir.path().join("cache"),
            u64::MAX,
            &pool,
            PreprocessorCacheModeConfig {
                use_preprocessor_cache_mode: preprocessor_cache_mode,
                ..Default::default()
            },
            CacheMode::ReadWrite,
        );
        let storage = Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage.clone(), pool.clone());
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        // Pretend to be GCC.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        const COMPILER_STDOUT: &[u8] = b"compiler stdout";
        const COMPILER_STDERR: &[u8] = b"compiler stderr";
        // The compiler should be invoked twice, since we're forcing
        // recaching.
        let obj = f.tempdir.path().join("foo.o");
        for _ in 0..2 {
            // The preprocessor invocation.
            next_command(
                &creator,
                Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
            );
            // The compiler invocation.
            let o = obj.clone();
            next_command_calls(&creator, move |_| {
                // Pretend to compile something.
                let mut f = File::create(&o)?;
                f.write_all(b"file contents")?;
                Ok(MockChild::new(
                    exit_status(0),
                    COMPILER_STDOUT,
                    COMPILER_STDERR,
                ))
            });
        }
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let hasher2 = hasher.clone();
        let (cached, res) = runtime
            .block_on(async {
                hasher
                    .get_cached_or_compile(
                        &service,
                        None,
                        creator.clone(),
                        storage.clone(),
                        arguments.clone(),
                        cwd.to_path_buf(),
                        vec![],
                        CacheControl::Default,
                        pool.clone(),
                    )
                    .await
            })
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::Normal, DistType::NoDist, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => panic!("Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, but force recaching.
        fs::remove_file(&obj).unwrap();
        let (cached, res) = hasher2
            .get_cached_or_compile(
                &service,
                None,
                creator,
                storage,
                arguments,
                cwd.to_path_buf(),
                vec![],
                CacheControl::ForceRecache,
                pool,
            )
            .wait()
            .unwrap();
        // Ensure that the object file was created.
        assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::ForcedRecache, DistType::NoDist, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => panic!("Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_compiler_get_cached_or_compile_preprocessor_error(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let storage = DiskCache::new(
            f.tempdir.path().join("cache"),
            u64::MAX,
            &pool,
            PreprocessorCacheModeConfig {
                use_preprocessor_cache_mode: preprocessor_cache_mode,
                ..Default::default()
            },
            CacheMode::ReadWrite,
        );
        let storage = Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage.clone(), pool.clone());

        // Pretend to be GCC.  Also inject a fake object file that the subsequent
        // preprocessor failure should remove.
        let obj = f.tempdir.path().join("foo.o");
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        let o = obj.clone();
        next_command_calls(&creator, move |_| {
            let mut f = File::create(&o)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", ""))
        });
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        // We should now have a fake object file.
        assert!(fs::metadata(&obj).is_ok());
        // The preprocessor invocation.
        const PREPROCESSOR_STDERR: &[u8] = b"something went wrong";
        next_command(
            &creator,
            Ok(MockChild::new(
                exit_status(1),
                b"preprocessor output",
                PREPROCESSOR_STDERR,
            )),
        );
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = runtime
            .block_on(async {
                hasher
                    .get_cached_or_compile(
                        &service,
                        None,
                        creator,
                        storage,
                        arguments,
                        cwd.to_path_buf(),
                        vec![],
                        CacheControl::Default,
                        pool,
                    )
                    .await
            })
            .unwrap();
        assert_eq!(cached, CompileResult::Error);
        assert_eq!(exit_status(1), res.status);
        // Shouldn't get anything on stdout, since that would just be preprocessor spew!
        assert_eq!(b"", res.stdout.as_slice());
        assert_eq!(PREPROCESSOR_STDERR, res.stderr.as_slice());
        // Errors in preprocessing should remove the object file.
        assert!(fs::metadata(&obj).is_err());
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    #[cfg(feature = "dist-client")]
    fn test_compiler_get_cached_or_compile_dist_error(preprocessor_cache_mode: bool) {
        drop(env_logger::try_init());
        let creator = new_creator();
        let f = TestFixture::new();
        let gcc = f.mk_bin("gcc").unwrap();
        let runtime = Runtime::new().unwrap();
        let pool = runtime.handle().clone();
        let dist_clients = vec![
            test_dist::ErrorPutToolchainClient::new(),
            test_dist::ErrorAllocJobClient::new(),
            test_dist::ErrorSubmitToolchainClient::new(),
            test_dist::ErrorRunJobClient::new(),
        ];
        // Write a dummy input file so the preprocessor cache mode can work
        std::fs::write(f.tempdir.path().join("foo.c"), "whatever").unwrap();
        let storage = DiskCache::new(
            f.tempdir.path().join("cache"),
            u64::MAX,
            &pool,
            PreprocessorCacheModeConfig {
                use_preprocessor_cache_mode: preprocessor_cache_mode,
                ..Default::default()
            },
            CacheMode::ReadWrite,
        );
        let storage = Arc::new(storage);
        // Pretend to be GCC.
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")),
        );
        let c = get_compiler_info(
            creator.clone(),
            &gcc,
            f.tempdir.path(),
            &[],
            &[],
            &pool,
            None,
        )
        .wait()
        .unwrap()
        .0;
        const COMPILER_STDOUT: &[u8] = b"compiler stdout";
        const COMPILER_STDERR: &[u8] = b"compiler stderr";
        // The compiler should be invoked twice, since we're forcing
        // recaching.
        let obj = f.tempdir.path().join("foo.o");
        for _ in dist_clients.iter() {
            // The preprocessor invocation.
            next_command(
                &creator,
                Ok(MockChild::new(exit_status(0), "preprocessor output", "")),
            );
            // The compiler invocation.
            let o = obj.clone();
            next_command_calls(&creator, move |_| {
                // Pretend to compile something.
                let mut f = File::create(&o)?;
                f.write_all(b"file contents")?;
                Ok(MockChild::new(
                    exit_status(0),
                    COMPILER_STDOUT,
                    COMPILER_STDERR,
                ))
            });
        }
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref(), &[]) {
            CompilerArguments::Ok(h) => h,
            o => panic!("Bad result from parse_arguments: {:?}", o),
        };
        // All these dist clients will fail, but should still result in successful compiles
        for dist_client in dist_clients {
            let service = server::SccacheService::mock_with_dist_client(
                dist_client.clone(),
                storage.clone(),
                pool.clone(),
            );

            if obj.is_file() {
                fs::remove_file(&obj).unwrap();
            }
            let hasher = hasher.clone();
            let (cached, res) = hasher
                .get_cached_or_compile(
                    &service,
                    Some(dist_client.clone()),
                    creator.clone(),
                    storage.clone(),
                    arguments.clone(),
                    cwd.to_path_buf(),
                    vec![],
                    CacheControl::ForceRecache,
                    pool.clone(),
                )
                .wait()
                .expect("Does not error if storage put fails. qed");
            // Ensure that the object file was created.
            assert!(fs::metadata(&obj).map(|m| m.len() > 0).unwrap());
            match cached {
                CompileResult::CacheMiss(MissType::ForcedRecache, DistType::Error, _, f) => {
                    // wait on cache write future so we don't race with it!
                    f.wait().unwrap();
                }
                _ => panic!("Unexpected compile result: {:?}", cached),
            }
            assert_eq!(exit_status(0), res.status);
            assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
            assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        }
    }
}

#[cfg(test)]
#[cfg(feature = "dist-client")]
mod test_dist {
    use crate::dist::pkg;
    use crate::dist::{
        self, AllocJobResult, CompileCommand, JobAlloc, JobComplete, JobId, OutputData,
        PathTransformer, ProcessOutput, RunJobResult, SchedulerStatusResult, ServerId,
        SubmitToolchainResult, Toolchain,
    };
    use async_trait::async_trait;
    use std::path::{Path, PathBuf};
    use std::sync::{atomic::AtomicBool, Arc};

    use crate::errors::*;

    pub struct ErrorPutToolchainClient;
    impl ErrorPutToolchainClient {
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> Arc<dyn dist::Client> {
            Arc::new(ErrorPutToolchainClient)
        }
    }
    #[async_trait]
    impl dist::Client for ErrorPutToolchainClient {
        async fn do_alloc_job(&self, _: Toolchain) -> Result<AllocJobResult> {
            unreachable!()
        }
        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            unreachable!()
        }
        async fn do_submit_toolchain(
            &self,
            _: JobAlloc,
            _: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            unreachable!()
        }
        async fn do_run_job(
            &self,
            _: JobAlloc,
            _: CompileCommand,
            _: Vec<String>,
            _: Box<dyn pkg::InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            unreachable!()
        }
        async fn put_toolchain(
            &self,
            _: PathBuf,
            _: String,
            _: Box<dyn pkg::ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            Err(anyhow!("MOCK: put toolchain failure"))
        }
        fn rewrite_includes_only(&self) -> bool {
            false
        }
        fn get_custom_toolchain(&self, _exe: &Path) -> Option<PathBuf> {
            None
        }
    }

    pub struct ErrorAllocJobClient {
        tc: Toolchain,
    }
    impl ErrorAllocJobClient {
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> Arc<dyn dist::Client> {
            Arc::new(Self {
                tc: Toolchain {
                    archive_id: "somearchiveid".to_owned(),
                },
            })
        }
    }
    #[async_trait]
    impl dist::Client for ErrorAllocJobClient {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            assert_eq!(self.tc, tc);
            Err(anyhow!("MOCK: alloc job failure"))
        }
        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            unreachable!()
        }
        async fn do_submit_toolchain(
            &self,
            _: JobAlloc,
            _: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            unreachable!()
        }
        async fn do_run_job(
            &self,
            _: JobAlloc,
            _: CompileCommand,
            _: Vec<String>,
            _: Box<dyn pkg::InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            unreachable!()
        }
        async fn put_toolchain(
            &self,
            _: PathBuf,
            _: String,
            _: Box<dyn pkg::ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            Ok((self.tc.clone(), None))
        }
        fn rewrite_includes_only(&self) -> bool {
            false
        }
        fn get_custom_toolchain(&self, _exe: &Path) -> Option<PathBuf> {
            None
        }
    }

    pub struct ErrorSubmitToolchainClient {
        has_started: AtomicBool,
        tc: Toolchain,
    }
    impl ErrorSubmitToolchainClient {
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> Arc<dyn dist::Client> {
            Arc::new(Self {
                has_started: AtomicBool::default(),
                tc: Toolchain {
                    archive_id: "somearchiveid".to_owned(),
                },
            })
        }
    }

    #[async_trait]
    impl dist::Client for ErrorSubmitToolchainClient {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            assert!(!self
                .has_started
                .swap(true, std::sync::atomic::Ordering::AcqRel));
            assert_eq!(self.tc, tc);
            Ok(AllocJobResult::Success {
                job_alloc: JobAlloc {
                    auth: "abcd".to_owned(),
                    job_id: JobId(0),
                    server_id: ServerId::new(([0, 0, 0, 0], 1).into()),
                },
                need_toolchain: true,
            })
        }
        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            unreachable!("fn do_get_status is not used for this test. qed")
        }
        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            assert_eq!(job_alloc.job_id, JobId(0));
            assert_eq!(self.tc, tc);
            Err(anyhow!("MOCK: submit toolchain failure"))
        }
        async fn do_run_job(
            &self,
            _: JobAlloc,
            _: CompileCommand,
            _: Vec<String>,
            _: Box<dyn pkg::InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            unreachable!("fn do_run_job is not used for this test. qed")
        }
        async fn put_toolchain(
            &self,
            _: PathBuf,
            _: String,
            _: Box<dyn pkg::ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            Ok((self.tc.clone(), None))
        }
        fn rewrite_includes_only(&self) -> bool {
            false
        }
        fn get_custom_toolchain(&self, _exe: &Path) -> Option<PathBuf> {
            None
        }
    }

    pub struct ErrorRunJobClient {
        has_started: AtomicBool,
        tc: Toolchain,
    }
    impl ErrorRunJobClient {
        #[allow(clippy::new_ret_no_self)]
        pub fn new() -> Arc<dyn dist::Client> {
            Arc::new(Self {
                has_started: AtomicBool::default(),
                tc: Toolchain {
                    archive_id: "somearchiveid".to_owned(),
                },
            })
        }
    }

    #[async_trait]
    impl dist::Client for ErrorRunJobClient {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            assert!(!self
                .has_started
                .swap(true, std::sync::atomic::Ordering::AcqRel));
            assert_eq!(self.tc, tc);
            Ok(AllocJobResult::Success {
                job_alloc: JobAlloc {
                    auth: "abcd".to_owned(),
                    job_id: JobId(0),
                    server_id: ServerId::new(([0, 0, 0, 0], 1).into()),
                },
                need_toolchain: true,
            })
        }
        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            unreachable!()
        }
        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            assert_eq!(job_alloc.job_id, JobId(0));
            assert_eq!(self.tc, tc);
            Ok(SubmitToolchainResult::Success)
        }
        async fn do_run_job(
            &self,
            job_alloc: JobAlloc,
            command: CompileCommand,
            _: Vec<String>,
            _: Box<dyn pkg::InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            assert_eq!(job_alloc.job_id, JobId(0));
            assert_eq!(command.executable, "/overridden/compiler");
            Err(anyhow!("MOCK: run job failure"))
        }
        async fn put_toolchain(
            &self,
            _: PathBuf,
            _: String,
            _: Box<dyn pkg::ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            Ok((
                self.tc.clone(),
                Some((
                    "/overridden/compiler".to_owned(),
                    PathBuf::from("somearchiveid"),
                )),
            ))
        }
        fn rewrite_includes_only(&self) -> bool {
            false
        }
        fn get_custom_toolchain(&self, _exe: &Path) -> Option<PathBuf> {
            None
        }
    }

    pub struct OneshotClient {
        has_started: AtomicBool,
        tc: Toolchain,
        output: ProcessOutput,
    }

    impl OneshotClient {
        #[allow(clippy::new_ret_no_self)]
        pub fn new(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Arc<dyn dist::Client> {
            Arc::new(Self {
                has_started: AtomicBool::default(),
                tc: Toolchain {
                    archive_id: "somearchiveid".to_owned(),
                },
                output: ProcessOutput::fake_output(code, stdout, stderr),
            })
        }
    }

    #[async_trait]
    impl dist::Client for OneshotClient {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            assert!(!self
                .has_started
                .swap(true, std::sync::atomic::Ordering::AcqRel));
            assert_eq!(self.tc, tc);

            Ok(AllocJobResult::Success {
                job_alloc: JobAlloc {
                    auth: "abcd".to_owned(),
                    job_id: JobId(0),
                    server_id: ServerId::new(([0, 0, 0, 0], 1).into()),
                },
                need_toolchain: true,
            })
        }
        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            unreachable!("fn do_get_status is not used for this test. qed")
        }
        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            assert_eq!(job_alloc.job_id, JobId(0));
            assert_eq!(self.tc, tc);

            Ok(SubmitToolchainResult::Success)
        }
        async fn do_run_job(
            &self,
            job_alloc: JobAlloc,
            command: CompileCommand,
            outputs: Vec<String>,
            inputs_packager: Box<dyn pkg::InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            assert_eq!(job_alloc.job_id, JobId(0));
            assert_eq!(command.executable, "/overridden/compiler");

            let mut inputs = vec![];
            let path_transformer = inputs_packager.write_inputs(&mut inputs).unwrap();
            let outputs = outputs
                .into_iter()
                .map(|name| {
                    let data = format!("some data in {}", name);
                    let data = OutputData::try_from_reader(data.as_bytes()).unwrap();
                    (name, data)
                })
                .collect();
            let result = RunJobResult::Complete(JobComplete {
                output: self.output.clone(),
                outputs,
            });
            Ok((result, path_transformer))
        }
        async fn put_toolchain(
            &self,
            _: PathBuf,
            _: String,
            _: Box<dyn pkg::ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            Ok((
                self.tc.clone(),
                Some((
                    "/overridden/compiler".to_owned(),
                    PathBuf::from("somearchiveid"),
                )),
            ))
        }
        fn rewrite_includes_only(&self) -> bool {
            false
        }
        fn get_custom_toolchain(&self, _exe: &Path) -> Option<PathBuf> {
            None
        }
    }
}
