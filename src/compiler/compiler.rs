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

use cache::{
    Cache,
    Storage,
};
use compiler::msvc;
use compiler::c::{CCompiler, CCompilerKind};
use compiler::clang::Clang;
use compiler::gcc::GCC;
use compiler::msvc::MSVC;
use compiler::rust::Rust;
use filetime::FileTime;
use futures::future;
use futures::{Future, IntoFuture};
use futures_cpupool::CpuPool;
use log::LogLevel::Debug;
use mock_command::{
    CommandChild,
    CommandCreatorSync,
    RunCommand,
    exit_status,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self,File};
use std::io::prelude::*;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self,Stdio};
use std::str;
use std::sync::Arc;
use std::time::{
    Duration,
    Instant,
};
use tempdir::TempDir;
use util::{fmt_duration_as_secs, sha1_digest};

use errors::*;

/// Supported compilers.
#[derive(Debug, PartialEq, Clone)]
pub enum CompilerKind {
    /// A C compiler.
    C(CCompilerKind),
    /// A Rust compiler.
    Rust,
}

/// An interface to a compiler for argument parsing.
pub trait Compiler<T>: Send + 'static
    where T: CommandCreatorSync,
{
    /// Return the kind of compiler.
    fn kind(&self) -> CompilerKind;
    /// Determine whether `arguments` are supported by this compiler.
    fn parse_arguments(&self,
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments<Box<CompilerHasher<T> + 'static>>;
    fn box_clone(&self) -> Box<Compiler<T>>;
}

impl<T: CommandCreatorSync> Clone for Box<Compiler<T>> {
    fn clone(&self) -> Box<Compiler<T>> { self.box_clone() }
}

/// An interface to a compiler for hash key generation, the result of
/// argument parsing.
pub trait CompilerHasher<T>: fmt::Debug + Send + 'static
    where T: CommandCreatorSync,
{
    /// Given information about a compiler command, generate a hash key
    /// that can be used for cache lookups, as well as any additional
    /// information that can be reused for compilation if necessary.
    fn generate_hash_key(self: Box<Self>,
                         creator: &T,
                         executable: &str,
                         executable_digest: &str,
                         cwd: &str,
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>;
    /// Get the output file of the compilation.
    fn output_file(&self) -> Cow<str>;
    fn box_clone(&self) -> Box<CompilerHasher<T>>;
}

impl<T: CommandCreatorSync> Clone for Box<CompilerHasher<T>> {
    fn clone(&self) -> Box<CompilerHasher<T>> { self.box_clone() }
}

/// An interface to a compiler for actually invoking compilation.
pub trait Compilation<T>
    where T: CommandCreatorSync,
{
    /// Given information about a compiler command, execute the compiler.
    fn compile(self: Box<Self>,
               creator: &T,
               executable: &str,
               cwd: &str,
               pool: &CpuPool)
               -> SFuture<(Cacheable, process::Output)>;
    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a String)> + 'a>;
}

/// Result of generating a hash from a compiler command.
pub enum HashResult<T: CommandCreatorSync> {
    /// Successful.
    Ok {
        /// The hash key of the inputs.
        key: String,
        /// An object to use for the actual compilation, if necessary.
        compilation: Box<Compilation<T> + 'static>,
    },
    /// Something failed.
    Error {
        /// The error output and return code.
        output: process::Output,
    },
}

/// Possible results of parsing compiler arguments.
#[derive(Debug, PartialEq)]
pub enum CompilerArguments<T>
{
    /// Commandline can be handled.
    Ok(T),
    /// Cannot cache this compilation.
    CannotCache,
    /// This commandline is not a compile.
    NotCompilation,
}

/// Information about a compiler.
#[derive(Clone)]
pub struct CompilerInfo<T: CommandCreatorSync> {
    /// The path to the compiler binary.
    pub executable: String,
    /// The last modified time of `executable`.
    pub mtime: FileTime,
    /// The sha-1 digest of `executable`, as a hex string.
    pub digest: String,
    /// The actual compiler implementation.
    pub compiler: Box<Compiler<T>>,
}

/// Specifics about cache misses.
#[derive(Debug, PartialEq)]
pub enum MissType {
    /// The compilation was not found in the cache, nothing more.
    Normal,
    /// Cache lookup was overridden, recompilation was forced.
    ForcedRecache,
}

/// Information about a successful cache write.
pub struct CacheWriteInfo {
    pub object_file: String,
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
    CacheMiss(MissType, Duration, SFuture<CacheWriteInfo>),
    /// Not in cache, but the compilation result was determined to be not cacheable.
    NotCacheable,
    /// Not in cache, but compilation failed.
    CompileFailed,
}


/// Can't derive(Debug) because of `CacheWriteFuture`.
impl fmt::Debug for CompileResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CompileResult::Error => write!(f, "CompileResult::Error"),
            &CompileResult::CacheHit(ref d) => write!(f, "CompileResult::CacheHit({:?})", d),
            &CompileResult::CacheMiss(ref m, ref d, _) => write!(f, "CompileResult::CacheMiss({:?}, {:?}, _)", d, m),
            &CompileResult::NotCacheable => write!(f, "CompileResult::NotCacheable"),
            &CompileResult::CompileFailed => write!(f, "CompileResult::CompileFailed"),
        }
    }
}

/// Can't use derive(PartialEq) because of the `CacheWriteFuture`.
impl PartialEq<CompileResult> for CompileResult {
    fn eq(&self, other: &CompileResult) -> bool {
        match (self, other) {
            (&CompileResult::Error, &CompileResult::Error) => true,
            (&CompileResult::CacheHit(_), &CompileResult::CacheHit(_)) => true,
            (&CompileResult::CacheMiss(ref m, _, _), &CompileResult::CacheMiss(ref n, _, _)) => m == n,
            (&CompileResult::NotCacheable, &CompileResult::NotCacheable) => true,
            (&CompileResult::CompileFailed, &CompileResult::CompileFailed) => true,
            _ => false,
        }
    }
}

#[cfg(unix)]
fn get_file_mode(path: &Path) -> Result<Option<u32>>
{
    use std::os::unix::fs::MetadataExt;
    Ok(Some(fs::metadata(path)?.mode()))
}

#[cfg(windows)]
fn get_file_mode(_path: &Path) -> Result<Option<u32>>
{
    Ok(None)
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()>
{
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let p = Permissions::from_mode(mode);
    fs::set_permissions(path, p)?;
    Ok(())
}

#[cfg(windows)]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()>
{
    Ok(())
}

/// Can this result be stored in cache?
#[derive(Debug, PartialEq)]
pub enum Cacheable {
    Yes,
    No,
}

/// Control of caching behavior.
#[derive(Debug, PartialEq)]
pub enum CacheControl {
    /// Default caching behavior.
    Default,
    /// Ignore existing cache entries, force recompilation.
    ForceRecache,
}

impl<T: CommandCreatorSync> CompilerInfo<T> {
    /// Create a new `CompilerInfo` with `compiler`, `executable` as the binary,
    /// and `digest` being the SHA-1 digest of `executable` as a hex string.
    pub fn new(executable: String, digest: String, compiler: Box<Compiler<T>>) -> Result<CompilerInfo<T>> {
        let attr = fs::metadata(&executable)?;
        Ok(CompilerInfo {
            executable: executable,
            mtime: FileTime::from_last_modification_time(&attr),
            digest: digest,
            compiler: compiler,
        })
    }

    /// Check that this compiler can handle and cache when run with `arguments`, and parse out the relevant bits.
    ///
    /// Not all compiler options can be cached, so this tests the set of
    /// options for each compiler.
    pub fn parse_arguments(&self,
                           arguments: &[String],
                           cwd: &Path) -> CompilerArguments<Box<CompilerHasher<T> + 'static>> {
        if log_enabled!(Debug) {
            let cmd_str = arguments.join(" ");
            debug!("parse_arguments: `{}`", cmd_str);
        }
        self.compiler.parse_arguments(arguments, cwd)
    }

    /// Look up a cached compile result in `storage`. If not found, run the
    /// compile and store the result.
    pub fn get_cached_or_compile(self,
                                 creator: T,
                                 storage: Arc<Storage>,
                                 arguments: Vec<String>,
                                 hasher: Box<CompilerHasher<T> + 'static>,
                                 cwd: String,
                                 cache_control: CacheControl,
                                 pool: CpuPool)
                                 -> SFuture<(CompileResult, process::Output)>
    {
        let CompilerInfo { executable, digest, .. } = self;
        let out_file = hasher.output_file().into_owned();
        if log_enabled!(Debug) {
            let cmd_str = arguments.join(" ");
            debug!("[{}]: get_cached_or_compile: {}", out_file, cmd_str);
        }
        let start = Instant::now();
        let result = hasher.generate_hash_key(&creator, &executable, &digest, &cwd, &pool);
        Box::new(result.and_then(move |hash_res| -> SFuture<_> {
            debug!("[{}]: generate_hash_key took {}", out_file, fmt_duration_as_secs(&start.elapsed()));
            let (key, compilation) = match hash_res {
                HashResult::Error { output } => {
                    return Box::new(future::ok((CompileResult::Error, output)));
                }
                HashResult::Ok { key, compilation } => (key, compilation),
            };
            trace!("[{}]: Hash key: {}", out_file, key);
            // If `ForceRecache` is enabled, we won't check the cache.
            let start = Instant::now();
            let cache_status = if cache_control == CacheControl::ForceRecache {
                Box::new(future::ok(Cache::Recache))
            } else {
                storage.get(&key)
            };

            // Check the result of the cache lookup.
            Box::new(cache_status.and_then(move |result| {
                let duration = start.elapsed();
                let pwd = Path::new(&cwd);
                let outputs = compilation.outputs()
                    .map(|(key, path)| (key.to_string(), pwd.join(path)))
                    .collect::<HashMap<_, _>>();

                let miss_type = match result {
                    Cache::Hit(mut entry) => {
                        debug!("[{}]: Cache hit in {}", out_file, fmt_duration_as_secs(&duration));
                        let mut stdout = io::Cursor::new(vec!());
                        let mut stderr = io::Cursor::new(vec!());
                        drop(entry.get_object("stdout", &mut stdout));
                        drop(entry.get_object("stderr", &mut stderr));
                        let write = pool.spawn_fn(move ||{
                            for (key, path) in &outputs {
                                let mut f = File::create(&path)?;
                                let mode = entry.get_object(&key, &mut f)?;
                                if let Some(mode) = mode {
                                    set_file_mode(&path, mode)?;
                                }
                            }
                            Ok(())
                        });
                        let output = process::Output {
                            status: exit_status(0),
                            stdout: stdout.into_inner(),
                            stderr: stderr.into_inner(),
                        };
                        let result = CompileResult::CacheHit(duration);
                        return Box::new(write.map(|_| {
                            (result, output)
                        })) as SFuture<_>
                    }
                    Cache::Miss => {
                        debug!("[{}]: Cache miss", out_file);
                        MissType::Normal
                    }
                    Cache::Recache => {
                        debug!("[{}]: Cache recache", out_file);
                        MissType::ForcedRecache
                    }
                };

                // Cache miss, so compile it.
                let start = Instant::now();
                let out_file = out_file.clone();
                let compile = compilation.compile(&creator, &executable, &cwd, &pool);
                Box::new(compile.and_then(move |(cacheable, compiler_result)| {
                    let duration = start.elapsed();
                    if !compiler_result.status.success() {
                        debug!("[{}]: Compiled but failed, not storing in cache",
                               out_file);
                        return Box::new(future::ok((CompileResult::CompileFailed, compiler_result)))
                            as SFuture<_>
                    }
                    if cacheable != Cacheable::Yes {
                        // Not cacheable
                        debug!("[{}]: Compiled but not cacheable",
                               out_file);
                        return Box::new(future::ok((CompileResult::NotCacheable, compiler_result)))
                    }
                    debug!("[{}]: Compiled in {}, storing in cache", out_file, fmt_duration_as_secs(&duration));
                    let mut entry = match storage.start_put(&key) {
                        Ok(entry) => entry,
                        Err(e) => return Box::new(future::err(e))
                    };
                    let write = pool.spawn_fn(move || -> Result<_> {
                        for (key, path) in &outputs {
                            let mut f = File::open(&path)?;
                            let mode = get_file_mode(&path)?;
                            entry.put_object(key, &mut f, mode).chain_err(|| {
                                format!("failed to put object `{:?}` in zip", path)
                            })?;
                        }
                        Ok(entry)
                    });
                    let write = write.chain_err(|| "failed to zip up compiler outputs");
                    let o = out_file.clone();
                    Box::new(write.and_then(move |mut entry| {
                        if !compiler_result.stdout.is_empty() {
                            let mut stdout = &compiler_result.stdout[..];
                            entry.put_object("stdout", &mut stdout, None)?;
                        }
                        if !compiler_result.stderr.is_empty() {
                            let mut stderr = &compiler_result.stderr[..];
                            entry.put_object("stderr", &mut stderr, None)?;
                        }

                        // Try to finish storing the newly-written cache
                        // entry. We'll get the result back elsewhere.
                        let out_file = out_file.clone();
                        let future = storage.finish_put(&key, entry)
                            .then(move |res| {
                                match res {
                                    Ok(_) => debug!("[{}]: Stored in cache successfully!", out_file),
                                    Err(ref e) => debug!("[{}]: Cache write error: {:?}", out_file, e),
                                }
                                res.map(|duration| CacheWriteInfo {
                                    object_file: out_file,
                                    duration: duration,
                                })
                            });
                        let future = Box::new(future);
                        Ok((CompileResult::CacheMiss(miss_type, duration, future), compiler_result))
                    }).chain_err(move || {
                        format!("failed to store `{}` to cache", o)
                    }))
                }))
            }))
        }))
    }
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
pub fn write_temp_file(pool: &CpuPool, path: &Path, contents: Vec<u8>)
                       -> SFuture<(TempDir, PathBuf)> {
    let path = path.to_owned();
    pool.spawn_fn(move || -> Result<_> {
        let dir = TempDir::new("sccache")?;
        let src = dir.path().join(path);
        let mut file = File::create(&src)?;
        file.write_all(&contents)?;
        Ok((dir, src))
    }).chain_err(|| {
        "failed to write temporary file"
    })
}

/// If `executable` is a known compiler, return `Some(Box<Compiler>)`.
fn detect_compiler<T>(creator: &T, executable: &str, pool: &CpuPool)
                      -> SFuture<Option<Box<Compiler<T>>>>
    where T: CommandCreatorSync
{
    trace!("detect_compiler");

    // First, see if this looks like rustc.
    let p = Path::new(executable);
    let filename = match p.file_stem() {
        None => return future::err("could not determine compiler kind".into()).boxed(),
        Some(f) => f,
    };
    let is_rustc = if filename.to_string_lossy().to_lowercase() == "rustc" {
        // Sanity check that it's really rustc.
        let child = creator.clone().new_command_sync(&executable)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .args(&["--version"])
            .spawn().chain_err(|| {
                format!("failed to execute {:?}", executable)
            });
        let output = child.into_future().and_then(move |child| {
            child.wait_with_output()
                .chain_err(|| "failed to read child output")
        });
        Box::new(output.map(|output| {
            if output.status.success() {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    if stdout.starts_with("rustc ") {
                        return true;
                    }
                }
            }
            false
        }))
    } else {
        Box::new(future::ok(false)) as SFuture<_>
    };

    let creator = creator.clone();
    let executable = executable.to_owned();
    let pool = pool.clone();
    Box::new(is_rustc.and_then(move |is_rustc| {
        if is_rustc {
            debug!("Found rustc");
            Box::new(future::ok(Some(Box::new(Rust) as Box<Compiler<T>>)))
        } else {
            detect_c_compiler(creator, executable, pool)
        }
    }))
}

fn detect_c_compiler<T>(creator: T, executable: String, pool: CpuPool)
                        -> SFuture<Option<Box<Compiler<T>>>>
    where T: CommandCreatorSync
{
    trace!("detect_c_compiler");

    let test = b"#if defined(_MSC_VER)
msvc
#elif defined(__clang__)
clang
#elif defined(__GNUC__)
gcc
#endif
".to_vec();
    let write = write_temp_file(&pool, "testfile.c".as_ref(), test);

    let mut cmd = creator.clone().new_command_sync(&executable);
    cmd.stdout(Stdio::piped())
       .stderr(Stdio::null());
    let output = write.and_then(move |(tempdir, src)| {
        let args = vec!(OsString::from("-E"), OsString::from(&src));
        trace!("compiler {:?}", cmd);
        let child = cmd.args(&args).spawn().chain_err(|| {
            format!("failed to execute {:?}", cmd)
        });
        child.into_future().and_then(|child| {
            child.wait_with_output().chain_err(|| "failed to read child output")
        }).map(|e| {
            drop(tempdir);
            e
        })
    });

    Box::new(output.and_then(move |output| -> SFuture<_> {
        let stdout = match str::from_utf8(&output.stdout) {
            Ok(s) => s,
            Err(_) => return future::err("Failed to parse output".into()).boxed(),
        };
        for line in stdout.lines() {
            //TODO: do something smarter here.
            if line == "gcc" {
                debug!("Found GCC");
                return future::ok(Some(Box::new(CCompiler(GCC)) as Box<Compiler<T>>)).boxed()
            } else if line == "clang" {
                debug!("Found clang");
                return future::ok(Some(Box::new(CCompiler(Clang)) as Box<Compiler<T>>)).boxed()
            } else if line == "msvc" {
                debug!("Found MSVC");
                let prefix = msvc::detect_showincludes_prefix(&creator,
                                                              executable.as_ref(),
                                                              &pool);
                return Box::new(prefix.map(|prefix| {
                    trace!("showIncludes prefix: '{}'", prefix);
                    Some(Box::new(CCompiler(MSVC {
                        includes_prefix: prefix,
                    })) as Box<Compiler<T>>)
                }))
            }
        }
        future::ok(None).boxed()
    }))
}

/// If `executable` is a known compiler, return a `CompilerInfo` containing information about it.
pub fn get_compiler_info<T>(creator: &T, executable: &str, pool: &CpuPool)
                            -> SFuture<CompilerInfo<T>>
    where T: CommandCreatorSync
{
    let executable = executable.to_string();
    let pool = pool.clone();
    let detect = detect_compiler(creator, &executable, &pool);
    Box::new(detect.and_then(move |compiler| {
        match compiler {
            Some(compiler) => {
                Box::new(sha1_digest(executable.clone(), &pool)
                         .and_then(move |digest| -> Result<_> {
                             CompilerInfo::new(executable, digest, compiler)
                         })) as SFuture<_>
            }
            None => Box::new(future::err("could not determine compiler kind".into())) as SFuture<_>,
        }
    }))
}

/// If `input`, write it to `child`'s stdin while also reading `child`'s stdout and stderr, then wait on `child` and return its status and output.
///
/// This was lifted from `std::process::Child::wait_with_output` and modified
/// to also write to stdin.
pub fn wait_with_input_output<T>(mut child: T, input: Option<Vec<u8>>)
                                 -> SFuture<process::Output>
    where T: CommandChild + 'static,
{
    use tokio_core::io::{write_all, read_to_end};
    let stdin = input.and_then(|i| {
        child.take_stdin().map(|stdin| {
            write_all(stdin, i)
        })
    }).chain_err(|| "failed to write stdin");
    let stdout = child.take_stdout().map(|io| read_to_end(io, Vec::new()));
    let stdout = stdout.chain_err(|| "failed to read stdout");
    let stderr = child.take_stderr().map(|io| read_to_end(io, Vec::new()));
    let stderr = stderr.chain_err(|| "failed to read stderr");

    // Finish writing stdin before waiting, because waiting drops stdin.
    let status = Future::and_then(stdin, |io| {
        drop(io);
        child.wait().chain_err(|| "failed to wait for child")
    });

    Box::new(status.join3(stdout, stderr).map(|(status, out, err)| {
        let stdout = out.map(|p| p.1);
        let stderr = err.map(|p| p.1);
        process::Output {
            status: status,
            stdout: stdout.unwrap_or_default(),
            stderr: stderr.unwrap_or_default(),
        }
    }))
}

/// Run `command`, writing `input` to its stdin if it is `Some` and return the exit status and output.
pub fn run_input_output<C>(mut command: C, input: Option<Vec<u8>>)
                           -> SFuture<process::Output>
    where C: RunCommand
{
    let child = command
        .no_console()
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::inherit() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .chain_err(|| "failed to spawn child");

    Box::new(future::result(child)
                .and_then(|child| wait_with_input_output(child, input)))
}

#[cfg(test)]
mod test {
    use super::*;
    use cache::Storage;
    use cache::disk::DiskCache;
    use futures::Future;
    use futures_cpupool::CpuPool;
    use mock_command::*;
    use std::fs::{self,File};
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;
    use std::usize;
    use test::utils::*;

    #[test]
    fn test_detect_compiler_kind_gcc() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nbar\ngcc", "")));
        let c = detect_compiler(&creator, "/foo/bar", &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::C(CCompilerKind::GCC), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_clang() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "clang\nfoo", "")));
        let c = detect_compiler(&creator, "/foo/bar", &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_msvc() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let srcfile = f.touch("stdio.h").unwrap();
        let mut s = srcfile.to_str().unwrap();
        if s.starts_with("\\\\?\\") {
            s = &s[4..];
        }
        let prefix = String::from("blah: ");
        let stdout = format!("{}{}\r\n", prefix, s);
        // Compiler detection output
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nmsvc\nbar", "")));
        // showincludes prefix detection output
        next_command(&creator, Ok(MockChild::new(exit_status(0), &stdout, &String::new())));
        let c = detect_compiler(&creator, "/foo/bar", &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::C(CCompilerKind::MSVC), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_rustc() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "rustc 1.15 (blah 2017-01-01)", "")));
        let c = detect_compiler(&creator, "/foo/rustc.exe", &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::Rust, c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_unknown() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "something", "")));
        assert!(detect_compiler(&creator, "/foo/bar", &pool).wait().unwrap().is_none());
    }

    #[test]
    fn test_detect_compiler_kind_process_fail() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert!(detect_compiler(&creator, "/foo/bar", &pool).wait().unwrap().is_none());
    }

    #[test]
    fn test_get_compiler_info() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  f.bins[0].to_str().unwrap(),
                                  &pool).wait().unwrap();
        assert_eq!(f.bins[0].to_str().unwrap(), c.executable);
        // sha-1 digest of an empty file.
        assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", c.digest);
        assert_eq!(CompilerKind::C(CCompilerKind::GCC), c.compiler.kind());
    }

    #[test]
    fn test_compiler_get_cached_or_compile_uncached() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  f.bins[0].to_str().unwrap(),
                                  &pool).wait().unwrap();
        // The preprocessor invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "preprocessor output", "")));
        // The compiler invocation.
        const COMPILER_STDOUT : &'static [u8] = b"compiler stdout";
        const COMPILER_STDERR : &'static [u8] = b"compiler stderr";
        let obj = f.tempdir.path().join("foo.o");
        let o = obj.clone();
        next_command_calls(&creator, move |_| {
            // Pretend to compile something.
            match File::create(&o)
                .and_then(|mut f| f.write_all(b"file contents")) {
                    Ok(_) => Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR)),
                    Err(e) => Err(e),
                }
        });
        let cwd = f.tempdir.path().to_str().unwrap().to_string();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let c2 = c.clone();
        let (cached, res) = c2.get_cached_or_compile(creator.clone(),
                                                     storage.clone(),
                                                     arguments.clone(),
                                                     parsed_args.clone(),
                                                     cwd.clone(),
                                                     CacheControl::Default,
                                                     pool.clone()).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::Normal, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => assert!(false, "Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, which should be a cache hit.
        fs::remove_file(&obj).unwrap();
        // The preprocessor invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "preprocessor output", "")));
        // There should be no actual compiler invocation.
        let (cached, res) = c.get_cached_or_compile(creator.clone(),
                                                    storage.clone(),
                                                    arguments,
                                                    parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    pool.clone()).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        assert_eq!(CompileResult::CacheHit(Duration::new(0, 0)), cached);
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test]
    fn test_compiler_get_cached_or_compile_cached() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  f.bins[0].to_str().unwrap(),
                                  &pool).wait().unwrap();
        // The preprocessor invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "preprocessor output", "")));
        // The compiler invocation.
        const COMPILER_STDOUT : &'static [u8] = b"compiler stdout";
        const COMPILER_STDERR : &'static [u8] = b"compiler stderr";
        let obj = f.tempdir.path().join("foo.o");
        let o = obj.clone();
        next_command_calls(&creator, move |_| {
            // Pretend to compile something.
            match File::create(&o)
                .and_then(|mut f| f.write_all(b"file contents")) {
                    Ok(_) => Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR)),
                    Err(e) => Err(e),
                }
        });
        let cwd = f.tempdir.path().to_str().unwrap().to_string();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let c2 = c.clone();
        let (cached, res) = c2.get_cached_or_compile(creator.clone(),
                                                     storage.clone(),
                                                     arguments.clone(),
                                                     parsed_args.clone(),
                                                     cwd.clone(),
                                                     CacheControl::Default,
                                                     pool.clone()).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::Normal, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => assert!(false, "Unexpected compile result: {:?}", cached),
        }

        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, which should be a cache hit.
        fs::remove_file(&obj).unwrap();
        // The preprocessor invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "preprocessor output", "")));
        // There should be no actual compiler invocation.
        let (cached, res) = c.get_cached_or_compile(creator,
                                                    storage,
                                                    arguments,
                                                    parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    pool).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        assert_eq!(CompileResult::CacheHit(Duration::new(0, 0)), cached);
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test]
    fn test_compiler_get_cached_or_compile_force_recache() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  f.bins[0].to_str().unwrap(),
                                  &pool).wait().unwrap();
        const COMPILER_STDOUT: &'static [u8] = b"compiler stdout";
        const COMPILER_STDERR: &'static [u8] = b"compiler stderr";
        // The compiler should be invoked twice, since we're forcing
        // recaching.
        let obj = f.tempdir.path().join("foo.o");
        for _ in 0..2 {
            // The preprocessor invocation.
            next_command(&creator, Ok(MockChild::new(exit_status(0), "preprocessor output", "")));
            // The compiler invocation.
            let o = obj.clone();
            next_command_calls(&creator, move |_| {
                // Pretend to compile something.
                match File::create(&o)
                    .and_then(|mut f| f.write_all(b"file contents")) {
                        Ok(_) => Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR)),
                        Err(e) => Err(e),
                    }
            });
        }
        let cwd = f.tempdir.path().to_str().unwrap().to_string();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let c2 = c.clone();
        let (cached, res) = c2.get_cached_or_compile(creator.clone(),
                                                     storage.clone(),
                                                     arguments.clone(),
                                                     parsed_args.clone(),
                                                     cwd.clone(),
                                                     CacheControl::Default,
                                                     pool.clone()).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::Normal, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => assert!(false, "Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, but force recaching.
        fs::remove_file(&obj).unwrap();
        let (cached, res) = c.get_cached_or_compile(creator,
                                                    storage,
                                                    arguments,
                                                    parsed_args,
                                                    cwd,
                                                    CacheControl::ForceRecache,
                                                    pool).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::ForcedRecache, _, f) => {
                // wait on cache write future so we don't race with it!
                f.wait().unwrap();
            }
            _ => assert!(false, "Unexpected compile result: {:?}", cached),
        }
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test]
    fn test_compiler_get_cached_or_compile_preprocessor_error() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  f.bins[0].to_str().unwrap(),
                                  &pool).wait().unwrap();
        // The preprocessor invocation.
        const PREPROCESSOR_STDERR: &'static [u8] = b"something went wrong";
        next_command(&creator, Ok(MockChild::new(exit_status(1), b"preprocessor output", PREPROCESSOR_STDERR)));
        let cwd = f.tempdir.path().to_str().unwrap().to_string();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(creator,
                                                    storage,
                                                    arguments,
                                                    parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    pool).wait().unwrap();
        assert_eq!(cached, CompileResult::Error);
        assert_eq!(exit_status(1), res.status);
        // Shouldn't get anything on stdout, since that would just be preprocessor spew!
        assert_eq!(b"", res.stdout.as_slice());
        assert_eq!(PREPROCESSOR_STDERR, res.stderr.as_slice());
    }
}
