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
    CacheWrite,
    Storage,
};
use compiler::msvc;
use compiler::c::{CCompiler, CCompilerKind};
use compiler::clang::Clang;
use compiler::gcc::GCC;
use compiler::msvc::MSVC;
use compiler::rust::Rust;
use futures::{Future, IntoFuture};
use futures_cpupool::CpuPool;
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
#[cfg(unix)]
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{self,Stdio};
use std::str;
use std::sync::Arc;
use std::time::{
    Duration,
    Instant,
};
use tempdir::TempDir;
use tempfile::NamedTempFile;
use util::fmt_duration_as_secs;
use tokio_core::reactor::{Handle, Timeout};

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
                       arguments: &[OsString],
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
                         cwd: &Path,
                         env_vars: &[(OsString, OsString)],
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>;

    /// Return the state of any `--color` option passed to the compiler.
    fn color_mode(&self) -> ColorMode;

    /// Look up a cached compile result in `storage`. If not found, run the
    /// compile and store the result.
    fn get_cached_or_compile(self: Box<Self>,
                             creator: T,
                             storage: Arc<Storage>,
                             arguments: Vec<OsString>,
                             cwd: PathBuf,
                             env_vars: Vec<(OsString, OsString)>,
                             cache_control: CacheControl,
                             pool: CpuPool,
                             handle: Handle)
                             -> SFuture<(CompileResult, process::Output)>
    {
        let out_pretty = self.output_pretty().into_owned();
        debug!("[{}]: get_cached_or_compile: {:?}", out_pretty, arguments);
        let start = Instant::now();
        let result = self.generate_hash_key(&creator, &cwd, &env_vars, &pool);
        Box::new(result.then(move |res| -> SFuture<_> {
            debug!("[{}]: generate_hash_key took {}", out_pretty, fmt_duration_as_secs(&start.elapsed()));
            let (key, compilation) = match res {
                Err(Error(ErrorKind::ProcessError(output), _)) => {
                    return f_ok((CompileResult::Error, output));
                }
                Err(e) => return f_err(e),
                Ok(HashResult { key, compilation }) => (key, compilation),
            };
            trace!("[{}]: Hash key: {}", out_pretty, key);
            // If `ForceRecache` is enabled, we won't check the cache.
            let start = Instant::now();
            let cache_status = if cache_control == CacheControl::ForceRecache {
                f_ok(Cache::Recache)
            } else {
                storage.get(&key)
            };

            // Set a maximum time limit for the cache to respond before we forge
            // ahead ourselves with a compilation.
            let timeout = Duration::new(60, 0);
            let timeout = Timeout::new(timeout, &handle).into_future().flatten();

            let cache_status = cache_status.map(Some);
            let timeout = timeout.map(|_| None).chain_err(|| "timeout error");
            let cache_status = cache_status.select(timeout).then(|r| {
                match r {
                    Ok((e, _other)) => Ok(e),
                    Err((e, _other)) => Err(e),
                }
            });

            // Check the result of the cache lookup.
            Box::new(cache_status.then(move |result| {
                let duration = start.elapsed();
                let pwd = Path::new(&cwd);
                let outputs = compilation.outputs()
                    .map(|(key, path)| (key.to_string(), pwd.join(path)))
                    .collect::<HashMap<_, _>>();

                let miss_type = match result {
                    Ok(Some(Cache::Hit(mut entry))) => {
                        debug!("[{}]: Cache hit in {}", out_pretty, fmt_duration_as_secs(&duration));
                        let mut stdout = Vec::new();
                        let mut stderr = Vec::new();
                        drop(entry.get_object("stdout", &mut stdout));
                        drop(entry.get_object("stderr", &mut stderr));
                        let write = pool.spawn_fn(move ||{
                            for (key, path) in &outputs {
                                let dir = match path.parent() {
                                    Some(d) => d,
                                    None => bail!("Output file without a parent directory!"),
                                };
                                // Write the cache entry to a tempfile and then atomically
                                // move it to its final location so that other rustc invocations
                                // happening in parallel don't see a partially-written file.
                                let mut tmp = NamedTempFile::new_in(dir)?;
                                let mode = entry.get_object(&key, &mut tmp)?;
                                tmp.persist(path)?;
                                if let Some(mode) = mode {
                                    set_file_mode(&path, mode)?;
                                }
                            }
                            Ok(())
                        });
                        let output = process::Output {
                            status: exit_status(0),
                            stdout: stdout,
                            stderr: stderr,
                        };
                        let result = CompileResult::CacheHit(duration);
                        return Box::new(write.map(|_| {
                            (result, output)
                        })) as SFuture<_>
                    }
                    Ok(Some(Cache::Miss)) => {
                        debug!("[{}]: Cache miss in {}", out_pretty, fmt_duration_as_secs(&duration));
                        MissType::Normal
                    }
                    Ok(Some(Cache::Recache)) => {
                        debug!("[{}]: Cache recache in {}", out_pretty, fmt_duration_as_secs(&duration));
                        MissType::ForcedRecache
                    }
                    Ok(None) => {
                        debug!("[{}]: Cache timed out {}", out_pretty, fmt_duration_as_secs(&duration));
                        MissType::TimedOut
                    }
                    Err(err) => {
                        error!("[{}]: Cache read error: {}", out_pretty, err);
                        for e in err.iter().skip(1) {
                            error!("[{}] \t{}", out_pretty, e);
                        }
                        MissType::CacheReadError
                    }
                };

                // Cache miss, so compile it.
                let start = Instant::now();
                let out_pretty = out_pretty.clone();
                let compile = compilation.compile(&creator, &cwd, &env_vars);
                Box::new(compile.and_then(move |(cacheable, compiler_result)| {
                    let duration = start.elapsed();
                    if !compiler_result.status.success() {
                        debug!("[{}]: Compiled but failed, not storing in cache",
                               out_pretty);
                        return f_ok((CompileResult::CompileFailed, compiler_result))
                            as SFuture<_>
                    }
                    if cacheable != Cacheable::Yes {
                        // Not cacheable
                        debug!("[{}]: Compiled but not cacheable",
                               out_pretty);
                        return f_ok((CompileResult::NotCacheable, compiler_result))
                    }
                    debug!("[{}]: Compiled in {}, storing in cache", out_pretty, fmt_duration_as_secs(&duration));
                    let write = pool.spawn_fn(move || -> Result<_> {
                        let mut entry = CacheWrite::new();
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
                    let o = out_pretty.clone();
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
                        let out_pretty = out_pretty.clone();
                        let future = storage.put(&key, entry)
                            .then(move |res| {
                                match res {
                                    Ok(_) => debug!("[{}]: Stored in cache successfully!", out_pretty),
                                    Err(ref e) => debug!("[{}]: Cache write error: {:?}", out_pretty, e),
                                }
                                res.map(|duration| CacheWriteInfo {
                                    object_file_pretty: out_pretty,
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

    /// A descriptive string about the file that we're going to be producing.
    ///
    /// This is primarily intended for debug logging and such, not for actual
    /// artifact generation.
    fn output_pretty(&self) -> Cow<str>;

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
               cwd: &Path,
               env_vars: &[(OsString, OsString)])
               -> SFuture<(Cacheable, process::Output)>;

    /// Returns an iterator over the results of this compilation.
    ///
    /// Each item is a descriptive (and unique) name of the output paired with
    /// the path where it'll show up.
    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a Path)> + 'a>;
}

/// Result of generating a hash from a compiler command.
pub struct HashResult<T: CommandCreatorSync> {
    /// The hash key of the inputs.
    pub key: String,
    /// An object to use for the actual compilation, if necessary.
    pub compilation: Box<Compilation<T> + 'static>,
}

/// Possible results of parsing compiler arguments.
#[derive(Debug, PartialEq)]
pub enum CompilerArguments<T>
{
    /// Commandline can be handled.
    Ok(T),
    /// Cannot cache this compilation.
    CannotCache(&'static str),
    /// This commandline is not a compile.
    NotCompilation,
}

/// Specifics about cache misses.
#[derive(Debug, PartialEq)]
pub enum MissType {
    /// The compilation was not found in the cache, nothing more.
    Normal,
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
    CacheMiss(MissType, Duration, SFuture<CacheWriteInfo>),
    /// Not in cache, but the compilation result was determined to be not cacheable.
    NotCacheable,
    /// Not in cache, but compilation failed.
    CompileFailed,
}

/// The state of `--color` options passed to a compiler.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum ColorMode {
    Off,
    On,
    Auto,
}

impl Default for ColorMode {
    fn default() -> ColorMode { ColorMode::Auto }
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
#[derive(Copy, Clone, Debug, PartialEq)]
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
fn detect_compiler<T>(creator: &T,
                      executable: &Path,
                      env: &[(OsString, OsString)],
                      pool: &CpuPool)
                      -> SFuture<Option<Box<Compiler<T>>>>
    where T: CommandCreatorSync
{
    trace!("detect_compiler");

    // First, see if this looks like rustc.
    let filename = match executable.file_stem() {
        None => return f_err("could not determine compiler kind"),
        Some(f) => f,
    };
    let is_rustc = if filename.to_string_lossy().to_lowercase() == "rustc" {
        // Sanity check that it's really rustc.
        let executable = executable.to_path_buf();
        let child = creator.clone().new_command_sync(&executable)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .args(&["--version"])
            .spawn();
        let output = child.and_then(move |child| {
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
        f_ok(false)
    };

    let creator = creator.clone();
    let executable = executable.to_owned();
    let env = env.to_owned();
    let pool = pool.clone();
    Box::new(is_rustc.and_then(move |is_rustc| {
        if is_rustc {
            debug!("Found rustc");
            Box::new(Rust::new(creator, executable, pool).map(|c| Some(Box::new(c) as Box<Compiler<T>>)))
        } else {
            detect_c_compiler(creator, executable, env, pool)
        }
    }))
}

fn detect_c_compiler<T>(creator: T,
                        executable: PathBuf,
                        env: Vec<(OsString, OsString)>,
                        pool: CpuPool)
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
       .stderr(Stdio::null())
       .envs(env.iter().map(|s| (&s.0, &s.1)));
    let output = write.and_then(move |(tempdir, src)| {
        cmd.arg("-E").arg(src);
        trace!("compiler {:?}", cmd);
        cmd.spawn().and_then(|child| {
            child.wait_with_output().chain_err(|| "failed to read child output")
        }).map(|e| {
            drop(tempdir);
            e
        })
    });

    Box::new(output.and_then(move |output| -> SFuture<_> {
        let stdout = match str::from_utf8(&output.stdout) {
            Ok(s) => s,
            Err(_) => return f_err("Failed to parse output"),
        };
        for line in stdout.lines() {
            //TODO: do something smarter here.
            if line == "gcc" {
                debug!("Found GCC");
                return Box::new(CCompiler::new(GCC, executable, &pool)
                                .map(|c| Some(Box::new(c) as Box<Compiler<T>>)));
            } else if line == "clang" {
                debug!("Found clang");
                return Box::new(CCompiler::new(Clang, executable, &pool)
                                .map(|c| Some(Box::new(c) as Box<Compiler<T>>)));
            } else if line == "msvc" {
                debug!("Found MSVC");
                let prefix = msvc::detect_showincludes_prefix(&creator,
                                                              executable.as_ref(),
                                                              env,
                                                              &pool);
                return Box::new(prefix.and_then(move |prefix| {
                    trace!("showIncludes prefix: '{}'", prefix);
                    CCompiler::new(MSVC {
                        includes_prefix: prefix,
                    }, executable, &pool)
                        .map(|c| Some(Box::new(c) as Box<Compiler<T>>))
                }))
            }
        }
        debug!("nothing useful in detection output {:?}", stdout);
        debug!("compiler status: {}", output.status);
        debug!("compiler stderr:\n{}", String::from_utf8_lossy(&output.stderr));
        f_ok(None)
    }))
}

/// If `executable` is a known compiler, return a `Box<Compiler>` containing information about it.
pub fn get_compiler_info<T>(creator: &T,
                            executable: &Path,
                            env: &[(OsString, OsString)],
                            pool: &CpuPool)
                            -> SFuture<Box<Compiler<T>>>
    where T: CommandCreatorSync
{
    let pool = pool.clone();
    let detect = detect_compiler(creator, executable, env, &pool);
    Box::new(detect.and_then(move |compiler| -> Result<_> {
        match compiler {
            Some(compiler) => Ok(compiler),
            None => bail!("could not determine compiler kind"),
        }
    }))
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
    use std::u64;
    use test::mock_storage::MockStorage;
    use test::utils::*;
    use tokio_core::reactor::Core;

    #[test]
    fn test_detect_compiler_kind_gcc() {
        let f = TestFixture::new();
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nbar\ngcc", "")));
        let c = detect_compiler(&creator, &f.bins[0], &[], &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::C(CCompilerKind::GCC), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_clang() {
        let f = TestFixture::new();
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "clang\nfoo", "")));
        let c = detect_compiler(&creator, &f.bins[0], &[], &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::C(CCompilerKind::Clang), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_msvc() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let srcfile = f.touch("test.h").unwrap();
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
        let c = detect_compiler(&creator, &f.bins[0], &[], &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::C(CCompilerKind::MSVC), c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_rustc() {
        let f = TestFixture::new();
        // Windows uses bin, everything else uses lib. Just create both.
        fs::create_dir(f.tempdir.path().join("lib")).unwrap();
        fs::create_dir(f.tempdir.path().join("bin")).unwrap();
        let rustc = f.mk_bin("rustc").unwrap();
        let creator = new_creator();
        let pool = CpuPool::new(1);
        // rustc --version
        next_command(&creator, Ok(MockChild::new(exit_status(0), "rustc 1.15 (blah 2017-01-01)", "")));
        // rustc --print=sysroot
        let sysroot = f.tempdir.path().to_str().unwrap();
        next_command(&creator, Ok(MockChild::new(exit_status(0), &sysroot, "")));
        let c = detect_compiler(&creator, &rustc, &[], &pool).wait().unwrap().unwrap();
        assert_eq!(CompilerKind::Rust, c.kind());
    }

    #[test]
    fn test_detect_compiler_kind_unknown() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "something", "")));
        assert!(detect_compiler(&creator, "/foo/bar".as_ref(), &[], &pool).wait().unwrap().is_none());
    }

    #[test]
    fn test_detect_compiler_kind_process_fail() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert!(detect_compiler(&creator, "/foo/bar".as_ref(), &[], &pool).wait().unwrap().is_none());
    }

    #[test]
    fn test_get_compiler_info() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  &f.bins[0],
                                  &[],
                                  &pool).wait().unwrap();
        // sha-1 digest of an empty file.
        assert_eq!(CompilerKind::C(CCompilerKind::GCC), c.kind());
    }

    #[test]
    fn test_compiler_get_cached_or_compile_uncached() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let core = Core::new().unwrap();
        let handle = core.handle();
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     u64::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  &f.bins[0],
                                  &[],
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
            let mut f = File::create(&o)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR))
        });
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(h) => h,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let hasher2 = hasher.clone();
        let (cached, res) = hasher.get_cached_or_compile(creator.clone(),
                                                         storage.clone(),
                                                         arguments.clone(),
                                                         cwd.to_path_buf(),
                                                         vec![],
                                                         CacheControl::Default,
                                                         pool.clone(),
                                                         handle.clone()).wait().unwrap();
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
        let (cached, res) = hasher2.get_cached_or_compile(creator.clone(),
                                                          storage.clone(),
                                                          arguments,
                                                          cwd.to_path_buf(),
                                                          vec![],
                                                          CacheControl::Default,
                                                          pool.clone(),
                                                          handle).wait().unwrap();
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
        let core = Core::new().unwrap();
        let handle = core.handle();
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     u64::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  &f.bins[0],
                                  &[],
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
            let mut f = File::create(&o)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR))
        });
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(h) => h,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let hasher2 = hasher.clone();
        let (cached, res) = hasher.get_cached_or_compile(creator.clone(),
                                                         storage.clone(),
                                                         arguments.clone(),
                                                         cwd.to_path_buf(),
                                                         vec![],
                                                         CacheControl::Default,
                                                         pool.clone(),
                                                         handle.clone()).wait().unwrap();
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
        let (cached, res) = hasher2.get_cached_or_compile(creator,
                                                          storage,
                                                          arguments,
                                                          cwd.to_path_buf(),
                                                          vec![],
                                                          CacheControl::Default,
                                                          pool,
                                                          handle).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        assert_eq!(CompileResult::CacheHit(Duration::new(0, 0)), cached);
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }

    #[test]
    /// Test that a cache read that results in an error is treated as a cache
    /// miss.
    fn test_compiler_get_cached_or_compile_cache_error() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let core = Core::new().unwrap();
        let handle = core.handle();
        let storage = MockStorage::new();
        let storage: Arc<MockStorage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  &f.bins[0],
                                  &[],
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
            let mut f = File::create(&o)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR))
        });
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(h) => h,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        // The cache will return an error.
        storage.next_get(f_err("Some Error"));
        let (cached, res) = hasher.get_cached_or_compile(creator.clone(),
                                                         storage.clone(),
                                                         arguments.clone(),
                                                         cwd.to_path_buf(),
                                                         vec![],
                                                         CacheControl::Default,
                                                         pool.clone(),
                                                         handle.clone()).wait().unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        match cached {
            CompileResult::CacheMiss(MissType::CacheReadError, _, f) => {
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
    fn test_compiler_get_cached_or_compile_force_recache() {
        use env_logger;
        drop(env_logger::init());
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let core = Core::new().unwrap();
        let handle = core.handle();
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     u64::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  &f.bins[0],
                                  &[],
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
                let mut f = File::create(&o)?;
                f.write_all(b"file contents")?;
                Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR))
            });
        }
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(h) => h,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let hasher2 = hasher.clone();
        let (cached, res) = hasher.get_cached_or_compile(creator.clone(),
                                                         storage.clone(),
                                                         arguments.clone(),
                                                         cwd.to_path_buf(),
                                                         vec![],
                                                         CacheControl::Default,
                                                         pool.clone(),
                                                         handle.clone()).wait().unwrap();
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
        let (cached, res) = hasher2.get_cached_or_compile(creator,
                                                          storage,
                                                          arguments,
                                                          cwd.to_path_buf(),
                                                          vec![],
                                                          CacheControl::ForceRecache,
                                                          pool,
                                                          handle).wait().unwrap();
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
        let core = Core::new().unwrap();
        let handle = core.handle();
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     u64::MAX,
                                     &pool);
        let storage: Arc<Storage> = Arc::new(storage);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(&creator,
                                  &f.bins[0],
                                  &[],
                                  &pool).wait().unwrap();
        // The preprocessor invocation.
        const PREPROCESSOR_STDERR: &'static [u8] = b"something went wrong";
        next_command(&creator, Ok(MockChild::new(exit_status(1), b"preprocessor output", PREPROCESSOR_STDERR)));
        let cwd = f.tempdir.path();
        let arguments = ovec!["-c", "foo.c", "-o", "foo.o"];
        let hasher = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(h) => h,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = hasher.get_cached_or_compile(creator,
                                                         storage,
                                                         arguments,
                                                         cwd.to_path_buf(),
                                                         vec![],
                                                         CacheControl::Default,
                                                         pool,
                                                         handle).wait().unwrap();
        assert_eq!(cached, CompileResult::Error);
        assert_eq!(exit_status(1), res.status);
        // Shouldn't get anything on stdout, since that would just be preprocessor spew!
        assert_eq!(b"", res.stdout.as_slice());
        assert_eq!(PREPROCESSOR_STDERR, res.stderr.as_slice());
    }
}
