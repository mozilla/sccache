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
    hash_key,
};
use compiler::{
    clang,
    gcc,
    msvc,
};
use filetime::FileTime;
use futures::future;
use futures::{Future, IntoFuture};
use futures_cpupool::CpuPool;
use log::LogLevel::{Debug,Trace};
use mock_command::{
    CommandChild,
    CommandCreatorSync,
    RunCommand,
    exit_status,
};
use sha1;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self,File};
use std::io::prelude::*;
use std::io::{
    self,
    BufReader,
};
use std::path::{Path, PathBuf};
use std::process::{self,Stdio};
use std::str;
use std::sync::Arc;
use std::time::{
    Duration,
    Instant,
};
use tempdir::TempDir;

use errors::*;

/// Supported compilers.
#[derive(Debug, PartialEq, Clone)]
pub enum CompilerKind {
    /// GCC
    Gcc,
    /// clang
    Clang,
    /// Microsoft Visual C++
    Msvc {
        /// The prefix used in the output of `-showIncludes`.
        includes_prefix: String,
    },
}

impl CompilerKind {
    pub fn parse_arguments(&self,
                           arguments: &[String],
                           cwd: &Path) -> CompilerArguments {
        match *self {
            // GCC and clang share the same argument parsing logic, but
            // accept different sets of arguments.
            CompilerKind::Gcc => gcc::parse_arguments(arguments, cwd, gcc::argument_takes_value),
            CompilerKind::Clang => gcc::parse_arguments(arguments, cwd, clang::argument_takes_value),
            CompilerKind::Msvc { .. } => msvc::parse_arguments(arguments),
        }
    }

    pub fn preprocess<T>(&self,
                         creator: &T,
                         compiler: &Compiler,
                         parsed_args: &ParsedArguments,
                         cwd: &str,
                         pool: &CpuPool)
                         -> SFuture<process::Output>
        where T: CommandCreatorSync
    {
        match *self {
            CompilerKind::Gcc | CompilerKind::Clang => {
                // GCC and clang use the same preprocessor invocation.
                gcc::preprocess(creator, compiler, parsed_args, cwd, pool)
            },
            CompilerKind::Msvc { ref includes_prefix } => msvc::preprocess(creator, compiler, parsed_args, cwd, includes_prefix, pool),
        }
    }

    pub fn compile<T>(&self,
                      creator: &T,
                      compiler: &Compiler,
                      preprocessor_output: Vec<u8>,
                      parsed_args: &ParsedArguments,
                      cwd: &str,
                      pool: &CpuPool)
                      -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync,
    {
        match *self {
            CompilerKind::Gcc => gcc::compile(creator, compiler, preprocessor_output, parsed_args, cwd, pool),
            CompilerKind::Clang => clang::compile(creator, compiler, preprocessor_output, parsed_args, cwd, pool),
            CompilerKind::Msvc { .. } => msvc::compile(creator, compiler, preprocessor_output, parsed_args, cwd, pool),
        }
    }
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
}

impl ParsedArguments {
    pub fn output_file(&self) -> Cow<str> {
        self.outputs.get("obj").and_then(|o| Path::new(o).file_name().map(|f| f.to_string_lossy())).unwrap_or(Cow::Borrowed("Unknown filename"))
    }
}

/// Possible results of parsing compiler arguments.
#[derive(Debug, PartialEq)]
pub enum CompilerArguments {
    /// Commandline can be handled.
    Ok(ParsedArguments),
    /// Cannot cache this compilation.
    CannotCache,
    /// This commandline is not a compile.
    NotCompilation,
}

/// Information about a compiler.
#[derive(Clone)]
pub struct Compiler {
    /// The path to the compiler binary.
    pub executable: String,
    /// The last modified time of `executable`.
    pub mtime: FileTime,
    /// The sha-1 digest of `executable`, as a hex string.
    pub digest: String,
    /// The kind of compiler, from the set of known compilers.
    pub kind: CompilerKind,
}

/// Specifics about cache misses.
#[derive(Debug, PartialEq)]
pub enum MissType {
    /// The compilation was not found in the cache, nothing more.
    Normal,
    /// There was a cache entry, but an error occurred trying to read it.
    CacheReadError,
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

impl Compiler {
    /// Create a new `Compiler` of `kind`, with `executable` as the binary.
    ///
    /// This will generate a hash of the contents of `executable`, so
    /// don't call it where it shouldn't block on I/O.
    pub fn new(executable: &str, kind: CompilerKind) -> io::Result<Compiler> {
        let attr = try!(fs::metadata(executable));
        let f = try!(File::open(executable));
        let mut m = sha1::Sha1::new();
        let mut reader = BufReader::new(f);
        loop {
            let mut buffer = [0; 1024];
            let count = try!(reader.read(&mut buffer[..]));
            if count == 0 {
                break;
            }
            m.update(&buffer[..count]);
        }
        Ok(Compiler {
            executable: executable.to_owned(),
            mtime: FileTime::from_last_modification_time(&attr),
            digest: m.digest().to_string(),
            kind: kind,
        })
    }

    /// Check that this compiler can handle and cache when run with `arguments`, and parse out the relevant bits.
    ///
    /// Not all compiler options can be cached, so this tests the set of
    /// options for each compiler.
    pub fn parse_arguments(&self,
                           arguments: &[String],
                           cwd: &Path) -> CompilerArguments {
        if log_enabled!(Debug) {
            let cmd_str = arguments.join(" ");
            debug!("parse_arguments: `{}`", cmd_str);
        }
        let parsed_args = self.kind.parse_arguments(arguments, cwd);
        match parsed_args {
            CompilerArguments::Ok(_) => debug!("parse_arguments: Ok"),
            CompilerArguments::CannotCache => debug!("parse_arguments: CannotCache"),
            CompilerArguments::NotCompilation => debug!("parse_arguments: NotCompilation"),
        };
        parsed_args
    }

    /// Look up a cached compile result in `storage`. If not found, run the
    /// compile and store the result.
    pub fn get_cached_or_compile<T>(&self,
                                    creator: &T,
                                    storage: &Arc<Storage>,
                                    arguments: &[String],
                                    parsed_args: &ParsedArguments,
                                    cwd: &str,
                                    cache_control: CacheControl,
                                    pool: &CpuPool)
                                    -> SFuture<(CompileResult, process::Output)>
        where T: CommandCreatorSync
    {
        let out_file = parsed_args.output_file();
        if log_enabled!(Debug) {
            let cmd_str = arguments.join(" ");
            debug!("[{}]: get_cached_or_compile: {}", out_file, cmd_str);
        }
        let result = self.kind.preprocess(creator, self, parsed_args, cwd, pool);
        let out_file = out_file.into_owned();
        let result = result.map_err(move |e| {
            debug!("[{}]: preprocessor failed: {:?}", out_file, e);
            e
        });

        let parsed_args = parsed_args.clone();
        let cwd = cwd.to_string();
        let arguments = arguments.to_vec();
        let me = self.clone();
        let storage = storage.clone();
        let pool = pool.clone();
        let creator = creator.clone();

        Box::new(result.and_then(move |preprocessor_result| -> SFuture<_> {
            // If the preprocessor failed, just return that result.
            if !preprocessor_result.status.success() {
                debug!("[{}]: preprocessor returned error status {:?}",
                       parsed_args.output_file(),
                       preprocessor_result.status.code());
                // Drop the stdout since it's the preprocessor output, just hand back stderr and the exit status.
                let output = process::Output {
                    stdout: vec!(),
                    ..preprocessor_result
                };
                return Box::new(future::ok((CompileResult::Error, output)))
            }
            trace!("[{}]: Preprocessor output is {} bytes",
                   parsed_args.output_file(),
                   preprocessor_result.stdout.len());

            let key = hash_key(&me, &arguments, &preprocessor_result.stdout);
            trace!("[{}]: Hash key: {}", parsed_args.output_file(), key);
            // If `ForceRecache` is enabled, we won't check the cache.
            let start = Instant::now();
            let cache_status = if cache_control == CacheControl::ForceRecache {
                Box::new(future::ok(Cache::Recache))
            } else {
                storage.get(&key)
            };

            Box::new(cache_status.then(move |result| {
                let duration = start.elapsed();
                let pwd = Path::new(&cwd);
                let outputs = parsed_args.outputs.iter()
                    .map(|(key, path)| (key.to_string(), pwd.join(path)))
                    .collect::<HashMap<_, _>>();

                let miss_type = match result {
                    Ok(Cache::Hit(mut entry)) => {
                        debug!("[{}]: Cache hit!", parsed_args.output_file());
                        let mut stdout = io::Cursor::new(vec!());
                        let mut stderr = io::Cursor::new(vec!());
                        entry.get_object("stdout", &mut stdout).unwrap_or(());
                        entry.get_object("stderr", &mut stderr).unwrap_or(());
                        let write = pool.spawn_fn(move ||{
                            for (key, path) in &outputs {
                                let mut f = try!(File::create(path));
                                try!(entry.get_object(&key, &mut f));
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
                    Ok(Cache::Miss) => {
                        debug!("[{}]: Cache miss!", parsed_args.output_file());
                        MissType::Normal
                    }
                    Ok(Cache::Recache) => {
                        debug!("[{}]: Cache recache!", parsed_args.output_file());
                        MissType::ForcedRecache
                    }
                    Err(e) => {
                        debug!("[{}]: Cache read error: {:?}", parsed_args.output_file(), e);
                        //TODO: store the error in CacheReadError in some way
                        MissType::CacheReadError
                    }
                };
                me.compile(&creator,
                           preprocessor_result,
                           parsed_args,
                           &cwd,
                           pool,
                           outputs,
                           storage,
                           key,
                           miss_type)
            }))
        }))
    }

    fn compile<T>(&self,
                  creator: &T,
                  preprocessor_result: process::Output,
                  parsed_args: ParsedArguments,
                  cwd: &str,
                  pool: CpuPool,
                  outputs: HashMap<String, PathBuf>,
                  storage: Arc<Storage>,
                  key: String,
                  miss_type: MissType)
                  -> SFuture<(CompileResult, process::Output)>
        where T: CommandCreatorSync,
    {
        let process::Output { stdout, .. } = preprocessor_result;
        let start = Instant::now();

        let compile = self.kind.compile(creator, self, stdout, &parsed_args, cwd, &pool);
        Box::new(compile.and_then(move |(cacheable, compiler_result)| {
            let duration = start.elapsed();
            if compiler_result.status.success() {
                if cacheable == Cacheable::Yes {
                    debug!("[{}]: Compiled, storing in cache",
                           parsed_args.output_file());
                    // fall through
                } else {
                    // Not cacheable
                    debug!("[{}]: Compiled but not cacheable",
                           parsed_args.output_file());
                    return Box::new(future::ok((CompileResult::NotCacheable, compiler_result)))
                        as SFuture<_>
                }
            } else {
                debug!("[{}]: Compiled but failed, not storing in cache",
                       parsed_args.output_file());
                return Box::new(future::ok((CompileResult::CompileFailed, compiler_result)))
            }
            let mut entry = match storage.start_put(&key) {
                Ok(entry) => entry,
                Err(e) => return Box::new(future::err(e))
            };
            let write = pool.spawn_fn(move || -> io::Result<_> {
                for (key, path) in &outputs {
                    let mut f = try!(File::open(&path));
                    try!(entry.put_object(key, &mut f).map_err(|e| {
                        let msg = format!("failed to put object `{:?}` in \
                                           storage: {}", path, e);
                        io::Error::new(io::ErrorKind::Other, msg)
                    }));
                }
                Ok(entry)
            });
            let write = write.chain_err(|| "failed to zip up compiler outputs");
            Box::new(write.and_then(move |mut entry| {
                if !compiler_result.stdout.is_empty() {
                    let mut stdout = &compiler_result.stdout[..];
                    entry.put_object("stdout", &mut stdout)?;
                }
                if !compiler_result.stderr.is_empty() {
                    let mut stderr = &compiler_result.stderr[..];
                    entry.put_object("stderr", &mut stderr)?;
                }

                // Try to finish storing the newly-written cache
                // entry. We'll get the result back elsewhere.
                let out_file = parsed_args.output_file().into_owned();
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
            }))
        }))
    }
}

/// Write `contents` to `path`.
fn write_file(path : &Path, contents: &[u8]) -> io::Result<()> {
    let mut f = try!(File::create(path));
    f.write_all(contents)
}

/// If `executable` is a known compiler, return `Some(CompilerKind)`.
pub fn detect_compiler_kind<T>(creator: &T, executable: &str, pool: &CpuPool)
                               -> SFuture<Option<CompilerKind>>
    where T: CommandCreatorSync
{
    trace!("detect_compiler");
    let write = pool.spawn_fn(move || -> io::Result<_> {
        let dir = TempDir::new("sccache")?;
        let src = dir.path().join("testfile.c");
        write_file(&src, b"#if defined(_MSC_VER)
msvc
#elif defined(__clang__)
clang
#elif defined(__GNUC__)
gcc
#endif
")?;
        Ok((dir, src))
    });
    let write = write.chain_err(|| "failed to write temporary file");

    let mut creator2 = creator.clone();
    let executable2 = executable.to_string();
    let output = write.and_then(move |(tempdir, src)| {
        let args = vec!(OsString::from("-E"), OsString::from(&src));
        if log_enabled!(Trace) {
            let va = args.iter().map(|a| a.to_str().unwrap()).collect::<Vec<&str>>();
            trace!("compiler: {}, args: '{}'", executable2, va.join(" "));
        }
        let child = creator2.new_command_sync(&executable2)
                        .args(&args)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn();
        let child = child.chain_err(|| "failed to spawn child");

        child.into_future().and_then(|child| {
            child.wait_with_output().chain_err(|| "failed to read child output")
        }).map(|e| {
            drop(tempdir);
            e
        })
    });

    let creator = creator.clone();
    let pool = pool.clone();
    let executable = executable.to_string();
    Box::new(output.and_then(move |output| -> SFuture<_> {
        let stdout = match str::from_utf8(&output.stdout) {
            Ok(s) => s,
            Err(_) => return future::err("Failed to parse output".into()).boxed(),
        };
        for line in stdout.lines() {
            //TODO: do something smarter here.
            if line == "gcc" {
                debug!("Found GCC");
                return future::ok(Some(CompilerKind::Gcc)).boxed()
            } else if line == "clang" {
                debug!("Found clang");
                return future::ok(Some(CompilerKind::Clang)).boxed()
            } else if line == "msvc" {
                debug!("Found MSVC");
                let prefix = msvc::detect_showincludes_prefix(&creator,
                                                              executable.as_ref(),
                                                              &pool);
                return Box::new(prefix.map(|prefix| {
                    trace!("showIncludes prefix: '{}'", prefix);
                    Some(CompilerKind::Msvc {
                        includes_prefix: prefix,
                    })
                }))
            }
        }
        future::ok(None).boxed()
    }))
}

/// If `executable` is a known compiler, return `Some(Compiler)` containing information about it.
pub fn get_compiler_info<T>(creator: &T, executable: &str, pool: &CpuPool)
                            -> SFuture<Compiler>
    where T: CommandCreatorSync
{
    let executable = executable.to_string();
    let pool = pool.clone();
    Box::new(detect_compiler_kind(creator, &executable, &pool).and_then(move |kind| {
        match kind {
            Some(kind) => {
                pool.spawn_fn(move || Compiler::new(&executable, kind))
                    .chain_err(|| "failed to learn compiler metadata")
            }
            None => future::err("could not determine compiler kind".into()).boxed(),
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
        let kind = detect_compiler_kind(&creator, "/foo/bar", &pool).wait().unwrap();
        assert_eq!(Some(CompilerKind::Gcc), kind);
    }

    #[test]
    fn test_detect_compiler_kind_clang() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "clang\nfoo", "")));
        let kind = detect_compiler_kind(&creator, "/foo/bar", &pool).wait().unwrap();
        assert_eq!(Some(CompilerKind::Clang), kind);
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
        let kind = detect_compiler_kind(&creator, "/foo/bar", &pool).wait().unwrap();
        assert_eq!(Some(CompilerKind::Msvc { includes_prefix: prefix }), kind);
    }

    #[test]
    fn test_detect_compiler_kind_unknown() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(0), "something", "")));
        assert_eq!(None, detect_compiler_kind(&creator, "/foo/bar", &pool).wait().unwrap());
    }

    #[test]
    fn test_detect_compiler_kind_process_fail() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert_eq!(None, detect_compiler_kind(&creator, "/foo/bar", &pool).wait().unwrap());
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
        assert_eq!(CompilerKind::Gcc, c.kind);
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
        next_command_calls(&creator, move || {
            // Pretend to compile something.
            match File::create(&o)
                .and_then(|mut f| f.write_all(b"file contents")) {
                    Ok(_) => Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR)),
                    Err(e) => Err(e),
                }
        });
        let cwd = f.tempdir.path().to_str().unwrap();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    &pool).wait().unwrap();
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
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    &pool).wait().unwrap();
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
        next_command_calls(&creator, move || {
            // Pretend to compile something.
            match File::create(&o)
                .and_then(|mut f| f.write_all(b"file contents")) {
                    Ok(_) => Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR)),
                    Err(e) => Err(e),
                }
        });
        let cwd = f.tempdir.path().to_str().unwrap();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    &pool).wait().unwrap();
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
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    &pool).wait().unwrap();
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
            next_command_calls(&creator, move || {
                // Pretend to compile something.
                match File::create(&o)
                    .and_then(|mut f| f.write_all(b"file contents")) {
                        Ok(_) => Ok(MockChild::new(exit_status(0), COMPILER_STDOUT, COMPILER_STDERR)),
                        Err(e) => Err(e),
                    }
            });
        }
        let cwd = f.tempdir.path().to_str().unwrap();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    &pool).wait().unwrap();
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
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::ForceRecache,
                                                    &pool).wait().unwrap();
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
        let cwd = f.tempdir.path().to_str().unwrap();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(&creator,
                                                    &storage,
                                                    &arguments,
                                                    &parsed_args,
                                                    cwd,
                                                    CacheControl::Default,
                                                    &pool).wait().unwrap();
        assert_eq!(cached, CompileResult::Error);
        assert_eq!(exit_status(1), res.status);
        // Shouldn't get anything on stdout, since that would just be preprocessor spew!
        assert_eq!(b"", res.stdout.as_slice());
        assert_eq!(PREPROCESSOR_STDERR, res.stderr.as_slice());
    }
}
