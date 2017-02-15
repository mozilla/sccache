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
use futures::Future;
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
    Error,
    ErrorKind,
};
use std::path::Path;
use std::process::{self,Stdio};
use std::str;
use std::thread;
use std::time::{
    Duration,
    Instant,
};
use tempdir::TempDir;

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

    pub fn preprocess<T : CommandCreatorSync>(&self, creator: T, compiler: &Compiler, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
        match *self {
            CompilerKind::Gcc | CompilerKind::Clang => {
                // GCC and clang use the same preprocessor invocation.
                gcc::preprocess(creator, compiler, parsed_args, cwd)
            },
            CompilerKind::Msvc { ref includes_prefix } => msvc::preprocess(creator, compiler, parsed_args, cwd, includes_prefix),
        }
    }

    pub fn compile<T : CommandCreatorSync>(&self, creator: T, compiler: &Compiler, preprocessor_output: Vec<u8>, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<(Cacheable, process::Output)> {
        match *self {
            CompilerKind::Gcc => gcc::compile(creator, compiler, preprocessor_output, parsed_args, cwd),
            CompilerKind::Clang => clang::compile(creator, compiler, preprocessor_output, parsed_args, cwd),
            CompilerKind::Msvc { .. } => msvc::compile(creator, compiler, preprocessor_output, parsed_args, cwd),
        }
    }
}

/// The results of parsing a compiler commandline.
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
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

/// A `Future` that may provide a `CacheWriteResult`.
pub type CacheWriteFuture = Box<Future<Item=CacheWriteInfo, Error=String> + Send>;

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
    CacheMiss(MissType, Duration, CacheWriteFuture),
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

    /// Look up a cached compile result in `storage`. If not found, run the compile and store the result.
    pub fn get_cached_or_compile<T>(&self,
                                    creator: T,
                                    storage: &Storage,
                                    arguments: &[String],
                                    parsed_args: &ParsedArguments,
                                    cwd: &str,
                                    cache_control: CacheControl)
                                    -> io::Result<(CompileResult, process::Output)>
        where T: CommandCreatorSync
    {
        let out_file = parsed_args.output_file();
        if log_enabled!(Debug) {
            let cmd_str = arguments.join(" ");
            debug!("[{}]: get_cached_or_compile: {}", out_file, cmd_str);
        }
        let preprocessor_result = try!(self.kind.preprocess(creator.clone(), self, parsed_args, cwd).map_err(|e| { debug!("[{}]: preprocessor failed: {:?}", out_file, e); e }));
        // If the preprocessor failed, just return that result.
        if !preprocessor_result.status.success() {
            debug!("[{}]: preprocessor returned error status {:?}", out_file, preprocessor_result.status.code());
            // Drop the stdout since it's the preprocessor output, just hand back stderr and the exit status.
            return Ok((CompileResult::Error, process::Output { stdout: vec!(), .. preprocessor_result }));
        }
        trace!("[{}]: Preprocessor output is {} bytes", out_file, preprocessor_result.stdout.len());

        // Remove object file from arguments before hash calculation
        let arguments = arguments.iter()
            .filter(|a| **a != out_file)
            .map(|a| &**a)
            .collect::<String>();
        let key = hash_key(self, &arguments, &preprocessor_result.stdout);
        trace!("[{}]: Hash key: {}", out_file, key);
        let pwd = Path::new(cwd);
        let outputs = parsed_args.outputs.iter()
            .map(|(key, path)| (key, pwd.join(path)))
            .collect::<HashMap<_, _>>();
        // If `ForceRecache` is enabled, we won't check the cache.
        let start = Instant::now();
        let cache_status = if cache_control == CacheControl::ForceRecache {
            Cache::Recache
        } else {
            storage.get(&key)
        };
        let duration = start.elapsed();
        match cache_status {
            Cache::Hit(mut entry) => {
                debug!("[{}]: Cache hit!", out_file);
                for (key, path) in &outputs {
                    let mut f = try!(File::create(path));
                    try!(entry.get_object(key, &mut f));
                }
                let mut stdout = io::Cursor::new(vec!());
                let mut stderr = io::Cursor::new(vec!());
                entry.get_object("stdout", &mut stdout).unwrap_or(());
                entry.get_object("stderr", &mut stderr).unwrap_or(());
                Ok((CompileResult::CacheHit(duration),
                    process::Output {
                        status: exit_status(0),
                        stdout: stdout.into_inner(),
                        stderr: stderr.into_inner(),
                    }))
            },

            res @ Cache::Miss | res @ Cache::Recache | res @ Cache::Error(_) => {
                let miss_type = match res {
                    Cache::Miss => { debug!("[{}]: Cache miss!", out_file); MissType::Normal }
                    Cache::Recache => { debug!("[{}]: Cache recache!", out_file); MissType::ForcedRecache }
                    Cache::Error(e) => {
                        debug!("[{}]: Cache read error: {:?}", out_file, e);
                        //TODO: store the error in CacheReadError in some way
                        MissType::CacheReadError
                    }
                    Cache::Hit(_) => MissType::Normal,
                };
                let process::Output { stdout, .. } = preprocessor_result;
                let start = Instant::now();
                let (cacheable, compiler_result) = try!(self.kind.compile(creator, self, stdout, parsed_args, cwd));
                let duration = start.elapsed();
                if compiler_result.status.success() {
                    if cacheable == Cacheable::Yes {
                        debug!("[{}]: Compiled, storing in cache", out_file);
                        let mut entry = try!(storage.start_put(&key));
                        for (key, path) in &outputs {
                            let mut f = try!(File::open(&path));
                            try!(entry.put_object(key, &mut f)
                                 .or_else(|e| {
                                     error!("[{}]: Failed to put object `{:?}` in storage: {:?}", out_file, path, e);
                                     Err(e)
                                 }));
                        }
                        if !compiler_result.stdout.is_empty() {
                            try!(entry.put_object("stdout", &mut io::Cursor::new(&compiler_result.stdout)));
                        }
                        if !compiler_result.stderr.is_empty() {
                            try!(entry.put_object("stderr", &mut io::Cursor::new(&compiler_result.stderr)));
                        }
                        // Try to finish storing the newly-written cache
                        // entry. We'll get the result back elsewhere.
                        let out_file = out_file.into_owned();
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
                    } else {
                        // Not cacheable
                        debug!("[{}]: Compiled but not cacheable", out_file);
                        Ok((CompileResult::NotCacheable, compiler_result))
                    }
                } else {
                    debug!("[{}]: Compiled but failed, not storing in cache", out_file);
                    Ok((CompileResult::CompileFailed, compiler_result))
                }
            }
        }
    }
}

/// Write `contents` to `path`.
fn write_file(path : &Path, contents: &[u8]) -> io::Result<()> {
    let mut f = try!(File::create(path));
    f.write_all(contents)
}

/// If `executable` is a known compiler, return `Some(CompilerKind)`.
pub fn detect_compiler_kind<T : CommandCreatorSync>(mut creator : T,  executable : &str) -> Option<CompilerKind> {
    trace!("detect_compiler");
    TempDir::new("sccache")
        .and_then(|dir| {
            let src = dir.path().join("testfile.c");
            try!(write_file(&src, b"#if defined(_MSC_VER)
msvc
#elif defined(__clang__)
clang
#elif defined(__GNUC__)
gcc
#endif
"));

            let args = vec!(OsString::from("-E"), OsString::from(&src));
            if log_enabled!(Trace) {
                let va = args.iter().map(|a| a.to_str().unwrap()).collect::<Vec<&str>>();
                trace!("compiler: {}, args: '{}'", executable, va.join(" "));
            }
            creator.new_command_sync(&executable)
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .and_then(|child| child.wait_with_output())
                .and_then(|output| {
                    str::from_utf8(&output.stdout)
                        .or_else(|_| Err(Error::new(ErrorKind::Other, "Failed to parse output")))
                        .and_then(|stdout| {
                            for line in stdout.lines() {
                                //TODO: do something smarter here.
                                if line == "gcc" {
                                    debug!("Found GCC");
                                    return Ok(Some(CompilerKind::Gcc));
                                } else if line == "clang" {
                                    debug!("Found clang");
                                    return Ok(Some(CompilerKind::Clang));
                                } else if line == "msvc" {
                                    debug!("Found MSVC");
                                    let prefix = try!(msvc::detect_showincludes_prefix(&mut creator, &executable));
                                    trace!("showIncludes prefix: '{}'", prefix);
                                    return Ok(Some(CompilerKind::Msvc {
                                        includes_prefix: prefix,
                                    }));
                                }
                            }
                            Ok(None)
                        })
                })
        }).unwrap_or_else(|e| {
            warn!("Failed to run compiler: {}", e);
            None
        })
}

/// If `executable` is a known compiler, return `Some(Compiler)` containing information about it.
pub fn get_compiler_info<T : CommandCreatorSync>(creator : T,  executable : &str) -> Option<Compiler> {
    detect_compiler_kind(creator, executable)
        .and_then(|kind| {
            Compiler::new(executable, kind)
                .or_else(|e| {
                    error!("Failed to create Compiler: {}", e);
                    Err(())
                })
                .ok()
        })
}

/// If `input`, write it to `child`'s stdin while also reading `child`'s stdout and stderr, then wait on `child` and return its status and output.
///
/// This was lifted from `std::process::Child::wait_with_output` and modified
/// to also write to stdin.
pub fn wait_with_input_output<T: CommandChild + 'static>(mut child: T, input: Option<Vec<u8>>) -> io::Result<process::Output> {
    let stdin = input.and_then(|i| {
        child.take_stdin().map(|mut stdin| {
            thread::spawn(move || {
                stdin.write_all(&i)
            })
        })
    });
    fn read<R>(mut input: R) -> thread::JoinHandle<io::Result<Vec<u8>>>
        where R: Read + Send + 'static
    {
        thread::spawn(move || {
            let mut ret = Vec::new();
            input.read_to_end(&mut ret).map(|_| ret)
        })
    }
    // Finish writing stdin before waiting, because waiting drops stdin.
    stdin.and_then(|t| t.join().unwrap().ok());
    let stdout = child.take_stdout().map(read);
    let stderr = child.take_stderr().map(read);
    let status = try!(child.wait());
    let stdout = stdout.and_then(|t| t.join().unwrap().ok());
    let stderr = stderr.and_then(|t| t.join().unwrap().ok());

    Ok(process::Output {
        status: status,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
    })
}

/// Run `command`, writing `input` to its stdin if it is `Some` and return the exit status and output.
pub fn run_input_output<C: RunCommand>(mut command: C, input: Option<Vec<u8>>) -> io::Result<process::Output> {
    command
        .no_console()
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::inherit() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|child| wait_with_input_output(child, input))
}

#[cfg(test)]
mod test {
    use super::*;
    use cache::disk::DiskCache;
    use futures::Future;
    use futures_cpupool::CpuPool;
    use mock_command::*;
    use std::fs::{self,File};
    use std::io::Write;
    use std::time::Duration;
    use std::usize;
    use test::utils::*;

    #[test]
    fn test_detect_compiler_kind_gcc() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nbar\ngcc", "")));
        assert_eq!(Some(CompilerKind::Gcc), detect_compiler_kind(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_kind_clang() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "clang\nfoo", "")));
        assert_eq!(Some(CompilerKind::Clang), detect_compiler_kind(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_kind_msvc() {
        use env_logger;
        match env_logger::init() {
            Ok(_) => {},
            Err(_) => {},
        }
        let creator = new_creator();
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
        assert_eq!(Some(CompilerKind::Msvc { includes_prefix: prefix }), detect_compiler_kind(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_kind_unknown() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "something", "")));
        assert_eq!(None, detect_compiler_kind(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_kind_process_fail() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert_eq!(None, detect_compiler_kind(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_get_compiler_info() {
        let creator = new_creator();
        let f = TestFixture::new();
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(creator.clone(),
                                  f.bins[0].to_str().unwrap()).unwrap();
        assert_eq!(f.bins[0].to_str().unwrap(), c.executable);
        // sha-1 digest of an empty file.
        assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", c.digest);
        assert_eq!(CompilerKind::Gcc, c.kind);
    }

    #[test]
    fn test_compiler_get_cached_or_compile_uncached() {
        use env_logger;
        match env_logger::init() {
            Ok(_) => {},
            Err(_) => {},
        }
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(creator.clone(),
                                  f.bins[0].to_str().unwrap()).unwrap();
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
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::Default).unwrap();
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
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::Default).unwrap();
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
        match env_logger::init() {
            Ok(_) => {},
            Err(_) => {},
        }
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(creator.clone(),
                                  f.bins[0].to_str().unwrap()).unwrap();
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
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::Default).unwrap();
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
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::Default).unwrap();
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
        match env_logger::init() {
            Ok(_) => {},
            Err(_) => {},
        }
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(creator.clone(),
                                  f.bins[0].to_str().unwrap()).unwrap();
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
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::Default).unwrap();
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
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::ForceRecache).unwrap();
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
        match env_logger::init() {
            Ok(_) => {},
            Err(_) => {},
        }
        let creator = new_creator();
        let f = TestFixture::new();
        let pool = CpuPool::new(1);
        let storage = DiskCache::new(&f.tempdir.path().join("cache"),
                                     usize::MAX,
                                     &pool);
        // Pretend to be GCC.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "gcc", "")));
        let c = get_compiler_info(creator.clone(),
                                  f.bins[0].to_str().unwrap()).unwrap();
        // The preprocessor invocation.
        const PREPROCESSOR_STDERR: &'static [u8] = b"something went wrong";
        next_command(&creator, Ok(MockChild::new(exit_status(1), b"preprocessor output", PREPROCESSOR_STDERR)));
        let cwd = f.tempdir.path().to_str().unwrap();
        let arguments = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let parsed_args = match c.parse_arguments(&arguments, ".".as_ref()) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd, CacheControl::Default).unwrap();
        assert_eq!(cached, CompileResult::Error);
        assert_eq!(exit_status(1), res.status);
        // Shouldn't get anything on stdout, since that would just be preprocessor spew!
        assert_eq!(b"", res.stdout.as_slice());
        assert_eq!(PREPROCESSOR_STDERR, res.stderr.as_slice());
    }
}
