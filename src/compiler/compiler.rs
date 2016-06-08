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
    Storage,
    hash_key,
};
use compiler::{
    clang,
    gcc,
    msvc,
};
use filetime::FileTime;
use log::LogLevel::Trace;
use mock_command::{
    CommandChild,
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
    exit_status,
};
use sha1;
use std::collections::HashMap;
use std::ffi::OsString;
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
use tempdir::TempDir;

/// Supported compilers.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CompilerKind {
    /// GCC
    Gcc,
    /// clang
    Clang,
    /// Microsoft Visual C++
    Msvc,
}

impl CompilerKind {
    pub fn parse_arguments(&self, arguments: &[String]) -> CompilerArguments {
        match self {
            // GCC and clang share the same argument parsing logic, but
            // accept different sets of arguments.
            &CompilerKind::Gcc => gcc::parse_arguments(arguments, gcc::argument_takes_value),
            &CompilerKind::Clang => gcc::parse_arguments(arguments, clang::argument_takes_value),
            &CompilerKind::Msvc => msvc::parse_arguments(arguments),
        }
    }

    pub fn preprocess<T : CommandCreatorSync>(&self, creator: T, compiler: &Compiler, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
        match self {
            &CompilerKind::Gcc | &CompilerKind::Clang => {
                // GCC and clang use the same preprocessor invocation.
                gcc::preprocess(creator, compiler, parsed_args, cwd)
            },
            &CompilerKind::Msvc => msvc::preprocess(creator, compiler, parsed_args, cwd),
        }
    }

    pub fn compile<T : CommandCreatorSync>(&self, creator: T, compiler: &Compiler, preprocessor_output: Vec<u8>, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
        match self {
            &CompilerKind::Gcc => gcc::compile(creator, compiler, preprocessor_output, parsed_args, cwd),
            &CompilerKind::Clang => clang::compile(creator, compiler, preprocessor_output, parsed_args, cwd),
            &CompilerKind::Msvc => msvc::compile(creator, compiler, preprocessor_output, parsed_args, cwd),
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
    /// Output files, keyed by a simple name, like "obj".
    pub outputs: HashMap<&'static str, String>,
    /// Commandline arguments for the preprocessor.
    pub preprocessor_args: Vec<String>,
    /// Commandline arguments for the preprocessor or the compiler.
    pub common_args: Vec<String>,
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

/// The result of a compilation or cache retrieval.
#[derive(Debug, PartialEq)]
pub enum CompileResult {
    /// An error made the compilation not possible.
    Error,
    /// Result was found in cache.
    CacheHit,
    /// Result was not found in cache.
    CacheMiss,
    /// Not in cache, but compilation failed.
    CompileFailed,
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
            digest: m.hexdigest(),
            kind: kind,
        })
    }

    /// Check that this compiler can handle and cache when run with `arguments`, and parse out the relevant bits.
    ///
    /// Not all compiler options can be cached, so this tests the set of
    /// options for each compiler.
    pub fn parse_arguments(&self, arguments: &[String]) -> CompilerArguments {
        if log_enabled!(Trace) {
            let cmd_str = arguments.join(" ");
            trace!("parse_arguments: `{}`", cmd_str);
        }
        let parsed_args = self.kind.parse_arguments(arguments);
        match parsed_args {
            CompilerArguments::Ok(_) => trace!("parse_arguments: Ok"),
            CompilerArguments::CannotCache => trace!("parse_arguments: CannotCache"),
            CompilerArguments::NotCompilation => trace!("parse_arguments: NotCompilation"),
        };
        parsed_args
    }

    pub fn get_cached_or_compile<T : CommandCreatorSync>(&self, creator: T, storage: &Storage, arguments: &[String], parsed_args: &ParsedArguments, cwd: &str) -> io::Result<(CompileResult, process::Output)> {
        if log_enabled!(Trace) {
            let cmd_str = arguments.join(" ");
            trace!("get_cached_or_compile: {}", cmd_str);
        }
        let preprocessor_result = try!(self.kind.preprocess(creator.clone(), self, parsed_args, cwd));
        // If the preprocessor failed, just return that result.
        if !preprocessor_result.status.success() {
            return Ok((CompileResult::Error, preprocessor_result));
        }
        trace!("Preprocessor output is {} bytes", preprocessor_result.stdout.len());

        let key = hash_key(self, arguments, &preprocessor_result.stdout);
        trace!("Hash key: {}", key);
        let pwd = Path::new(cwd);
        let outputs = parsed_args.outputs.iter()
            .map(|(key, path)| (key, pwd.join(path)))
            .collect::<HashMap<_, _>>();
        storage.get(&key)
            .map(|mut entry| {
                debug!("Cache hit!");
                for (key, path) in outputs.iter() {
                    let mut f = try!(File::create(path));
                    try!(entry.get_object(key, &mut f));
                }
                let mut stdout = io::Cursor::new(vec!());
                let mut stderr = io::Cursor::new(vec!());
                entry.get_object("stdout", &mut stdout).unwrap_or(());
                entry.get_object("stderr", &mut stderr).unwrap_or(());
                Ok((CompileResult::CacheHit,
                    process::Output {
                        status: exit_status(0),
                        stdout: stdout.into_inner(),
                        stderr: stderr.into_inner(),
                    }))
            })
            .unwrap_or_else(move || {
                debug!("Cache miss!");
                let process::Output { stdout, .. } = preprocessor_result;
                let compiler_result = try!(self.kind.compile(creator, self, stdout, parsed_args, cwd));
                if compiler_result.status.success() {
                    trace!("Compiled, storing in cache");
                    let mut entry = try!(storage.start_put(&key));
                    for (key, path) in outputs.iter() {
                        let mut f = try!(File::open(&path));
                        try!(entry.put_object(key, &mut f)
                             .or_else(|e| {
                                 error!("Failed to put object `{:?}` in storage: {:?}", path, e);
                                 Err(e)
                             }));
                    }
                    if !compiler_result.stdout.is_empty() {
                        try!(entry.put_object("stdout", &mut io::Cursor::new(&compiler_result.stdout)));
                    }
                    if !compiler_result.stderr.is_empty() {
                        try!(entry.put_object("stderr", &mut io::Cursor::new(&compiler_result.stderr)));
                    }
                    //TODO: do this on a background thread.
                    try!(storage.finish_put(&key, entry));
                    Ok((CompileResult::CacheMiss, compiler_result))
                } else {
                    trace!("Compiled but failed, not storing in cache");
                    Ok((CompileResult::CompileFailed, compiler_result))
                }

            })
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
                        .or(Err(Error::new(ErrorKind::Other, "Failed to parse output")))
                        .and_then(|stdout| {
                            for line in stdout.lines() {
                                //TODO: do something smarter here.
                                if line == "gcc" {
                                    trace!("Found GCC");
                                    return Ok(Some(CompilerKind::Gcc));
                                } else if line == "clang" {
                                    trace!("Found clang");
                                    return Ok(Some(CompilerKind::Clang));
                                } else if line == "msvc" {
                                    trace!("Found MSVC");
                                    return Ok(Some(CompilerKind::Msvc));
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
    detect_compiler_kind(creator, &executable)
        .and_then(|kind| {
            Compiler::new(&executable, kind)
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
        stdout: stdout.unwrap_or(Vec::new()),
        stderr: stderr.unwrap_or(Vec::new()),
    })
}

/// Run `command`, writing `input` to its stdin if it is `Some` and return the exit status and output.
pub fn run_input_output<C: RunCommand>(mut command: C, input: Option<Vec<u8>>) -> io::Result<process::Output> {
    command.stdin(if input.is_some() { Stdio::piped() } else { Stdio::inherit() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|child| wait_with_input_output(child, input))
}

#[cfg(test)]
mod test {
    use super::*;
    use cache::disk::DiskCache;
    use mock_command::*;
    use std::fs::{self,File};
    use std::io::Write;
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
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nmsvc\nbar", "")));
        assert_eq!(Some(CompilerKind::Msvc), detect_compiler_kind(creator.clone(), "/foo/bar"));
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
        let storage = DiskCache::new(&f.tempdir.path());
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
        let parsed_args = match c.parse_arguments(&arguments) {
            CompilerArguments::Ok(parsed) => parsed,
            o @ _ => panic!("Bad result from parse_arguments: {:?}", o),
        };
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd).unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        assert_eq!(CompileResult::CacheMiss, cached);
        assert_eq!(exit_status(0), res.status);
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
        // Now compile again, which should be a cache hit.
        fs::remove_file(&obj).unwrap();
        // The preprocessor invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "preprocessor output", "")));
        // There should be no actual compiler invocation.
        let (cached, res) = c.get_cached_or_compile(creator.clone(), &storage, &arguments, &parsed_args, cwd).unwrap();
        // Ensure that the object file was created.
        assert_eq!(true, fs::metadata(&obj).and_then(|m| Ok(m.len() > 0)).unwrap());
        assert_eq!(CompileResult::CacheHit, cached);
        assert_eq!(exit_status(0), res.status);
        //FIXME: this is broken!
        assert_eq!(COMPILER_STDOUT, res.stdout.as_slice());
        assert_eq!(COMPILER_STDERR, res.stderr.as_slice());
    }
}
