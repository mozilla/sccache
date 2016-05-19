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

    /*
    pub fn dump_info(&self) {
        println!("executable: {}", self.executable);
        println!("mtime: {}", self.mtime);
        println!("digest: {}", self.digest);
    }
    */

    /// Check that this compiler can handle and cache when run with `arguments`, and parse out the relevant bits.
    ///
    /// Not all compiler options can be cached, so this tests the set of
    /// options for each compiler.
    pub fn parse_arguments(&self, arguments: &[String]) -> CompilerArguments {
        match self.kind {
            CompilerKind::Gcc => gcc::parse_arguments(arguments),
            CompilerKind::Clang => clang::parse_arguments(arguments),
            CompilerKind::Msvc => msvc::parse_arguments(arguments),
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

/// Whether to capture a processes output or inherit the parent stdio handles.
#[derive(PartialEq)]
pub enum ProcessOutput {
    /// Capture process output.
    Capture,
    /// Inherit parent stdio handles.
    Inherit,
}

/// Run `cmdline` in `cwd` using `creator`, and return the exit status.
pub fn run_compiler<T : CommandCreatorSync>(mut creator : T, cmdline : Vec<String>, cwd : &str, capture_output: ProcessOutput) -> io::Result<process::Output> {
    if log_enabled!(Trace) {
        let cmd_str = cmdline.join(" ");
        trace!("run_compiler: '{}' in '{}'", cmd_str, cwd);
    }
    let capture = capture_output == ProcessOutput::Capture;
    creator.new_command_sync(&cmdline[0])
        .args(&cmdline[1..])
        .current_dir(cwd)
        .stdout(if capture { Stdio::piped() } else { Stdio::inherit() })
        .stderr(if capture { Stdio::piped() } else { Stdio::inherit() })
        .spawn()
        .and_then(|child| child.wait_with_output())
}

#[cfg(test)]
mod test {
    use super::*;
    use mock_command::*;
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

/*
    #[test]
    fn foo() {
        use std::env;
        use mock_command::ProcessCommandCreator;
        let creator = ProcessCommandCreator;
        let executable = env::args().skip_while(|a| a != "foo").nth(1).unwrap();
        let compiler = get_compiler_info(creator, &executable).unwrap();
        compiler.dump_info();
    }
*/
}
