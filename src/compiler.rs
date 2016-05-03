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

use log::LogLevel::Trace;
use mock_command::{
    CommandChild,
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self,Error,ErrorKind,Write};
use std::path::Path;
use std::process::{self,Stdio};
use std::str;
use tempdir::TempDir;

/// Supported compilers.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Compiler {
    /// GCC
    Gcc,
    /// clang
    Clang,
    /// Microsoft Visual C++
    Msvc,
}

/// Write `contents` to `path`.
fn write_file(path : &Path, contents: &[u8]) -> io::Result<()> {
    let mut f = try!(File::create(path));
    f.write_all(contents)
}

/// If this is using a known compiler, return the compiler type.
pub fn detect_compiler<T : CommandCreatorSync>(mut creator : T,  executable : &str) -> Option<Compiler> {
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
                                    return Ok(Some(Compiler::Gcc));
                                } else if line == "clang" {
                                    trace!("Found clang");
                                    return Ok(Some(Compiler::Clang));
                                } else if line == "msvc" {
                                    trace!("Found MSVC");
                                    return Ok(Some(Compiler::Msvc));
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

/// Run `cmdline` in `cwd` using `creator`, and return the exit status.
pub fn run_compiler<T : CommandCreatorSync>(mut creator : T, cmdline : &Vec<String>, cwd : &str) -> io::Result<process::ExitStatus> {
    if log_enabled!(Trace) {
        let cmd_str = cmdline.join(" ");
        trace!("run_compiler: '{}' in '{}'", cmd_str, cwd);
    }
    //TODO: should allow capturing output.
    creator.new_command_sync(&cmdline[0])
        .args(&cmdline[1..])
        .current_dir(cwd)
        .spawn()
        .and_then(|mut child| child.wait())
}

#[cfg(test)]
mod test {
    use super::*;
    use mock_command::*;
    use std::io;
    use std::sync::{Arc,Mutex};

    fn new_creator() -> Arc<Mutex<MockCommandCreator>> {
        Arc::new(Mutex::new(MockCommandCreator::new()))
    }

    fn next_command(creator : &Arc<Mutex<MockCommandCreator>>,
                    child: io::Result<MockChild>) {
        creator.lock().unwrap().next_command_spawns(child);
    }

    #[test]
    fn test_detect_compiler_gcc() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nbar\ngcc", "")));
        assert_eq!(Some(Compiler::Gcc), detect_compiler(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_clang() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "clang\nfoo", "")));
        assert_eq!(Some(Compiler::Clang), detect_compiler(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_msvc() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nmsvc\nbar", "")));
        assert_eq!(Some(Compiler::Msvc), detect_compiler(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_unknown() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "something", "")));
        assert_eq!(None, detect_compiler(creator.clone(), "/foo/bar"));
    }

    #[test]
    fn test_detect_compiler_process_fail() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        assert_eq!(None, detect_compiler(creator.clone(), "/foo/bar"));
    }
}
