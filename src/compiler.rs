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
    RunCommand,
};
use std::io;
use std::process;

/// Supported compilers.
#[allow(dead_code)]
pub enum Compiler {
    /// GCC
    Gcc,
    /// clang
    Clang,
    /// Microsoft Visual C++
    Msvc,
}

/// If this is using a known compiler, return the compiler type.
pub fn can_handle_compile(_cmdline : &Vec<String>) -> Option<Compiler> {
    //TODO: actually implement this
    None
}

/// Run `cmdline` in `cwd` using `creator`, and return the exit status.
pub fn run_compiler<T : CommandCreator>(creator : &mut T, cmdline : &Vec<String>, cwd : &str) -> io::Result<process::ExitStatus> {
    if log_enabled!(Trace) {
        let cmd_str = cmdline.join(" ");
        trace!("run_compiler: '{}' in '{}'", cmd_str, cwd);
    }
    //TODO: should allow capturing output.
    creator.new_command(&cmdline[0])
        .args(&cmdline[1..])
        .current_dir(cwd)
        .spawn()
        .and_then(|mut child| child.wait())
}
