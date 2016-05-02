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

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{
    Child,
    Command,
    ExitStatus,
    Output,
};

pub trait CommandChild {
    fn wait(&mut self) -> io::Result<ExitStatus>;
    fn wait_with_output(self) -> io::Result<Output>;
}

impl CommandChild for Child {
    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.wait()
    }
    fn wait_with_output(self) -> io::Result<Output> {
        self.wait_with_output()
    }
}

pub trait RunCommand {
    type C: CommandChild;

    fn new<S: AsRef<OsStr>>(program: S) -> Self;
    fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut Self;
    fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self;
    fn spawn(&mut self) -> io::Result<Self::C>;
}

impl RunCommand for Command {
    type C = Child;

    fn new<S: AsRef<OsStr>>(program: S) -> Command {
        Command::new(program)
    }
    fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut Command {
        self.args(args)
    }
    fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Command {
        self.current_dir(dir)
    }
    fn spawn(&mut self) -> io::Result<Child> {
        self.spawn()
    }
}

pub trait CommandCreator {
    type Cmd: RunCommand;
    fn new_command<S: AsRef<OsStr>>(&self, program: S) -> Self::Cmd;
}

pub struct ProcessCommandCreator;

impl CommandCreator for ProcessCommandCreator {
    type Cmd = Command;
    fn new_command<S: AsRef<OsStr>>(&self, program: S) -> Command {
        Command::new(program)
    }
}
