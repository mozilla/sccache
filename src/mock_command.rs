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

#[cfg(unix)]
use libc;
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

    fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut Self;
    fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self;
    fn spawn(&mut self) -> io::Result<Self::C>;
}

impl RunCommand for Command {
    type C = Child;

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
    fn new_command<S: AsRef<OsStr>>(&mut self, program: S) -> Self::Cmd;
}

pub struct ProcessCommandCreator;

impl CommandCreator for ProcessCommandCreator {
    type Cmd = Command;
    fn new_command<S: AsRef<OsStr>>(&mut self, program: S) -> Command {
        Command::new(program)
    }
}


#[cfg(unix)]
pub type ExitStatusValue = libc::c_int;

#[cfg(windows)]
// DWORD
pub type ExitStatusValue = u32;

#[allow(dead_code)]
struct InnerExitStatus(ExitStatusValue);

/// Hack until `ExitStatus::from_raw()` is stable.
#[allow(dead_code)]
pub fn exit_status(v : ExitStatusValue) -> ExitStatus {
    use std::mem::transmute;
    unsafe { transmute(InnerExitStatus(v)) }
}

#[allow(dead_code)]
pub struct MockChild {
    pub output : Option<io::Result<Output>>,
}

impl MockChild {
    #[allow(dead_code)]
    pub fn new(status : ExitStatus, stdout : &str, stderr : &str) -> MockChild {
        MockChild {
            output : Some(Ok(Output {
                status: status,
                stdout: stdout.as_bytes().to_vec(),
                stderr: stderr.as_bytes().to_vec(),
            }))
        }
    }

    #[allow(dead_code)]
    pub fn with_error(err : io::Error) -> MockChild {
        MockChild {
            output : Some(Err(err)),
        }
    }
}

impl CommandChild for MockChild {
    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.output.take().unwrap().and_then(|o| Ok(o.status))
    }
    fn wait_with_output(self) -> io::Result<Output> {
        let MockChild { mut output } = self;
        output.take().unwrap()
    }
}

#[allow(dead_code)]
pub struct MockCommand {
    pub child : Option<io::Result<MockChild>>,
}

impl RunCommand for MockCommand {
    type C = MockChild;

    fn args<S: AsRef<OsStr>>(&mut self, _args: &[S]) -> &mut MockCommand {
        //TODO: assert value of args
        self
    }
    fn current_dir<P: AsRef<Path>>(&mut self, _dir: P) -> &mut MockCommand {
        //TODO: assert value of dir
        self
    }
    fn spawn(&mut self) -> io::Result<MockChild> {
        self.child.take().unwrap()
    }
}

#[allow(dead_code)]
pub struct MockCommandCreator {
    /// Data to be used as the return value of `MockCommand::spawn`.
    pub children : Vec<io::Result<MockChild>>,
}

impl MockCommandCreator {
    #[allow(dead_code)]
    pub fn new() -> MockCommandCreator {
        MockCommandCreator {
            children: vec!(),
        }
    }

    /// The next `MockCommand` created will return `child` from `RunCommand::spawn`.
    #[allow(dead_code)]
    pub fn next_command_spawns(&mut self, child : io::Result<MockChild>) {
        self.children.push(child);
    }
}

impl CommandCreator for MockCommandCreator {
    type Cmd = MockCommand;
    fn new_command<S: AsRef<OsStr>>(&mut self, _program: S) -> MockCommand {
        assert!(self.children.len() > 0, "Too many calls to MockCommandCreator::new_command, or not enough to MockCommandCreator::new_command_spawns!");
        //TODO: assert value of program
        MockCommand {
            child: Some(self.children.remove(0)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::error::Error;
    use std::ffi::OsStr;
    use std::io;
    use std::process::{
        ExitStatus,
        Output,
    };

    fn spawn_command<T : CommandCreator, S: AsRef<OsStr>>(creator : &mut T, program: S) -> io::Result<<<T as CommandCreator>::Cmd as RunCommand>::C> {
        creator.new_command(program).spawn()
    }

    fn spawn_wait_command<T : CommandCreator, S: AsRef<OsStr>>(creator : &mut T, program: S) -> io::Result<ExitStatus> {
        spawn_command(creator, program).and_then(|mut c| c.wait())
    }

    fn spawn_output_command<T : CommandCreator, S: AsRef<OsStr>>(creator : &mut T, program: S) -> io::Result<Output> {
        spawn_command(creator, program).and_then(|c| c.wait_with_output())
    }

    #[test]
    fn test_mock_command_wait() {
        let mut creator = MockCommandCreator::new();
        creator.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
        assert_eq!(0, spawn_wait_command(&mut creator, "foo").unwrap().code().unwrap());
    }

    #[test]
    fn test_mock_command_output() {
        let mut creator = MockCommandCreator::new();
        creator.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
        let output = spawn_output_command(&mut creator, "foo").unwrap();
        assert_eq!(0, output.status.code().unwrap());
        assert_eq!("hello".as_bytes().to_vec(), output.stdout);
        assert_eq!("error".as_bytes().to_vec(), output.stderr);
    }

    #[test]
    fn test_mock_spawn_error() {
        let mut creator = MockCommandCreator::new();
        creator.next_command_spawns(Err(io::Error::new(io::ErrorKind::Other, "error")));
        let e = spawn_command(&mut creator, "foo").err().unwrap();
        assert_eq!(io::ErrorKind::Other, e.kind());
        assert_eq!("error", e.description());
    }

    #[test]
    fn test_mock_wait_error() {
        let mut creator = MockCommandCreator::new();
        creator.next_command_spawns(Ok(MockChild::with_error(io::Error::new(io::ErrorKind::Other, "error"))));
        let e = spawn_wait_command(&mut creator, "foo").err().unwrap();
        assert_eq!(io::ErrorKind::Other, e.kind());
        assert_eq!("error", e.description());
    }
}
