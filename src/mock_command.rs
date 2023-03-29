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

//! Traits and types for mocking process execution.
//!
//! This module provides a set of traits and types that can be used
//! to write code that expects to execute processes using `std::process::Command`
//! in a way that can be mocked for tests.
//!
//! Instead of using `Command::new()`, make your code generic using
//! `CommandCreator` as a trait bound, and use its `new_command` method.
//! `new_command` returns an object implementing `CommandChild`, which
//! mirrors the methods of `Command`.
//!
//! For production use, you can then instantiate your code with
//! `ProcessCommandCreator`, which simply returns `Command::new()` from
//! its `new_command` method.
//!
//! For testing, you can instantiate your code with `MockCommandCreator`,
//! which creates `MockCommand` objects which in turn spawn `MockChild`
//! objects. You can use `MockCommand::next_command_spawns` to provide
//! the result of `spawn` from the next `MockCommand` that it creates.
//! `MockCommandCreator::new_command` will fail an `assert` if it attempts
//! to create a command and does not have any pending `MockChild` objects
//! to hand out, so your tests must provide enough outputs for all
//! expected process executions in the test.
//!
//! If your code under test needs to spawn processes across threads, you
//! can use `CommandCreatorSync` as a trait bound, which is implemented for
//! `ProcessCommandCreator` (since it has no state), and also for
//! `Arc<Mutex<CommandCreator>>`. `CommandCreatorSync` provides a
//! `new_command_sync` method which your code can call to create new
//! objects implementing `CommandChild` in a thread-safe way. Your tests can
//! then create an `Arc<Mutex<MockCommandCreator>>` and safely provide
//! `MockChild` outputs.

use crate::errors::*;
use crate::jobserver::{Acquired, Client};
use async_trait::async_trait;
use std::boxed::Box;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

/// A trait that provides a subset of the methods of `std::process::Child`.
#[async_trait]
pub trait CommandChild {
    /// The type of the process' standard input.
    type I: AsyncWrite + Unpin + Sync + Send + 'static;
    /// The type of the process' standard output.
    type O: AsyncRead + Unpin + Sync + Send + 'static;
    /// The type of the process' standard error.
    type E: AsyncRead + Unpin + Sync + Send + 'static;

    /// Take the stdin object from the process, if available.
    fn take_stdin(&mut self) -> Option<Self::I>;
    /// Take the stdout object from the process, if available.
    fn take_stdout(&mut self) -> Option<Self::O>;
    /// Take the stderr object from the process, if available.
    fn take_stderr(&mut self) -> Option<Self::E>;
    /// Wait for the process to complete and return its exit status.
    async fn wait(self) -> io::Result<ExitStatus>;
    /// Wait for the process to complete and return its output.
    async fn wait_with_output(self) -> io::Result<Output>;
}

/// A trait that provides a subset of the methods of `std::process::Command`.
#[async_trait]
pub trait RunCommand: fmt::Debug + Send {
    /// The type returned by `spawn`.
    type C: CommandChild + Send + 'static;

    /// Append `arg` to the process commandline.
    fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self;
    /// Append `args` to the process commandline.
    fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut Self;
    /// Insert or update an environment variable mapping.
    fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>;
    /// Add or update multiple environment variable mappings.
    fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>;
    /// Clears the entire environment map for the child process.
    fn env_clear(&mut self) -> &mut Self;
    /// Set the working directory of the process to `dir`.
    fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self;
    /// Set the process' stdin from `cfg`.
    fn stdin(&mut self, cfg: Stdio) -> &mut Self;
    /// Set the process' stdout from `cfg`.
    fn stdout(&mut self, cfg: Stdio) -> &mut Self;
    /// Set the process' stderr from `cfg`.
    fn stderr(&mut self, cfg: Stdio) -> &mut Self;
    /// Execute the process and return a process object.
    async fn spawn(&mut self) -> Result<Self::C>;
}

/// A trait that provides a means to create objects implementing `RunCommand`.
///
/// This is provided so that `MockCommandCreator` can have state for testing.
/// For the non-testing scenario, `ProcessCommandCreator` is simply a unit
/// struct with a trivial implementation of this.
pub trait CommandCreator {
    /// The type returned by `new_command`.
    type Cmd: RunCommand;

    /// Create a new instance of this type.
    fn new(client: &Client) -> Self;
    /// Create a new object that implements `RunCommand` that can be used
    /// to create a new process.
    fn new_command<S: AsRef<OsStr>>(&mut self, program: S) -> Self::Cmd;
}

/// A trait for simplifying the normal case while still allowing the mock case requiring mutability.
pub trait CommandCreatorSync: Clone + Send + Sync + 'static {
    type Cmd: RunCommand;

    fn new(client: &Client) -> Self;

    fn new_command_sync<S: AsRef<OsStr>>(&mut self, program: S) -> Self::Cmd;
}

pub struct Child {
    inner: tokio::process::Child,
    token: Acquired,
}

/// Trivial implementation of `CommandChild` for `std::process::Child`.
#[async_trait]
impl CommandChild for Child {
    type I = ChildStdin;
    type O = ChildStdout;
    type E = ChildStderr;

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.inner.stdin.take()
    }
    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.inner.stdout.take()
    }
    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.inner.stderr.take()
    }

    async fn wait(self) -> io::Result<ExitStatus> {
        let Child { mut inner, token } = self;
        inner.wait().await.map(|ret| {
            drop(token);
            ret
        })
    }

    async fn wait_with_output(self) -> io::Result<Output> {
        let Child { inner, token } = self;
        inner.wait_with_output().await.map(|ret| {
            drop(token);
            ret
        })
    }
}

pub struct AsyncCommand {
    inner: Option<Command>,
    jobserver: Client,
}

impl AsyncCommand {
    pub fn new<S: AsRef<OsStr>>(program: S, jobserver: Client) -> AsyncCommand {
        AsyncCommand {
            inner: Some(Command::new(program)),
            jobserver,
        }
    }

    fn inner(&mut self) -> &mut Command {
        self.inner.as_mut().expect("can't reuse commands")
    }
}

/// Trivial implementation of `RunCommand` for `std::process::Command`.
#[async_trait]
impl RunCommand for AsyncCommand {
    type C = Child;

    fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut AsyncCommand {
        self.inner().arg(arg);
        self
    }
    fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut AsyncCommand {
        self.inner().args(args);
        self
    }
    fn env<K, V>(&mut self, key: K, val: V) -> &mut AsyncCommand
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.inner().env(key, val);
        self
    }
    fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.inner().envs(vars);
        self
    }
    fn env_clear(&mut self) -> &mut AsyncCommand {
        self.inner().env_clear();
        self
    }
    fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut AsyncCommand {
        self.inner().current_dir(dir);
        self
    }

    fn stdin(&mut self, cfg: Stdio) -> &mut AsyncCommand {
        self.inner().stdin(cfg);
        self
    }
    fn stdout(&mut self, cfg: Stdio) -> &mut AsyncCommand {
        self.inner().stdout(cfg);
        self
    }
    fn stderr(&mut self, cfg: Stdio) -> &mut AsyncCommand {
        self.inner().stderr(cfg);
        self
    }
    async fn spawn(&mut self) -> Result<Child> {
        let mut inner = self.inner.take().unwrap();
        inner.env_remove("MAKEFLAGS");
        inner.env_remove("MFLAGS");
        inner.env_remove("CARGO_MAKEFLAGS");
        self.jobserver.configure(&mut inner);

        let token = self.jobserver.acquire().await?;
        let mut inner = tokio::process::Command::from(inner);
        let child = inner
            .spawn()
            .with_context(|| format!("failed to spawn {:?}", inner))?;

        Ok(Child {
            inner: child,
            token,
        })
    }
}

impl fmt::Debug for AsyncCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Struct to use `RunCommand` with `std::process::Command`.
#[derive(Clone)]
pub struct ProcessCommandCreator {
    jobserver: Client,
}

/// Trivial implementation of `CommandCreator` for `ProcessCommandCreator`.
impl CommandCreator for ProcessCommandCreator {
    type Cmd = AsyncCommand;

    fn new(client: &Client) -> ProcessCommandCreator {
        ProcessCommandCreator {
            jobserver: client.clone(),
        }
    }

    fn new_command<S: AsRef<OsStr>>(&mut self, program: S) -> AsyncCommand {
        AsyncCommand::new(program, self.jobserver.clone())
    }
}

/// Trivial implementation of `CommandCreatorSync` for `ProcessCommandCreator`.
impl CommandCreatorSync for ProcessCommandCreator {
    type Cmd = AsyncCommand;

    fn new(client: &Client) -> ProcessCommandCreator {
        CommandCreator::new(client)
    }

    fn new_command_sync<S: AsRef<OsStr>>(&mut self, program: S) -> AsyncCommand {
        // This doesn't actually use any mutable state.
        self.new_command(program)
    }
}

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

#[cfg(unix)]
pub type ExitStatusValue = i32;
#[cfg(windows)]
pub type ExitStatusValue = u32;

#[allow(dead_code)]
pub fn exit_status(v: ExitStatusValue) -> ExitStatus {
    ExitStatus::from_raw(v)
}

/// A struct that mocks `std::process::Child`.
#[allow(dead_code)]
#[derive(Debug)]
pub struct MockChild {
    //TODO: this doesn't work to actually track writes...
    /// A `Cursor` to hand out as stdin.
    pub stdin: Option<io::Cursor<Vec<u8>>>,
    /// A `Cursor` to hand out as stdout.
    pub stdout: Option<io::Cursor<Vec<u8>>>,
    /// A `Cursor` to hand out as stderr.
    pub stderr: Option<io::Cursor<Vec<u8>>>,
    /// The `Result` to be handed out when `wait` is called.
    pub wait_result: Option<io::Result<ExitStatus>>,
}

/// A mocked child process that simply returns stored values for its status and output.
impl MockChild {
    /// Create a `MockChild` that will return the specified `status`, `stdout`, and `stderr` when waited upon.
    #[allow(dead_code)]
    pub fn new<T: AsRef<[u8]>, U: AsRef<[u8]>>(
        status: ExitStatus,
        stdout: T,
        stderr: U,
    ) -> MockChild {
        MockChild {
            stdin: Some(io::Cursor::new(vec![])),
            stdout: Some(io::Cursor::new(stdout.as_ref().to_vec())),
            stderr: Some(io::Cursor::new(stderr.as_ref().to_vec())),
            wait_result: Some(Ok(status)),
        }
    }

    /// Create a `MockChild` that will return the specified `err` when waited upon.
    #[allow(dead_code)]
    pub fn with_error(err: io::Error) -> MockChild {
        MockChild {
            stdin: None,
            stdout: None,
            stderr: None,
            wait_result: Some(Err(err)),
        }
    }
}

#[async_trait]
impl CommandChild for MockChild {
    type I = io::Cursor<Vec<u8>>;
    type O = io::Cursor<Vec<u8>>;
    type E = io::Cursor<Vec<u8>>;

    fn take_stdin(&mut self) -> Option<io::Cursor<Vec<u8>>> {
        self.stdin.take()
    }
    fn take_stdout(&mut self) -> Option<io::Cursor<Vec<u8>>> {
        self.stdout.take()
    }
    fn take_stderr(&mut self) -> Option<io::Cursor<Vec<u8>>> {
        self.stderr.take()
    }

    async fn wait(mut self) -> io::Result<ExitStatus> {
        self.wait_result.take().unwrap()
    }

    async fn wait_with_output(self) -> io::Result<Output> {
        let MockChild {
            stdout,
            stderr,
            wait_result,
            ..
        } = self;

        wait_result.unwrap().map(|status| Output {
            status,
            stdout: stdout.map(|c| c.into_inner()).unwrap_or_else(Vec::new),
            stderr: stderr.map(|c| c.into_inner()).unwrap_or_else(Vec::new),
        })
    }
}

pub enum ChildOrCall {
    Child(Result<MockChild>),
    Call(Box<dyn Fn(&[OsString]) -> Result<MockChild> + Send>),
}

impl fmt::Debug for ChildOrCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ChildOrCall::Child(ref r) => write!(f, "ChildOrCall::Child({:?}", r),
            ChildOrCall::Call(_) => write!(f, "ChildOrCall::Call(...)"),
        }
    }
}

/// A mocked command that simply returns its `child` from `spawn`.
#[allow(dead_code)]
#[derive(Debug)]
pub struct MockCommand {
    pub child: Option<ChildOrCall>,
    pub args: Vec<OsString>,
}

#[async_trait]
impl RunCommand for MockCommand {
    type C = MockChild;

    fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut MockCommand {
        self.args.push(arg.as_ref().to_owned());
        self
    }
    fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut MockCommand {
        self.args.extend(args.iter().map(|a| a.as_ref().to_owned()));
        self
    }
    fn env<K, V>(&mut self, _key: K, _val: V) -> &mut MockCommand
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self
    }
    fn envs<I, K, V>(&mut self, _vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self
    }
    fn env_clear(&mut self) -> &mut MockCommand {
        self
    }
    fn current_dir<P: AsRef<Path>>(&mut self, _dir: P) -> &mut MockCommand {
        //TODO: assert value of dir
        self
    }
    fn stdin(&mut self, _cfg: Stdio) -> &mut MockCommand {
        self
    }
    fn stdout(&mut self, _cfg: Stdio) -> &mut MockCommand {
        self
    }
    fn stderr(&mut self, _cfg: Stdio) -> &mut MockCommand {
        self
    }
    async fn spawn(&mut self) -> Result<MockChild> {
        match self.child.take().unwrap() {
            ChildOrCall::Child(c) => c,
            ChildOrCall::Call(f) => f(&self.args),
        }
    }
}

/// `MockCommandCreator` allows mocking out process creation by providing `MockChild` instances to be used in advance.
#[allow(dead_code)]
pub struct MockCommandCreator {
    /// Data to be used as the return value of `MockCommand::spawn`.
    pub children: Vec<ChildOrCall>,
}

impl MockCommandCreator {
    /// The next `MockCommand` created will return `child` from `RunCommand::spawn`.
    #[allow(dead_code)]
    pub fn next_command_spawns(&mut self, child: Result<MockChild>) {
        self.children.push(ChildOrCall::Child(child));
    }

    /// The next `MockCommand` created will call `call` with the command-line
    /// arguments passed to the command.
    #[allow(dead_code)]
    pub fn next_command_calls<C>(&mut self, call: C)
    where
        C: Fn(&[OsString]) -> Result<MockChild> + Send + 'static,
    {
        self.children.push(ChildOrCall::Call(Box::new(call)));
    }
}

impl CommandCreator for MockCommandCreator {
    type Cmd = MockCommand;

    fn new(_client: &Client) -> MockCommandCreator {
        MockCommandCreator {
            children: Vec::new(),
        }
    }

    fn new_command<S: AsRef<OsStr>>(&mut self, _program: S) -> MockCommand {
        assert!(!self.children.is_empty(), "Too many calls to MockCommandCreator::new_command, or not enough to MockCommandCreator::new_command_spawns!");
        //TODO: assert value of program
        MockCommand {
            child: Some(self.children.remove(0)),
            args: vec![],
        }
    }
}

/// To simplify life for using a `CommandCreator` across multiple threads.
impl<T: CommandCreator + 'static + Send> CommandCreatorSync for Arc<Mutex<T>> {
    type Cmd = T::Cmd;

    fn new(client: &Client) -> Arc<Mutex<T>> {
        Arc::new(Mutex::new(T::new(client)))
    }

    fn new_command_sync<S: AsRef<OsStr>>(&mut self, program: S) -> T::Cmd {
        self.lock().unwrap().new_command(program)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::jobserver::Client;
    use crate::test::utils::*;
    use std::ffi::OsStr;
    use std::io;
    use std::process::{ExitStatus, Output};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn spawn_command<T: CommandCreator, S: AsRef<OsStr>>(
        creator: &mut T,
        program: S,
    ) -> Result<<<T as CommandCreator>::Cmd as RunCommand>::C> {
        creator.new_command(program).spawn().wait()
    }

    fn spawn_wait_command<T: CommandCreator, S: AsRef<OsStr>>(
        creator: &mut T,
        program: S,
    ) -> Result<ExitStatus> {
        Ok(spawn_command(creator, program)?.wait().wait()?)
    }

    fn spawn_output_command<T: CommandCreator, S: AsRef<OsStr>>(
        creator: &mut T,
        program: S,
    ) -> Result<Output> {
        Ok(spawn_command(creator, program)?.wait_with_output().wait()?)
    }

    fn spawn_on_thread<T: CommandCreatorSync + Send + 'static>(
        mut t: T,
        really: bool,
    ) -> ExitStatus {
        thread::spawn(move || {
            if really {
                t.new_command_sync("foo")
                    .spawn()
                    .wait()
                    .unwrap()
                    .wait()
                    .wait()
                    .unwrap()
            } else {
                exit_status(1)
            }
        })
        .join()
        .unwrap()
    }

    #[test]
    fn test_mock_command_wait() {
        let client = Client::new_num(1);
        let mut creator = MockCommandCreator::new(&client);
        creator.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
        assert_eq!(
            0,
            spawn_wait_command(&mut creator, "foo")
                .unwrap()
                .code()
                .unwrap()
        );
    }

    #[test]
    #[should_panic]
    fn test_unexpected_new_command() {
        // If next_command_spawns hasn't been called enough times,
        // new_command should panic.
        let client = Client::new_num(1);
        let mut creator = MockCommandCreator::new(&client);
        creator.new_command("foo").spawn().wait().unwrap();
    }

    #[test]
    fn test_mock_command_output() {
        let client = Client::new_num(1);
        let mut creator = MockCommandCreator::new(&client);
        creator.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
        let output = spawn_output_command(&mut creator, "foo").unwrap();
        assert_eq!(0, output.status.code().unwrap());
        assert_eq!(b"hello".to_vec(), output.stdout);
        assert_eq!(b"error".to_vec(), output.stderr);
    }

    #[test]
    fn test_mock_command_calls() {
        let client = Client::new_num(1);
        let mut creator = MockCommandCreator::new(&client);
        creator.next_command_calls(|_| Ok(MockChild::new(exit_status(0), "hello", "error")));
        let output = spawn_output_command(&mut creator, "foo").unwrap();
        assert_eq!(0, output.status.code().unwrap());
        assert_eq!(b"hello".to_vec(), output.stdout);
        assert_eq!(b"error".to_vec(), output.stderr);
    }

    #[test]
    fn test_mock_spawn_error() {
        let client = Client::new_num(1);
        let mut creator = MockCommandCreator::new(&client);
        creator.next_command_spawns(Err(anyhow!("error")));
        let e = spawn_command(&mut creator, "foo").err().unwrap();
        assert_eq!("error", e.to_string());
    }

    #[test]
    fn test_mock_wait_error() {
        let client = Client::new_num(1);
        let mut creator = MockCommandCreator::new(&client);
        creator.next_command_spawns(Ok(MockChild::with_error(io::Error::new(
            io::ErrorKind::Other,
            "error",
        ))));
        let e = spawn_wait_command(&mut creator, "foo").err().unwrap();
        assert_eq!("error", e.to_string());
    }

    #[test]
    fn test_mock_command_sync() {
        let client = Client::new_num(1);
        let creator = Arc::new(Mutex::new(MockCommandCreator::new(&client)));
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), "hello", "error")),
        );
        assert_eq!(exit_status(0), spawn_on_thread(creator, true));
    }
}
