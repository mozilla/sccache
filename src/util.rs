// Copyright 2017 Mozilla Foundation
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

use futures::future;
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::{CommandChild, RunCommand};
use sha1;
use std::ffi::OsStr;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::{self,Stdio};
use std::time::Duration;

use errors::*;

/// Calculate the SHA-1 digest of the contents of `path`, running
/// the actual hash computation on a background thread in `pool`.
pub fn sha1_digest<T>(path: T, pool: &CpuPool) -> SFuture<String>
    where T: Into<PathBuf>
{
    let path = path.into();
    Box::new(pool.spawn_fn(move || -> Result<_> {
        let f = File::open(&path).chain_err(|| format!("Failed to open file for hashing: {:?}", path))?;
        let mut m = sha1::Sha1::new();
        let mut reader = BufReader::new(f);
        loop {
            let mut buffer = [0; 1024];
            let count = reader.read(&mut buffer[..])?;
            if count == 0 {
                break;
            }
            m.update(&buffer[..count]);
        }
        Ok(m.digest().to_string())
    }))
}

/// Format `duration` as seconds with a fractional component.
pub fn fmt_duration_as_secs(duration: &Duration) -> String
{
    format!("{}.{:03}s", duration.as_secs(), duration.subsec_nanos() / 1000_000)
}


#[cfg(unix)]
pub fn os_str_bytes(s: &OsStr) -> &[u8]
{
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes()
}

#[cfg(windows)]
pub fn os_str_bytes(s: &OsStr) -> &[u8]
{
    use std::mem;
    unsafe { mem::transmute(s) }
}

/// If `input`, write it to `child`'s stdin while also reading `child`'s stdout and stderr, then wait on `child` and return its status and output.
///
/// This was lifted from `std::process::Child::wait_with_output` and modified
/// to also write to stdin.
fn wait_with_input_output<T>(mut child: T, input: Option<Vec<u8>>)
                             -> SFuture<process::Output>
    where T: CommandChild + 'static,
{
    use tokio_io::io::{write_all, read_to_end};
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

#[test]
fn test_os_str_bytes() {
    // Just very basic sanity checks in case anyone changes the underlying
    // representation of OsStr on Windows.
    assert_eq!(os_str_bytes(OsStr::new("hello")), b"hello");
    assert_eq!(os_str_bytes(OsStr::new("你好")), "你好".as_bytes());
}
