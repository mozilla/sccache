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

use bincode;
use byteorder::{ByteOrder, BigEndian};
use futures::Future;
use futures_cpupool::CpuPool;
use mock_command::{CommandChild, RunCommand};
use ring::digest::{SHA512, Context};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::hash::Hasher;
use std::io::BufReader;
use std::io::prelude::*;
use std::path::Path;
use std::process::{self,Stdio};
use std::time::Duration;

use errors::*;

#[derive(Clone)]
pub struct Digest {
    inner: Context,
}

impl Digest {
    pub fn new() -> Digest {
        Digest { inner: Context::new(&SHA512) }
    }

    /// Calculate the SHA-512 digest of the contents of `path`, running
    /// the actual hash computation on a background thread in `pool`.
    pub fn file<T>(path: T, pool: &CpuPool) -> SFuture<String>
        where T: AsRef<Path>
    {
        let path = path.as_ref();
        let f = ftry!(File::open(&path).chain_err(|| format!("Failed to open file for hashing: {:?}", path)));
        Self::reader(f, pool)
    }

    pub fn reader<R: Read + Send + 'static>(rdr: R, pool: &CpuPool) -> SFuture<String> {
        Box::new(pool.spawn_fn(move || -> Result<_> {
            let mut m = Digest::new();
            let mut reader = BufReader::new(rdr);
            loop {
                let mut buffer = [0; 1024];
                let count = reader.read(&mut buffer[..])?;
                if count == 0 {
                    break;
                }
                m.update(&buffer[..count]);
            }
            Ok(m.finish())
        }))
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    pub fn finish(self) -> String {
        hex(self.inner.finish().as_ref())
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(hex(byte & 0xf));
        s.push(hex((byte >> 4)& 0xf));
    }
    return s;

    fn hex(byte: u8) -> char {
        match byte {
            0...9 => (b'0' + byte) as char,
            _ => (b'a' + byte - 10) as char,
        }
    }
}

/// Format `duration` as seconds with a fractional component.
pub fn fmt_duration_as_secs(duration: &Duration) -> String
{
    format!("{}.{:03} s", duration.as_secs(), duration.subsec_nanos() / 1000_000)
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
            write_all(stdin, i).chain_err(|| "failed to write stdin")
        })
    });
    let stdout = child.take_stdout().map(|io| {
        read_to_end(io, Vec::new()).chain_err(|| "failed to read stdout")
    });
    let stderr = child.take_stderr().map(|io| {
        read_to_end(io, Vec::new()).chain_err(|| "failed to read stderr")
    });

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
///
/// If the command returns a non-successful exit status, an error of `ErrorKind::ProcessError`
/// will be returned containing the process output.
pub fn run_input_output<C>(mut command: C, input: Option<Vec<u8>>)
                           -> SFuture<process::Output>
    where C: RunCommand
{
    let child = command
        .no_console()
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::inherit() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    Box::new(child
             .and_then(|child| {
                 wait_with_input_output(child, input).and_then(|output| {
                     if output.status.success() {
                         f_ok(output)
                     } else {
                         f_err(ErrorKind::ProcessError(output))
                     }
                 })
             }))
}

/// Write `data` to `writer` with bincode serialization, prefixed by a `u32` length.
pub fn write_length_prefixed_bincode<W, S>(mut writer: W, data: S) -> Result<()>
    where W: Write,
          S: Serialize,
{
    let bytes = bincode::serialize(&data)?;
    let mut len = [0; 4];
    BigEndian::write_u32(&mut len, bytes.len() as u32);
    writer.write_all(&len)?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub trait OsStrExt {
    fn starts_with(&self, s: &str) -> bool;
    fn split_prefix(&self, s: &str) -> Option<OsString>;
}

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _OsStrExt;

#[cfg(unix)]
impl OsStrExt for OsStr {
    fn starts_with(&self, s: &str) -> bool {
        self.as_bytes().starts_with(s.as_bytes())
    }

    fn split_prefix(&self, s: &str) -> Option<OsString> {
        let bytes = self.as_bytes();
        if bytes.starts_with(s.as_bytes()) {
            Some(OsStr::from_bytes(&bytes[s.len()..]).to_owned())
        } else {
            None
        }
    }
}

#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt as _OsStrExt, OsStringExt};

#[cfg(windows)]
impl OsStrExt for OsStr {
    fn starts_with(&self, s: &str) -> bool {
        // Attempt to interpret this OsStr as utf-16. This is a pretty "poor
        // man's" implementation, however, as it only handles a subset of
        // unicode characters in `s`. Currently that's sufficient, though, as
        // we're only calling `starts_with` with ascii string literals.
        let mut u16s = self.encode_wide();
        let mut utf8 = s.chars();

        while let Some(codepoint) = u16s.next() {
            let to_match = match utf8.next() {
                Some(ch) => ch,
                None => return true,
            };

            let to_match = to_match as u32;
            let codepoint = codepoint as u32;

            // UTF-16 encodes codepoints < 0xd7ff as just the raw value as a
            // u16, and that's all we're matching against. If the codepoint in
            // `s` is *over* this value then just assume it's not in `self`.
            //
            // If `to_match` is the same as the `codepoint` coming out of our
            // u16 iterator we keep going, otherwise we've found a mismatch.
            if to_match < 0xd7ff {
                if to_match != codepoint {
                    return false
                }
            } else {
                return false
            }
        }

        // If we ran out of characters to match, then the strings should be
        // equal, otherwise we've got more data to match in `s` so we didn't
        // start with `s`
        utf8.next().is_none()
    }

    fn split_prefix(&self, s: &str) -> Option<OsString> {
        // See comments in the above implementation for what's going on here
        let mut u16s = self.encode_wide().peekable();
        let mut utf8 = s.chars();

        while let Some(&codepoint) = u16s.peek() {
            let to_match = match utf8.next() {
                Some(ch) => ch,
                None => {
                    let codepoints = u16s.collect::<Vec<_>>();
                    return Some(OsString::from_wide(&codepoints))
                }
            };

            let to_match = to_match as u32;
            let codepoint = codepoint as u32;

            if to_match < 0xd7ff {
                if to_match != codepoint {
                    return None
                }
            } else {
                return None
            }
            u16s.next();
        }

        if utf8.next().is_none() {
            Some(OsString::new())
        } else {
            None
        }
    }
}

pub struct HashToDigest<'a> {
    pub digest: &'a mut Digest,
}

impl<'a> Hasher for HashToDigest<'a> {
    fn write(&mut self, bytes: &[u8]) {
        self.digest.update(bytes)
    }

    fn finish(&self) -> u64 {
        panic!("not supposed to be called");
    }
}

/// Turns a slice of environment var tuples into the type expected by Command::envs.
pub fn ref_env(env: &[(OsString, OsString)]) -> impl Iterator<Item = (&OsString, &OsString)> {
    env.iter().map(|&(ref k, ref v)| (k, v))
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use super::OsStrExt;

    #[test]
    fn simple_starts_with() {
        let a: &OsStr = "foo".as_ref();
        assert!(a.starts_with(""));
        assert!(a.starts_with("f"));
        assert!(a.starts_with("fo"));
        assert!(a.starts_with("foo"));
        assert!(!a.starts_with("foo2"));
        assert!(!a.starts_with("b"));
        assert!(!a.starts_with("b"));

        let a: &OsStr = "".as_ref();
        assert!(!a.starts_with("a"))
    }

    #[test]
    fn simple_strip_prefix() {
        let a: &OsStr = "foo".as_ref();

        assert_eq!(a.split_prefix(""), Some(OsString::from("foo")));
        assert_eq!(a.split_prefix("f"), Some(OsString::from("oo")));
        assert_eq!(a.split_prefix("fo"), Some(OsString::from("o")));
        assert_eq!(a.split_prefix("foo"), Some(OsString::from("")));
        assert_eq!(a.split_prefix("foo2"), None);
        assert_eq!(a.split_prefix("b"), None);
    }
}
