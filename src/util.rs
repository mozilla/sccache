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

use crate::mock_command::{CommandChild, RunCommand};
use ar::Archive;
use blake3::Hasher as blake3_Hasher;
use byteorder::{BigEndian, ByteOrder};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::hash::Hasher;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::str;
use std::time;
use std::time::Duration;

use crate::errors::*;

#[derive(Clone)]
pub struct Digest {
    inner: blake3_Hasher,
}

impl Digest {
    pub fn new() -> Digest {
        Digest {
            inner: blake3_Hasher::new(),
        }
    }

    /// Calculate the BLAKE3 digest of the contents of `path`, running
    /// the actual hash computation on a background thread in `pool`.
    pub async fn file<T>(path: T, pool: &tokio::runtime::Handle) -> Result<String>
    where
        T: AsRef<Path>,
    {
        Self::reader(path.as_ref().to_owned(), pool).await
    }

    /// Calculate the BLAKE3 digest of the contents read from `reader`.
    pub fn reader_sync<R: Read>(mut reader: R) -> Result<String> {
        let mut m = Digest::new();
        // A buffer of 128KB should give us the best performance.
        // See https://eklitzke.org/efficient-file-copying-on-linux.
        let mut buffer = [0; 128 * 1024];
        loop {
            let count = reader.read(&mut buffer[..])?;
            if count == 0 {
                break;
            }
            m.update(&buffer[..count]);
        }
        Ok(m.finish())
    }

    /// Calculate the BLAKE3 digest of the contents of `path`, running
    /// the actual hash computation on a background thread in `pool`.
    pub async fn reader(path: PathBuf, pool: &tokio::runtime::Handle) -> Result<String> {
        pool.spawn_blocking(move || {
            let reader = File::open(&path)
                .with_context(|| format!("Failed to open file for hashing: {:?}", path))?;
            Digest::reader_sync(reader)
        })
        .await?
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    pub fn finish(self) -> String {
        hex(self.inner.finalize().as_bytes())
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(hex(byte & 0xf));
        s.push(hex((byte >> 4) & 0xf));
    }
    return s;

    fn hex(byte: u8) -> char {
        match byte {
            0..=9 => (b'0' + byte) as char,
            _ => (b'a' + byte - 10) as char,
        }
    }
}

/// Calculate the digest of each file in `files` on background threads in
/// `pool`.
pub async fn hash_all(files: &[PathBuf], pool: &tokio::runtime::Handle) -> Result<Vec<String>> {
    let start = time::Instant::now();
    let count = files.len();
    let iter = files.iter().map(move |f| Digest::file(f, pool));
    let hashes = futures::future::try_join_all(iter).await?;
    trace!(
        "Hashed {} files in {}",
        count,
        fmt_duration_as_secs(&start.elapsed())
    );
    Ok(hashes)
}

/// Calculate the digest of each static library archive in `files` on background threads in
/// `pool`.
///
/// The hash is calculated by adding the filename of each archive entry followed
/// by its contents, ignoring headers and other file metadata. This primarily
/// exists because Apple's `ar` tool inserts timestamps for each file with
/// no way to disable this behavior.
pub async fn hash_all_archives(
    files: &[PathBuf],
    pool: &tokio::runtime::Handle,
) -> Result<Vec<String>> {
    let start = time::Instant::now();
    let count = files.len();
    let iter = files.iter().map(|path| {
        let path = path.clone();
        pool.spawn_blocking(move || -> Result<String> {
            let mut m = Digest::new();
            let reader = File::open(&path)
                .with_context(|| format!("Failed to open file for hashing: {:?}", path))?;
            let mut archive = Archive::new(reader);
            while let Some(entry) = archive.next_entry() {
                let entry = entry?;
                m.update(entry.header().identifier());
                update_from_reader(&mut m, entry)?;
            }
            Ok(m.finish())
        })
    });

    let mut hashes = futures::future::try_join_all(iter).await?;
    if let Some(i) = hashes.iter().position(|res| res.is_err()) {
        return Err(hashes.swap_remove(i).unwrap_err());
    }

    trace!(
        "Hashed {} files in {}",
        count,
        fmt_duration_as_secs(&start.elapsed())
    );
    Ok(hashes.into_iter().map(|res| res.unwrap()).collect())
}

/// Update the digest `m` with all data from `reader`.
fn update_from_reader<R: Read>(m: &mut Digest, mut reader: R) -> Result<()> {
    loop {
        let mut buffer = [0; 1024];
        let count = reader.read(&mut buffer[..])?;
        if count == 0 {
            break;
        }
        m.update(&buffer[..count]);
    }
    Ok(())
}

/// Format `duration` as seconds with a fractional component.
pub fn fmt_duration_as_secs(duration: &Duration) -> String {
    format!("{}.{:03} s", duration.as_secs(), duration.subsec_millis())
}

/// If `input`, write it to `child`'s stdin while also reading `child`'s stdout and stderr, then wait on `child` and return its status and output.
///
/// This was lifted from `std::process::Child::wait_with_output` and modified
/// to also write to stdin.
async fn wait_with_input_output<T>(mut child: T, input: Option<Vec<u8>>) -> Result<process::Output>
where
    T: CommandChild + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let stdin = input.and_then(|i| {
        child.take_stdin().map(|mut stdin| async move {
            stdin.write_all(&i).await.context("failed to write stdin")
        })
    });
    let stdout = child.take_stdout();
    let stdout = async move {
        match stdout {
            Some(mut stdout) => {
                let mut buf = Vec::new();
                stdout
                    .read_to_end(&mut buf)
                    .await
                    .context("failed to read stdout")?;
                Result::Ok(Some(buf))
            }
            None => Ok(None),
        }
    };

    let stderr = child.take_stderr();
    let stderr = async move {
        match stderr {
            Some(mut stderr) => {
                let mut buf = Vec::new();
                stderr
                    .read_to_end(&mut buf)
                    .await
                    .context("failed to read stderr")?;
                Result::Ok(Some(buf))
            }
            None => Ok(None),
        }
    };

    // Finish writing stdin before waiting, because waiting drops stdin.
    let status = async move {
        if let Some(stdin) = stdin {
            let _ = stdin.await;
        }

        child.wait().await.context("failed to wait for child")
    };

    let (status, stdout, stderr) = futures::future::try_join3(status, stdout, stderr).await?;

    Ok(process::Output {
        status,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
    })
}

/// Run `command`, writing `input` to its stdin if it is `Some` and return the exit status and output.
///
/// If the command returns a non-successful exit status, an error of `SccacheError::ProcessError`
/// will be returned containing the process output.
pub async fn run_input_output<C>(mut command: C, input: Option<Vec<u8>>) -> Result<process::Output>
where
    C: RunCommand,
{
    let child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .await?;

    wait_with_input_output(child, input)
        .await
        .and_then(|output| {
            if output.status.success() {
                Ok(output)
            } else {
                Err(ProcessError(output).into())
            }
        })
}

/// Write `data` to `writer` with bincode serialization, prefixed by a `u32` length.
pub fn write_length_prefixed_bincode<W, S>(mut writer: W, data: S) -> Result<()>
where
    W: Write,
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
        let u16s = self.encode_wide();
        let mut utf8 = s.chars();

        for codepoint in u16s {
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
                    return false;
                }
            } else {
                return false;
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
                    return Some(OsString::from_wide(&codepoints));
                }
            };

            let to_match = to_match as u32;
            let codepoint = codepoint as u32;

            if to_match < 0xd7ff {
                if to_match != codepoint {
                    return None;
                }
            } else {
                return None;
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

#[cfg(feature = "hyperx")]
pub use self::http_extension::{HeadersExt, RequestExt};

#[cfg(feature = "hyperx")]
mod http_extension {
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::fmt;

    pub trait HeadersExt {
        fn set<H>(&mut self, header: H)
        where
            H: hyperx::header::Header + fmt::Display;

        fn get_hyperx<H>(&self) -> Option<H>
        where
            H: hyperx::header::Header;
    }

    impl HeadersExt for HeaderMap {
        fn set<H>(&mut self, header: H)
        where
            H: hyperx::header::Header + fmt::Display,
        {
            self.insert(
                H::header_name(),
                HeaderValue::from_maybe_shared(header.to_string()).unwrap(),
            );
        }

        fn get_hyperx<H>(&self) -> Option<H>
        where
            H: hyperx::header::Header,
        {
            http::HeaderMap::get(self, H::header_name())
                .and_then(|header| H::parse_header(&header).ok())
        }
    }

    pub trait RequestExt {
        fn set_header<H>(self, header: H) -> Self
        where
            H: hyperx::header::Header + fmt::Display;
    }

    impl RequestExt for http::request::Builder {
        fn set_header<H>(self, header: H) -> Self
        where
            H: hyperx::header::Header + fmt::Display,
        {
            self.header(
                H::header_name(),
                HeaderValue::from_maybe_shared(header.to_string()).unwrap(),
            )
        }
    }

    impl RequestExt for http::response::Builder {
        fn set_header<H>(self, header: H) -> Self
        where
            H: hyperx::header::Header + fmt::Display,
        {
            self.header(
                H::header_name(),
                HeaderValue::from_maybe_shared(header.to_string()).unwrap(),
            )
        }
    }

    #[cfg(feature = "reqwest")]
    impl RequestExt for ::reqwest::RequestBuilder {
        fn set_header<H>(self, header: H) -> Self
        where
            H: hyperx::header::Header + fmt::Display,
        {
            self.header(
                H::header_name(),
                HeaderValue::from_maybe_shared(header.to_string()).unwrap(),
            )
        }
    }

    #[cfg(feature = "reqwest")]
    impl RequestExt for ::reqwest::blocking::RequestBuilder {
        fn set_header<H>(self, header: H) -> Self
        where
            H: hyperx::header::Header + fmt::Display,
        {
            self.header(
                H::header_name(),
                HeaderValue::from_maybe_shared(header.to_string()).unwrap(),
            )
        }
    }
}

pub trait DateTimeExt {
    fn to_rfc7231(&self) -> String;
}

#[cfg(feature = "azure")]
impl<Tz: chrono::TimeZone> DateTimeExt for chrono::DateTime<Tz>
where
    Tz::Offset: core::fmt::Display,
{
    fn to_rfc7231(&self) -> String {
        self.naive_utc().format("%a, %d %b %Y %T GMT").to_string()
    }
}

/// Pipe `cmd`'s stdio to `/dev/null`, unless a specific env var is set.
#[cfg(not(windows))]
pub fn daemonize() -> Result<()> {
    use daemonize::Daemonize;
    use std::env;
    use std::mem;

    match env::var("SCCACHE_NO_DAEMON") {
        Ok(ref val) if val == "1" => {}
        _ => {
            Daemonize::new().start().context("failed to daemonize")?;
        }
    }

    static mut PREV_SIGSEGV: *mut libc::sigaction = 0 as *mut _;
    static mut PREV_SIGBUS: *mut libc::sigaction = 0 as *mut _;
    static mut PREV_SIGILL: *mut libc::sigaction = 0 as *mut _;

    // We don't have a parent process any more once we've reached this point,
    // which means that no one's probably listening for our exit status.
    // In order to assist with debugging crashes of the server we configure our
    // rlimit to allow runtime dumps and we also install a signal handler for
    // segfaults which at least prints out what just happened.
    unsafe {
        match env::var("SCCACHE_ALLOW_CORE_DUMPS") {
            Ok(ref val) if val == "1" => {
                let rlim = libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &rlim);
            }
            _ => {}
        }

        PREV_SIGSEGV = Box::into_raw(Box::new(mem::zeroed::<libc::sigaction>()));
        PREV_SIGBUS = Box::into_raw(Box::new(mem::zeroed::<libc::sigaction>()));
        PREV_SIGILL = Box::into_raw(Box::new(mem::zeroed::<libc::sigaction>()));
        let mut new: libc::sigaction = mem::zeroed();
        new.sa_sigaction = handler as usize;
        new.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigaction(libc::SIGSEGV, &new, &mut *PREV_SIGSEGV);
        libc::sigaction(libc::SIGBUS, &new, &mut *PREV_SIGBUS);
        libc::sigaction(libc::SIGILL, &new, &mut *PREV_SIGILL);
    }

    return Ok(());

    extern "C" fn handler(
        signum: libc::c_int,
        _info: *mut libc::siginfo_t,
        _ptr: *mut libc::c_void,
    ) {
        use std::fmt::{Result, Write};

        struct Stderr;

        impl Write for Stderr {
            fn write_str(&mut self, s: &str) -> Result {
                unsafe {
                    let bytes = s.as_bytes();
                    libc::write(libc::STDERR_FILENO, bytes.as_ptr() as *const _, bytes.len());
                    Ok(())
                }
            }
        }

        unsafe {
            let _ = writeln!(Stderr, "signal {} received", signum);

            // Configure the old handler and then resume the program. This'll
            // likely go on to create a runtime dump if one's configured to be
            // created.
            match signum {
                libc::SIGBUS => libc::sigaction(signum, &*PREV_SIGBUS, std::ptr::null_mut()),
                libc::SIGILL => libc::sigaction(signum, &*PREV_SIGILL, std::ptr::null_mut()),
                _ => libc::sigaction(signum, &*PREV_SIGSEGV, std::ptr::null_mut()),
            };
        }
    }
}

/// This is a no-op on Windows.
#[cfg(windows)]
pub fn daemonize() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::OsStrExt;
    use std::ffi::{OsStr, OsString};

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

    #[cfg(feature = "azure")]
    #[test]
    fn rfc7231_format() {
        use crate::util::DateTimeExt;
        use chrono::{DateTime, NaiveDateTime, Utc};

        let time = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);

        assert_eq!(time.to_rfc7231(), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
