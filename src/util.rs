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
use blake3::Hasher as blake3_Hasher;
use byteorder::{BigEndian, ByteOrder};
use fs::File;
use fs_err as fs;
use object::{macho, read::archive::ArchiveFile, read::macho::FatArch};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::hash::Hasher;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::str;
use std::time::Duration;
use std::time::{self, SystemTime};

use crate::errors::*;

/// The url safe engine for base64.
pub const BASE64_URL_SAFE_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub const HASH_BUFFER_SIZE: usize = 128 * 1024;

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
    pub fn reader_sync<R: Read>(reader: R) -> Result<String> {
        Self::reader_sync_with(reader, |_| {}).map(|d| d.finish())
    }

    /// Calculate the BLAKE3 digest of the contents read from `reader`, calling
    /// `each` before each time the digest is updated.
    pub fn reader_sync_with<R: Read, F: FnMut(&[u8])>(mut reader: R, mut each: F) -> Result<Self> {
        let mut m = Digest::new();
        // A buffer of 128KB should give us the best performance.
        // See https://eklitzke.org/efficient-file-copying-on-linux.
        let mut buffer = [0; HASH_BUFFER_SIZE];
        loop {
            let count = reader.read(&mut buffer[..])?;
            if count == 0 {
                break;
            }
            each(&buffer[..count]);
            m.update(&buffer[..count]);
        }
        Ok(m)
    }

    /// Calculate the BLAKE3 digest of the contents read from `reader`, while
    /// also checking for the presence of time macros.
    /// See [`TimeMacroFinder`] for more details.
    pub fn reader_sync_time_macros<R: Read>(reader: R) -> Result<(String, TimeMacroFinder)> {
        let mut finder = TimeMacroFinder::new();

        Ok((
            Self::reader_sync_with(reader, |visit| finder.find_time_macros(visit))?.finish(),
            finder,
        ))
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

    pub fn delimiter(&mut self, name: &[u8]) {
        self.update(b"\0SCCACHE\0");
        self.update(name);
        self.update(b"\0");
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

/// The longest pattern we're looking for is `__TIMESTAMP__`
const MAX_HAYSTACK_LEN: usize = b"__TIMESTAMP__".len();

#[cfg(test)]
pub const MAX_TIME_MACRO_HAYSTACK_LEN: usize = MAX_HAYSTACK_LEN;

/// Used during the chunked hashing process to check for C preprocessor time
/// macros (namely `__TIMESTAMP__`, `__DATE__`, `__DATETIME__`) while reusing
/// the same buffer as the hashing function, for efficiency.
///
/// See `[Self::find_time_macros]` for details.
#[derive(Debug, Default)]
pub struct TimeMacroFinder {
    found_date: Cell<bool>,
    found_time: Cell<bool>,
    found_timestamp: Cell<bool>,
    overlap_buffer: [u8; MAX_HAYSTACK_LEN * 2],
    /// Counter of chunks of full size we've been through. Partial reads do
    /// not count and are handled separately.
    full_chunks_counter: usize,
    /// Contents of the previous read if it was smaller than `MAX_HAYSTACK_LEN`,
    /// plus MAX_HAYSTACK_LEN bytes of the previous chunk, to account for
    /// the possibility of partial reads splitting a time macro
    /// across two calls.
    previous_small_read: Vec<u8>,
}

impl TimeMacroFinder {
    /// Called for each chunk of a file during the hashing process
    /// in preprocessor cache mode.
    ///
    /// When buffer reading a file, we get something like this:
    ///
    /// `[xxxx....aaaa][bbbb....cccc][dddd....eeee][ffff...]`
    ///
    /// The brackets represent each buffer chunk. We use the fact that the largest
    /// pattern we're looking for is `__TIMESTAMP__` to avoid copying the entire
    /// file to memory and re-searching the entire buffer for each pattern.
    /// We can check inside each chunk for each pattern, and we use an overlap
    /// buffer to keep the last `b"__TIMESTAMP__".len()` bytes around from the
    /// last chunk, to also catch any pattern overlapping two chunks.
    ///
    /// In the above case, the overflow buffer would look like:
    ///
    /// ```text
    ///    Chunk 1
    ///    - aaaa0000
    ///    Chunk 2
    ///    - aaaabbbb
    ///    - cccc0000
    ///    Chunk 3
    ///    - ccccdddd
    ///    - eeee0000
    ///    Chunk 4
    ///    - eeeeffff
    ///    [...]
    /// ```
    ///
    /// We have to be careful to zero out the buffer right after each overlap check,
    /// otherwise we risk the (unlikely) case of a pattern being spread between the
    /// start of a chunk and its end.
    /// Finally, we need to account for partial reads: it's possible that a read
    /// smaller than the haystack hide a time macro because it spreads it across
    /// two calls. This makes the example more complicated and isn't necessary
    /// to get the point of the algorithm across.
    /// See unit tests for some concrete examples.
    pub fn find_time_macros(&mut self, visit: &[u8]) {
        if self.full_chunks_counter == 0 {
            if visit.len() <= MAX_HAYSTACK_LEN {
                // The read is smaller than the largest haystack.
                // We might get called again, if this was an incomplete read.
                if !self.previous_small_read.is_empty() {
                    // In a rare pathological case where all reads are small,
                    // this will grow up to the length of the file.
                    // It it *very* unlikely and of minor performance
                    // importance compared to just getting many small reads.
                    self.previous_small_read.extend(visit);
                } else {
                    visit.clone_into(&mut self.previous_small_read);
                }
                self.find_macros(&self.previous_small_read);
                return;
            }
            // Copy the right side of the visit to the left of the buffer
            let right_half = visit.len() - MAX_HAYSTACK_LEN;
            self.overlap_buffer[..MAX_HAYSTACK_LEN].copy_from_slice(&visit[right_half..]);
        } else {
            if visit.len() < MAX_HAYSTACK_LEN {
                // The read is smaller than the largest haystack.
                // We might get called again, if this was an incomplete read.
                if !self.previous_small_read.is_empty() {
                    self.previous_small_read.extend(visit);
                } else {
                    // Since this isn't the first non-small read (counter != 0)
                    // we need to start from MAX_HAYSTACK_LEN bytes of the previous
                    // read, otherwise we might miss a complete read followed
                    // by a small read.
                    let mut buf = self.overlap_buffer[..MAX_HAYSTACK_LEN].to_owned();
                    buf.extend(visit);
                    self.previous_small_read = buf;
                }

                // zero the right side of the buffer
                self.overlap_buffer[MAX_HAYSTACK_LEN..].copy_from_slice(&[0; MAX_HAYSTACK_LEN]);
                // Copy the visit to the right of the buffer, starting from the middle
                self.overlap_buffer[MAX_HAYSTACK_LEN..MAX_HAYSTACK_LEN + visit.len()]
                    .copy_from_slice(visit);

                // Check both the concatenation with the previous small read
                self.find_macros(&self.previous_small_read);
                // ...and the overlap buffer
                self.find_macros(&self.overlap_buffer);
                return;
            } else {
                // Copy the left side of the visit to the right of the buffer
                let left_half = MAX_HAYSTACK_LEN;
                self.overlap_buffer[left_half..].copy_from_slice(&visit[..left_half]);
                self.find_macros(&self.overlap_buffer);
                // zero the buffer
                self.overlap_buffer = Default::default();
                // Copy the right side of the visit to the left of the buffer
                let right_half = visit.len() - MAX_HAYSTACK_LEN;
                self.overlap_buffer[..MAX_HAYSTACK_LEN].copy_from_slice(&visit[right_half..]);
            }
            self.find_macros(&self.overlap_buffer);
        }
        // Also check the concatenation with the previous small read
        if !self.previous_small_read.is_empty() {
            let mut concatenated = self.previous_small_read.to_owned();
            concatenated.extend(visit);
            self.find_macros(&concatenated);
        }

        self.find_macros(visit);
        self.full_chunks_counter += 1;
        self.previous_small_read.clear();
    }

    fn find_macros(&self, buffer: &[u8]) {
        // TODO
        // This could be made more efficient, either by using a regex for all
        // three patterns, or by doing some SIMD trickery like `ccache` does.
        //
        // `ccache` reads the file twice, so we might actually already be
        // winning in most cases... though they have an inode cache.
        // In any case, let's only improve this if it ends up being slow.
        if memchr::memmem::find(buffer, b"__TIMESTAMP__").is_some() {
            self.found_timestamp.set(true);
        }
        if memchr::memmem::find(buffer, b"__TIME__").is_some() {
            self.found_time.set(true);
        };
        if memchr::memmem::find(buffer, b"__DATE__").is_some() {
            self.found_date.set(true);
        };
    }

    pub fn found_time_macros(&self) -> bool {
        self.found_date() || self.found_time() || self.found_timestamp()
    }

    pub fn found_time(&self) -> bool {
        self.found_time.get()
    }

    pub fn found_date(&self) -> bool {
        self.found_date.get()
    }

    pub fn found_timestamp(&self) -> bool {
        self.found_timestamp.get()
    }

    pub fn new() -> Self {
        Default::default()
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
            let archive_file = File::open(&path)
                .with_context(|| format!("Failed to open file for hashing: {:?}", path))?;
            let archive_mmap =
                unsafe { memmap2::MmapOptions::new().map_copy_read_only(&archive_file)? };

            match macho::FatHeader::parse(&*archive_mmap) {
                Ok(h) if h.magic.get(object::endian::BigEndian) == macho::FAT_MAGIC => {
                    for arch in macho::FatHeader::parse_arch32(&*archive_mmap)? {
                        hash_regular_archive(&mut m, arch.data(&*archive_mmap)?)?;
                    }
                }
                Ok(h) if h.magic.get(object::endian::BigEndian) == macho::FAT_MAGIC_64 => {
                    for arch in macho::FatHeader::parse_arch64(&*archive_mmap)? {
                        hash_regular_archive(&mut m, arch.data(&*archive_mmap)?)?;
                    }
                }
                // Not a FatHeader at all, regular archive.
                _ => hash_regular_archive(&mut m, &archive_mmap)?,
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

fn hash_regular_archive(m: &mut Digest, data: &[u8]) -> Result<()> {
    let archive = ArchiveFile::parse(data)?;
    for entry in archive.members() {
        let entry = entry?;
        m.update(entry.name());
        m.update(entry.data(data)?);
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

#[cfg(unix)]
pub fn encode_path(dst: &mut dyn Write, path: &Path) -> std::io::Result<()> {
    use std::os::unix::prelude::*;

    let bytes = path.as_os_str().as_bytes();
    dst.write_all(bytes)
}

#[cfg(windows)]
pub fn encode_path(dst: &mut dyn Write, path: &Path) -> std::io::Result<()> {
    use std::os::windows::prelude::*;

    let points = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let bytes = wide_char_to_multi_byte(&points)?; // use_default_char_flag
    dst.write_all(&bytes)
}

#[cfg(unix)]
pub fn decode_path(bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::os::unix::prelude::*;
    Ok(OsStr::from_bytes(bytes).into())
}

#[cfg(windows)]
pub fn decode_path(bytes: &[u8]) -> std::io::Result<PathBuf> {
    use windows_sys::Win32::Globalization::{CP_OEMCP, MB_ERR_INVALID_CHARS};

    let codepage = CP_OEMCP;
    let flags = MB_ERR_INVALID_CHARS;

    Ok(OsString::from_wide(&multi_byte_to_wide_char(codepage, flags, bytes)?).into())
}

#[cfg(windows)]
pub fn wide_char_to_multi_byte(wide_char_str: &[u16]) -> std::io::Result<Vec<u8>> {
    use windows_sys::Win32::Globalization::{WideCharToMultiByte, CP_OEMCP};

    let codepage = CP_OEMCP;
    let flags = 0;
    // Empty string
    if wide_char_str.is_empty() {
        return Ok(Vec::new());
    }
    unsafe {
        // Get length of multibyte string
        let len = WideCharToMultiByte(
            codepage,
            flags,
            wide_char_str.as_ptr(),
            wide_char_str.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        );

        if len > 0 {
            // Convert from UTF-16 to multibyte
            let mut astr: Vec<u8> = Vec::with_capacity(len as usize);
            let len = WideCharToMultiByte(
                codepage,
                flags,
                wide_char_str.as_ptr(),
                wide_char_str.len() as i32,
                astr.as_mut_ptr() as _,
                len,
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            if len > 0 {
                astr.set_len(len as usize);
                if (len as usize) == astr.len() {
                    return Ok(astr);
                } else {
                    return Ok(astr[0..(len as usize)].to_vec());
                }
            }
        }
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
/// Wrapper for MultiByteToWideChar.
///
/// See https://msdn.microsoft.com/en-us/library/windows/desktop/dd319072(v=vs.85).aspx
/// for more details.
pub fn multi_byte_to_wide_char(
    codepage: u32,
    flags: u32,
    multi_byte_str: &[u8],
) -> std::io::Result<Vec<u16>> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;

    if multi_byte_str.is_empty() {
        return Ok(vec![]);
    }
    unsafe {
        // Get length of UTF-16 string
        let len = MultiByteToWideChar(
            codepage,
            flags,
            multi_byte_str.as_ptr(),
            multi_byte_str.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if len > 0 {
            // Convert to UTF-16
            let mut wstr: Vec<u16> = Vec::with_capacity(len as usize);
            let len = MultiByteToWideChar(
                codepage,
                flags,
                multi_byte_str.as_ptr(),
                multi_byte_str.len() as i32,
                wstr.as_mut_ptr(),
                len,
            );
            wstr.set_len(len as usize);
            if len > 0 {
                return Ok(wstr);
            }
        }
        Err(std::io::Error::last_os_error())
    }
}

/// A Unix timestamp with nanoseconds precision
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    seconds: i64,
    /// Always in the `0 .. 1_000_000_000` range.
    nanoseconds: u32,
}

const NSEC_PER_SEC: u32 = 1_000_000_000;

impl From<std::time::SystemTime> for Timestamp {
    fn from(system_time: std::time::SystemTime) -> Self {
        // On Unix, `SystemTime` is a wrapper for the `timespec` C struct:
        // https://www.gnu.org/software/libc/manual/html_node/Time-Types.html#index-struct-timespec
        // On Windows, `SystemTime` wraps a 100ns intervals-based struct.
        // We want to effectively access the inner fields, but the Rust standard
        // library does not expose them. The best we can do is:
        let seconds;
        let nanoseconds;
        match system_time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => {
                seconds = duration.as_secs() as i64;
                nanoseconds = duration.subsec_nanos();
            }
            Err(error) => {
                // `system_time` is before `UNIX_EPOCH`.
                // We need to undo this algorithm:
                // https://github.com/rust-lang/rust/blob/6bed1f0bc3cc50c10aab26d5f94b16a00776b8a5/library/std/src/sys/unix/time.rs#L40-L41
                let negative = error.duration();
                let negative_secs = negative.as_secs() as i64;
                let negative_nanos = negative.subsec_nanos();
                if negative_nanos == 0 {
                    seconds = -negative_secs;
                    nanoseconds = 0;
                } else {
                    // For example if `system_time` was 4.3 seconds before
                    // the Unix epoch we get a Duration that represents
                    // `(-4, -0.3)` but we want `(-5, +0.7)`:
                    seconds = -1 - negative_secs;
                    nanoseconds = NSEC_PER_SEC - negative_nanos;
                }
            }
        };
        Self {
            seconds,
            nanoseconds,
        }
    }
}

impl PartialEq<SystemTime> for Timestamp {
    fn eq(&self, other: &SystemTime) -> bool {
        self == &Self::from(*other)
    }
}

impl Timestamp {
    pub fn new(seconds: i64, nanoseconds: u32) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }
}

/// Adds a fallback for trying Unix's `ctime` semantics on Windows systems.
pub trait MetadataCtimeExt {
    fn ctime_or_creation(&self) -> std::io::Result<Timestamp>;
}

impl MetadataCtimeExt for std::fs::Metadata {
    #[cfg(unix)]
    fn ctime_or_creation(&self) -> std::io::Result<Timestamp> {
        use std::os::unix::prelude::MetadataExt;
        Ok(Timestamp {
            seconds: self.ctime(),
            nanoseconds: self.ctime_nsec().try_into().unwrap_or(0),
        })
    }
    #[cfg(windows)]
    fn ctime_or_creation(&self) -> std::io::Result<Timestamp> {
        // Windows does not have the actual notion of ctime in the Unix sense.
        // Best effort is creation time (also called ctime in windows libs...)
        self.created().map(Into::into)
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

/// Disable connection pool to avoid broken connection between runtime
///
/// # TODO
///
/// We should refactor sccache current model to make sure that we only have
/// one tokio runtime and keep reqwest alive inside it.
///
/// ---
///
/// More details could be found at https://github.com/mozilla/sccache/pull/1563
#[cfg(any(feature = "dist-server", feature = "dist-client"))]
pub fn new_reqwest_blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .expect("http client must build with success")
}

#[cfg(test)]
mod tests {
    use super::{OsStrExt, TimeMacroFinder};
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

    #[test]
    fn test_time_macro_short_read() {
        // Normal "read" should succeed
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"__TIME__");
        assert!(finder.found_time());

        // So should a partial "read"
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"__");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TIME__");
        assert!(finder.found_time());

        // So should a partial "read" later down the line
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"Something or other larger than the haystack");
        finder.find_time_macros(b"__");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TIME__");
        assert!(finder.found_time());

        // Even if the last "read" is large
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"Something or other larger than the haystack");
        finder.find_time_macros(b"__");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TIME__ something or other larger than the haystack");
        assert!(finder.found_time());

        // Pathological case
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"__");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TI");
        assert!(!finder.found_time());
        finder.find_time_macros(b"ME");
        assert!(!finder.found_time());
        finder.find_time_macros(b"__");
        assert!(finder.found_time());

        // Odd-numbered pathological case
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"This is larger than the haystack __");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TI");
        assert!(!finder.found_time());
        finder.find_time_macros(b"ME");
        assert!(!finder.found_time());
        finder.find_time_macros(b"__");
        assert!(finder.found_time());

        // Sawtooth length pathological case
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"This is larger than the haystack __");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TI");
        assert!(!finder.found_time());
        finder.find_time_macros(b"ME__ This is larger than the haystack");
        assert!(finder.found_time());
        assert!(!finder.found_timestamp());
        finder.find_time_macros(b"__");
        assert!(!finder.found_timestamp());
        finder.find_time_macros(b"TIMESTAMP__ This is larger than the haystack");
        assert!(finder.found_timestamp());

        // Odd-numbered sawtooth length pathological case
        let mut finder = TimeMacroFinder::new();
        finder.find_time_macros(b"__");
        assert!(!finder.found_time());
        finder.find_time_macros(b"TIME__ This is larger than the haystack");
        assert!(finder.found_time());
        assert!(!finder.found_timestamp());
        finder.find_time_macros(b"__");
        assert!(!finder.found_timestamp());
        finder.find_time_macros(b"TIMESTAMP__ This is larger than the haystack");
        assert!(finder.found_timestamp());
    }
}
