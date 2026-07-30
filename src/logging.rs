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

//! Logging setup shared by `sccache` and `sccache-dist`.
//!
//! Several sccache processes log concurrently to the same destination: the
//! daemon, and every short-lived CLI process (which, in client-side mode, runs
//! the whole compile pipeline and so does most of the logging).  Lines from
//! different processes therefore interleave, and nothing can prevent that.
//! What this module does guarantee is that interleaved output stays readable:
//!
//! * every physical line carries the pid of the process that emitted it, so a
//!   line can be attributed and `grep`ed for, and
//! * every physical line is emitted with exactly one `write_all` call, so lines
//!   are never torn in half by a concurrent writer.
//!
//! `SCCACHE_ERROR_LOG` names a file that log output is appended to instead of
//! going to stderr.  It is honoured by every process: in client-side mode the
//! CLI, not the daemon, is where the compile pipeline logs from.  Appends to a
//! file opened with `O_APPEND` are serialised by the kernel, so a shared file
//! is safe for concurrent processes as long as each line is one write.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use env_logger::fmt::Formatter;
use fs::{File, OpenOptions};
use fs_err as fs;
use log::Record;

use crate::errors::*;

/// Environment variable naming a file to append log output to.
pub const ERROR_LOG_ENV: &str = "SCCACHE_ERROR_LOG";

/// Initialise logging from the `SCCACHE_LOG` environment variable.
///
/// Does nothing if `SCCACHE_LOG` is unset, and panics if a logger has already
/// been installed.
pub fn init() {
    if std::env::var(crate::LOGGING_ENV).is_err() {
        return;
    }

    let millis = std::env::var_os("SCCACHE_LOG_MILLIS").is_some();
    let pid = std::process::id();

    // Note that only the log output is redirected, never file descriptor 2
    // itself: a CLI process passes the compiler's diagnostics through its own
    // stderr, and those have to reach the build.  The daemon has no such
    // constraint and additionally redirects its stderr (see
    // `commands::run_command`), which is what catches panics and backtraces.
    let sink: Box<dyn Write + Send> = match error_log_path() {
        Some(path) => match open_error_log(&path) {
            Ok(file) => Box::new(file),
            Err(e) => {
                // No logger yet, so this cannot go through `log`.
                eprintln!("sccache: {e}, logging to stderr instead");
                Box::new(io::stderr())
            }
        },
        None => Box::new(io::stderr()),
    };

    let mut builder = env_logger::Builder::from_env(crate::LOGGING_ENV);
    builder
        .format(move |buf, record| format_record(buf, record, pid, millis))
        .target(env_logger::Target::Pipe(Box::new(LineWriter::new(sink))));

    match builder.try_init() {
        Ok(_) => (),
        Err(e) => panic!("Failed to initialize logging: {:?}", e),
    }
}

/// The file `SCCACHE_ERROR_LOG` points at, if it is set to a non-empty value.
pub fn error_log_path() -> Option<PathBuf> {
    match std::env::var_os(ERROR_LOG_ENV) {
        Some(name) if !name.is_empty() => Some(PathBuf::from(name)),
        _ => None,
    }
}

/// Open the error log for appending, creating it if needed.
pub fn open_error_log(path: &Path) -> Result<File> {
    // `O_APPEND` is what makes writes from concurrent processes land one after
    // the other instead of overwriting each other.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Cannot open/write log file '{}'", path.display()))
}

/// Format one record as `[<timestamp> <LEVEL> <pid> <target>] <message>`.
///
/// This mirrors `env_logger`'s default format with the pid inserted after the
/// level.  A record whose message spans several lines is emitted as several
/// complete lines, each with the full prefix: continuation lines would
/// otherwise be unattributable once interleaved with another process' output.
fn format_record(
    buf: &mut Formatter,
    record: &Record<'_>,
    pid: u32,
    millis: bool,
) -> io::Result<()> {
    let timestamp = if millis {
        buf.timestamp_millis().to_string()
    } else {
        buf.timestamp().to_string()
    };
    let prefix = format!(
        "[{} {:<5} {} {}] ",
        timestamp,
        record.level(),
        pid,
        record.target()
    );
    write_lines(buf, &prefix, &record.args().to_string())
}

/// Write `message` as one prefixed line per line it contains.
fn write_lines(out: &mut dyn Write, prefix: &str, message: &str) -> io::Result<()> {
    for line in message.trim_end_matches('\n').split('\n') {
        writeln!(out, "{}{}", prefix, line.trim_end_matches('\r'))?;
    }
    Ok(())
}

/// A log sink that issues exactly one `write_all` per physical line.
///
/// `env_logger` hands a whole formatted record to its target in a single
/// `write_all`; this splits that back into lines so that a record spanning
/// several lines cannot be interleaved line-wise with another process'.  One
/// `write_all` of a line-sized buffer is a single `write` syscall for both
/// unbuffered stderr and a regular file, which is what keeps concurrent
/// writers from tearing each other's lines.
struct LineWriter {
    inner: Box<dyn Write + Send>,
    /// Bytes of an as-yet unterminated line.
    pending: Vec<u8>,
}

impl LineWriter {
    fn new(inner: Box<dyn Write + Send>) -> Self {
        LineWriter {
            inner,
            pending: Vec::new(),
        }
    }
}

impl Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);

        let mut written = 0;
        while let Some(pos) = self.pending[written..].iter().position(|&b| b == b'\n') {
            let end = written + pos + 1;
            self.inner.write_all(&self.pending[written..end])?;
            written = end;
        }
        self.pending.drain(..written);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // `env_logger` flushes after every record, by which point the formatter
        // has always terminated the last line; a leftover only happens if a
        // record was written by some other means.  Terminate it rather than
        // letting the next line be appended to it.
        if !self.pending.is_empty() {
            self.pending.push(b'\n');
            self.inner.write_all(&self.pending)?;
            self.pending.clear();
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records the buffer handed to each individual `write` call.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<Vec<u8>>>>);

    impl Recorder {
        fn writes(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect()
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_lines_repeats_prefix_on_every_line() {
        let mut out = Vec::new();
        write_lines(&mut out, "PREFIX ", "first\nsecond\nthird").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "PREFIX first\nPREFIX second\nPREFIX third\n"
        );
    }

    #[test]
    fn write_lines_does_not_emit_an_empty_trailing_line() {
        let mut out = Vec::new();
        write_lines(&mut out, "P ", "only\n").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "P only\n");
    }

    #[test]
    fn write_lines_strips_carriage_returns() {
        let mut out = Vec::new();
        write_lines(&mut out, "P ", "first\r\nsecond\r\n").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "P first\nP second\n");
    }

    #[test]
    fn one_write_per_line() {
        let recorder = Recorder::default();
        let mut writer = LineWriter::new(Box::new(recorder.clone()));
        // A whole multi-line record, as `env_logger` would hand it over.
        writer.write_all(b"one\ntwo\nthree\n").unwrap();
        writer.flush().unwrap();
        assert_eq!(recorder.writes(), vec!["one\n", "two\n", "three\n"]);
    }

    #[test]
    fn partial_lines_are_held_until_terminated() {
        let recorder = Recorder::default();
        let mut writer = LineWriter::new(Box::new(recorder.clone()));
        writer.write_all(b"beginning").unwrap();
        assert!(recorder.writes().is_empty());
        writer.write_all(b" and end\nnext").unwrap();
        assert_eq!(recorder.writes(), vec!["beginning and end\n"]);
        // Flush terminates whatever is left over.
        writer.flush().unwrap();
        assert_eq!(recorder.writes(), vec!["beginning and end\n", "next\n"]);
    }
}
