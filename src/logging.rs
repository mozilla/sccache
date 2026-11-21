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
//! * every record is emitted with one `write_all` call, or every line of it for
//!   a record too long to be written atomically, so lines are never torn in
//!   half by a concurrent writer.
//!
//! `SCCACHE_ERROR_LOG` names a file that log output is appended to instead of
//! going to stderr.  It is honoured by every process: in client-side mode the
//! CLI, not the daemon, is where the compile pipeline logs from.  Appends to a
//! file opened with `O_APPEND` are serialised by the kernel, so a shared file
//! is safe for concurrent processes as long as each line is in one write.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use env_logger::fmt::Formatter;
use fs::{File, OpenOptions};
use fs_err as fs;
use log::Record;

use crate::errors::*;

/// Environment variable naming a file to append log output to.
pub const ERROR_LOG_ENV: &str = "SCCACHE_ERROR_LOG";

/// The descriptor of the error log opened by [`init`], which the daemon has to
/// keep open when it closes the descriptors it inherited.
#[cfg(unix)]
static ERROR_LOG_FD: std::sync::OnceLock<std::os::unix::io::RawFd> = std::sync::OnceLock::new();

/// The descriptor log records are written to, if they go to the error log.
#[cfg(unix)]
pub fn error_log_fd() -> Option<std::os::unix::io::RawFd> {
    ERROR_LOG_FD.get().copied()
}

/// Where log records go, and the error log it is, if any: the daemon swaps it
/// for a file named after its own pid once it has forked.
static SINK: std::sync::Mutex<Option<(Box<dyn Write + Send>, Option<PathBuf>)>> =
    std::sync::Mutex::new(None);

/// What `env_logger` writes to: whatever [`SINK`] holds at the time.
struct Sink;

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut *SINK.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((sink, _)) => sink.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut *SINK.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((sink, _)) => sink.flush(),
            None => Ok(()),
        }
    }
}

/// Switch to the error log this process should write to, when that is not the
/// one it opened: a per-process path (`%p`, or a directory) resolves to another
/// file once the daemon has forked. Returns the newly opened file, if any.
pub fn reopen_error_log() -> Result<Option<File>> {
    let Some(path) = error_log_path() else {
        return Ok(None);
    };
    let mut sink = SINK.lock().unwrap_or_else(|e| e.into_inner());
    match &*sink {
        Some((_, Some(opened))) if *opened != path => {}
        _ => return Ok(None),
    }
    let file = open_error_log(&path)?;
    *sink = Some((Box::new(file.try_clone()?), Some(path)));
    Ok(Some(file))
}

/// Initialise logging from the `SCCACHE_LOG` environment variable.
///
/// Does nothing if `SCCACHE_LOG` is unset, and panics if a logger has already
/// been installed.
pub fn init() {
    if std::env::var(crate::LOGGING_ENV).is_err() {
        return;
    }

    let millis = std::env::var_os("SCCACHE_LOG_MILLIS").is_some();

    // Note that only the log output is redirected, never file descriptor 2
    // itself: a CLI process passes the compiler's diagnostics through its own
    // stderr, and those have to reach the build.  The daemon has no such
    // constraint and additionally redirects its stderr (see
    // `commands::run_command`), which is what catches panics and backtraces.
    let sink: (Box<dyn Write + Send>, Option<PathBuf>) = match error_log_path() {
        Some(path) => match open_error_log(&path) {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    let _ = ERROR_LOG_FD.set(file.as_raw_fd());
                }
                (Box::new(file), Some(path))
            }
            Err(e) => {
                // No logger yet, so this cannot go through `log`.
                eprintln!("sccache: {e}, logging to stderr instead");
                (Box::new(io::stderr()), None)
            }
        },
        None => (Box::new(io::stderr()), None),
    };
    *SINK.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);

    let mut builder = env_logger::Builder::from_env(crate::LOGGING_ENV);
    builder
        // The pid is read for each record: the daemon forks after this.
        .format(move |buf, record| format_record(buf, record, std::process::id(), millis))
        .target(env_logger::Target::Pipe(Box::new(RecordWriter::new(
            Box::new(Sink),
        ))));

    match builder.try_init() {
        Ok(_) => (),
        Err(e) => panic!("Failed to initialize logging: {:?}", e),
    }
}

/// The file `SCCACHE_ERROR_LOG` points at, if it is set to a non-empty value.
///
/// See [`resolve_error_log_path`] for how the value is interpreted.
pub fn error_log_path() -> Option<PathBuf> {
    match std::env::var_os(ERROR_LOG_ENV) {
        Some(name) if !name.is_empty() => {
            Some(resolve_error_log_path(Path::new(&name), std::process::id()))
        }
        _ => None,
    }
}

/// Expand a `SCCACHE_ERROR_LOG` value into the path to write to.
///
/// A shared log file is readable thanks to the pid prefix on every line, but
/// giving each process its own file sidesteps the interleaving altogether.  Two
/// ways to ask for that:
///
/// * `%p` anywhere in the value is replaced with the pid, and
/// * a value naming an existing directory becomes `sccache.<pid>.log` in it.
///
/// Anything else is used as-is, so the shared-file behaviour is unchanged.
fn resolve_error_log_path(value: &Path, pid: u32) -> PathBuf {
    if let Some(value) = value.to_str()
        && value.contains("%p")
    {
        return PathBuf::from(value.replace("%p", &pid.to_string()));
    }
    if value.is_dir() {
        return value.join(format!("sccache.{pid}.log"));
    }
    value.to_path_buf()
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

/// Atomic writes to a pipe only go up to this many bytes (`PIPE_BUF` on Linux;
/// POSIX only guarantees 512, but no platform sccache runs on is that small).
const ATOMIC_WRITE_LEN: usize = 4096;

/// A log sink that writes each record in one `write_all`, or each of its lines
/// in one if the record is too long for that.
///
/// `env_logger` hands a whole formatted record over and then flushes. One write
/// of it keeps a multi-line record together, but a write to a pipe is only
/// atomic up to [`ATOMIC_WRITE_LEN`]: past that, a concurrent writer can tear a
/// line in half, so a longer record is written line by line instead.
struct RecordWriter {
    inner: Box<dyn Write + Send>,
    /// The record being written, until the flush that ends it.
    pending: Vec<u8>,
}

impl RecordWriter {
    fn new(inner: Box<dyn Write + Send>) -> Self {
        RecordWriter {
            inner,
            pending: Vec::new(),
        }
    }
}

impl Write for RecordWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return self.inner.flush();
        }
        // The formatter always terminates the last line; terminate a record
        // written by other means rather than letting the next one join it.
        if !self.pending.ends_with(b"\n") {
            self.pending.push(b'\n');
        }
        if self.pending.len() <= ATOMIC_WRITE_LEN {
            self.inner.write_all(&self.pending)?;
        } else {
            for line in self.pending.split_inclusive(|&b| b == b'\n') {
                self.inner.write_all(line)?;
            }
        }
        self.pending.clear();
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
    fn error_log_path_is_used_as_is_by_default() {
        assert_eq!(
            resolve_error_log_path(Path::new("/tmp/sccache.log"), 42),
            PathBuf::from("/tmp/sccache.log")
        );
    }

    #[test]
    fn error_log_path_expands_pid_placeholder() {
        assert_eq!(
            resolve_error_log_path(Path::new("/tmp/sccache.%p.log"), 42),
            PathBuf::from("/tmp/sccache.42.log")
        );
    }

    #[test]
    fn error_log_path_in_a_directory_gets_a_per_process_name() {
        let tempdir = tempfile::Builder::new()
            .prefix("sccache_logging_test")
            .tempdir()
            .unwrap();
        assert_eq!(
            resolve_error_log_path(tempdir.path(), 42),
            tempdir.path().join("sccache.42.log")
        );
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
    fn one_write_per_record() {
        let recorder = Recorder::default();
        let mut writer = RecordWriter::new(Box::new(recorder.clone()));
        // A whole multi-line record, as `env_logger` would hand it over.
        writer.write_all(b"one\ntwo\nthree\n").unwrap();
        assert!(recorder.writes().is_empty());
        writer.flush().unwrap();
        assert_eq!(recorder.writes(), vec!["one\ntwo\nthree\n"]);
    }

    #[test]
    fn long_records_are_written_line_by_line() {
        let recorder = Recorder::default();
        let mut writer = RecordWriter::new(Box::new(recorder.clone()));
        let line = format!("{}\n", "x".repeat(ATOMIC_WRITE_LEN / 2));
        writer.write_all(line.repeat(3).as_bytes()).unwrap();
        writer.flush().unwrap();
        assert_eq!(recorder.writes(), vec![line.clone(), line.clone(), line]);
    }

    #[test]
    fn unterminated_records_are_terminated() {
        let recorder = Recorder::default();
        let mut writer = RecordWriter::new(Box::new(recorder.clone()));
        writer.write_all(b"beginning").unwrap();
        writer.write_all(b" and end").unwrap();
        writer.flush().unwrap();
        assert_eq!(recorder.writes(), vec!["beginning and end\n"]);
    }
}
