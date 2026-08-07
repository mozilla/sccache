// Copyright 2026 Mozilla Foundation
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

//! Following a log file, the way `tail -f` does.
//!
//! The server writes its log by having stderr redirected to `SCCACHE_ERROR_LOG`,
//! so there is nothing to ask it for: the monitor just follows the file. It may
//! not exist yet when the monitor starts, and it may be replaced or truncated
//! underneath us, so keep checking rather than giving up.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

/// How much of the end of the file to read at startup. Enough to fill the pane
/// several times over without reading a log that has been growing all day.
const INITIAL_BYTES: u64 = 64 * 1024;
/// How often to look for new output once the end of the file is reached.
const POLL: Duration = Duration::from_millis(250);
/// Most lines to hand over at once, so that a burst cannot stall the UI thread.
const BATCH: usize = 512;

/// Something that happened to the log file being followed.
pub enum LogEvent {
    /// Lines appended since the last event, oldest first.
    Lines(Vec<String>),
    /// The file was truncated or replaced: what came before is gone.
    Rotated,
    /// The file cannot be read yet; the reason is worth showing.
    Waiting(String),
}

/// Follow `path` on a background thread, reporting to `tx` until it hangs up.
pub fn spawn(path: PathBuf, tx: Sender<LogEvent>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("sccache-monitor-tail".into())
        .spawn(move || follow(&path, &tx))?;
    Ok(())
}

fn follow(path: &Path, tx: &Sender<LogEvent>) {
    let mut complained = false;
    loop {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) => {
                // Say why once, rather than on every attempt.
                if !complained {
                    complained = true;
                    if tx.send(LogEvent::Waiting(format!("{e}"))).is_err() {
                        return;
                    }
                }
                thread::sleep(POLL);
                continue;
            }
        };
        complained = false;
        if !read_to_end_of_time(path, file, tx) {
            return;
        }
    }
}

/// Read `file` until it is rotated or the receiver hangs up. Returns false when
/// the caller should stop, true when it should reopen the path.
fn read_to_end_of_time(path: &Path, mut file: File, tx: &Sender<LogEvent>) -> bool {
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut pos = len.saturating_sub(INITIAL_BYTES);
    // Seeking into the middle of the file lands mid-line as often as not; drop
    // whatever is left of that line rather than showing half of it.
    let mut skip_partial_line = pos > 0;
    if file.seek(SeekFrom::Start(pos)).is_err() {
        return true;
    }

    let mut reader = BufReader::new(file);
    let mut batch: Vec<String> = Vec::new();
    // A line the writer has not finished yet: hold it until its newline shows
    // up, so a message never arrives split in two.
    let mut partial = String::new();
    let mut buf = String::new();

    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => {
                if !batch.is_empty()
                    && tx
                        .send(LogEvent::Lines(std::mem::take(&mut batch)))
                        .is_err()
                {
                    return false;
                }
                // A file that has shrunk was truncated or replaced.
                match std::fs::metadata(path) {
                    Ok(meta) if meta.len() < pos => {
                        return tx.send(LogEvent::Rotated).is_ok();
                    }
                    Err(_) => return true,
                    _ => {}
                }
                thread::sleep(POLL);
            }
            Ok(read) => {
                pos += read as u64;
                if !buf.ends_with('\n') {
                    partial.push_str(&buf);
                    continue;
                }
                let mut line = std::mem::take(&mut partial);
                line.push_str(buf.trim_end_matches(['\n', '\r']));
                // Logging is initialised before the daemon redirects its
                // stderr, so a server started from a terminal writes the
                // colour codes env_logger picked for a tty into the file.
                // Drop them: the pane colours lines by level itself, and the
                // escapes would otherwise show up as text.
                let line = strip_ansi_escapes::strip_str(&line);
                if skip_partial_line {
                    skip_partial_line = false;
                } else {
                    batch.push(line);
                }
                if batch.len() >= BATCH
                    && tx
                        .send(LogEvent::Lines(std::mem::take(&mut batch)))
                        .is_err()
                {
                    return false;
                }
            }
            // A read error is usually the file going away under us.
            Err(_) => return true,
        }
    }
}
