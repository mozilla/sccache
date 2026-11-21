// Tests for statistics reporting and IPC payload limits.
//
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

#![deny(rust_2018_idioms)]
#![cfg(unix)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Wait for `child`, returning `None` if it outlives `timeout` (in which case it
/// is killed, so it cannot outlive the test).
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait().unwrap() {
            Some(status) => return Some(status),
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn sccache_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sccache"))
}

fn find_c_compiler() -> Option<PathBuf> {
    ["cc", "gcc", "clang"]
        .iter()
        .find_map(|c| which::which(c).ok())
}

/// A source file whose cache entry is comfortably larger than the small frame
/// limit used below.
fn write_source(path: &Path) {
    let mut source = String::from("#include <stddef.h>\n");
    for i in 0..2000 {
        source.push_str(&format!("int fn{i}(int x) {{ return x * {i} + {i}; }}\n"));
    }
    std::fs::write(path, source).unwrap();
}

struct Daemon {
    tempdir: TempDir,
    socket: PathBuf,
    log: PathBuf,
    max_frame_length: Option<&'static str>,
}

impl Daemon {
    fn start(max_frame_length: Option<&'static str>) -> Daemon {
        let tempdir = TempDir::new().unwrap();
        let daemon = Daemon {
            socket: tempdir.path().join("sccache.sock"),
            log: tempdir.path().join("sccache.log"),
            tempdir,
            max_frame_length,
        };
        let output = daemon.command().arg("--start-server").output().unwrap();
        assert!(
            output.status.success(),
            "failed to start server: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        daemon
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(sccache_bin());
        cmd.env("SCCACHE_CLIENT_SIDE", "1")
            .env("SCCACHE_DIR", self.tempdir.path())
            .env("SCCACHE_SERVER_UDS", &self.socket)
            .env("SCCACHE_LOG", "debug")
            .env("SCCACHE_ERROR_LOG", &self.log)
            .env_remove("SCCACHE_MAX_FRAME_LENGTH");
        if let Some(len) = self.max_frame_length {
            cmd.env("SCCACHE_MAX_FRAME_LENGTH", len);
        }
        cmd
    }

    /// Compile `name.c` and return the compile's exit status.
    fn compile(&self, name: &str) -> std::process::ExitStatus {
        let compiler = find_c_compiler().expect("checked by the caller");
        let source = self.tempdir.path().join(format!("{}.c", name));
        write_source(&source);
        self.command()
            .arg(compiler)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(self.tempdir.path().join(format!("{}.o", name)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
    }

    fn stats(&self) -> serde_json::Value {
        let output = self
            .command()
            .args(["--show-stats", "--stats-format=json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to read stats: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// The number of C/C++ cache misses the daemon has recorded.
    fn cache_misses(&self) -> u64 {
        self.stats()["stats"]["cache_misses"]["counts"]["C/C++"]
            .as_u64()
            .unwrap_or(0)
    }

    fn cache_write_errors(&self) -> u64 {
        self.stats()["stats"]["cache_write_errors"]
            .as_u64()
            .unwrap()
    }

    /// How many times the daemon tore down a connection over a frame that did
    /// not fit its limit.
    fn frame_limit_kills(&self) -> usize {
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        log.lines()
            .filter(|line| line.contains("frame size too big"))
            .count()
    }

    fn stop(self) {
        let output = self.command().arg("--stop-server").output().unwrap();
        assert!(
            output.status.success(),
            "failed to stop server: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Shut the daemon down without requiring the RPC to succeed, for limits so
    /// small that even the shutdown response does not fit a frame. The daemon
    /// still acts on the request; only its reply is lost.
    fn stop_best_effort(self) {
        let _ = self.command().arg("--stop-server").output();
    }
}

#[test]
#[serial_test::serial]
fn test_client_side_records_cache_misses() {
    if find_c_compiler().is_none() {
        eprintln!("No C compiler found, skipping test");
        return;
    }

    let daemon = Daemon::start(None);
    assert!(daemon.compile("plain").success());
    assert_eq!(daemon.cache_misses(), 1);
    assert_eq!(daemon.cache_write_errors(), 0);
    daemon.stop();
}

// A cache entry that does not fit a frame used to be sent anyway, and the daemon
// dropped the connection over it: the entry went uncached, every later RPC on
// that connection failed, and the stats hand-off at the end of the invocation
// took the whole delta down with it — the compile counted a cache miss that
// never reached `--show-stats`. Rust hit this constantly, since rlibs dwarfed
// the old 8 MiB default limit.
//
// The limit is now well above any real entry, and a client that somehow still
// has an oversized payload declines to send it. The entry goes uncached, and
// nothing else about the invocation is affected.
#[test]
#[serial_test::serial]
fn test_client_side_survives_an_entry_larger_than_the_frame_limit() {
    if find_c_compiler().is_none() {
        eprintln!("No C compiler found, skipping test");
        return;
    }

    let daemon = Daemon::start(Some("4096"));

    // The compile succeeds; only the cache write is skipped.
    assert!(daemon.compile("oversized").success());
    // The connection is still good, so a second invocation works the same way.
    assert!(daemon.compile("oversized").success());

    assert_eq!(
        daemon.frame_limit_kills(),
        0,
        "the daemon dropped a connection over an oversized frame"
    );
    assert_eq!(daemon.cache_misses(), 2);
    assert_eq!(daemon.cache_write_errors(), 2);

    daemon.stop();
}

// A response too large to encode used to hang the client forever. The daemon's
// handler task gave up on the connection, but the two halves of a connection are
// independent, so the socket stayed open with nobody left to answer on it, and a
// client blocked on `read_one_response` waited for a response that was never
// coming. The request has to fail — the response genuinely cannot be delivered —
// but it has to fail, not hang.
#[test]
#[serial_test::serial]
fn test_an_undeliverable_response_does_not_hang_the_client() {
    // Small enough that the daemon cannot encode a stats response.
    let daemon = Daemon::start(Some("250"));

    let mut child = daemon
        .command()
        .args(["--show-stats"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_with_timeout(&mut child, Duration::from_secs(30));

    let Some(status) = status else {
        daemon.stop_best_effort();
        panic!("--show-stats hung waiting for a response that was never coming");
    };
    assert!(
        !status.success(),
        "--show-stats reported success without a response"
    );

    // The daemon survives: only that one connection was torn down.
    let mut child = daemon
        .command()
        .args(["--show-stats"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_with_timeout(&mut child, Duration::from_secs(30)).is_some(),
        "the daemon stopped answering after an undeliverable response"
    );

    daemon.stop_best_effort();
}
