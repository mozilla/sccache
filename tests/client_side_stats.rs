// Tests for statistics reporting in client-side mode.
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
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn sccache_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sccache"))
}

fn find_c_compiler() -> Option<PathBuf> {
    ["cc", "gcc", "clang"]
        .iter()
        .find_map(|c| which::which(c).ok())
}

/// A source file whose cache entry is comfortably larger than the frame limit
/// used below, so that storing it has to send an oversized request.
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
    max_frame_length: Option<&'static str>,
}

impl Daemon {
    fn start(max_frame_length: Option<&'static str>) -> Daemon {
        let tempdir = TempDir::new().unwrap();
        let daemon = Daemon {
            socket: tempdir.path().join("sccache.sock"),
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

    /// The number of C/C++ cache misses the daemon has recorded.
    fn cache_misses(&self) -> u64 {
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
        let stats: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        stats["stats"]["cache_misses"]["counts"]["C/C++"]
            .as_u64()
            .unwrap_or(0)
    }

    fn stop(self) {
        let output = self.command().arg("--stop-server").output().unwrap();
        assert!(
            output.status.success(),
            "failed to stop server: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
    daemon.stop();
}

// A cache write larger than SCCACHE_MAX_FRAME_LENGTH makes the daemon drop the
// connection. That used to take the whole invocation's stats delta with it,
// because the delta was shipped last over that same connection and the failure
// was ignored: the compile counted a cache miss that never showed up in
// `--show-stats`. Rust hit this routinely, since rlibs dwarf the 8 MiB default.
#[test]
#[serial_test::serial]
fn test_client_side_records_cache_misses_when_the_connection_breaks() {
    if find_c_compiler().is_none() {
        eprintln!("No C compiler found, skipping test");
        return;
    }

    let daemon = Daemon::start(Some("4096"));
    // The compile itself still succeeds; only the cache write fails.
    assert!(daemon.compile("oversized").success());
    assert_eq!(daemon.cache_misses(), 1);
    daemon.stop();
}
