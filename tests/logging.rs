// Tests for logging functionality.
//
// Copyright 2025 Mozilla Foundation
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

use regex::Regex;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

// Get the path to the sccache binary
fn sccache_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sccache"))
}

// Matches the start of a log line: `[<timestamp> <LEVEL> <pid> <target>] `
fn log_line_regex() -> Regex {
    Regex::new(r"^\[\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\w+\s+(\d+)\s+\S+\] ").unwrap()
}

#[test]
#[serial_test::serial]
fn test_log_timestamp_format_without_millis() {
    // Test that without SCCACHE_LOG_MILLIS, timestamps have second precision
    let tempdir = TempDir::new().unwrap();

    let mut cmd = Command::new(sccache_bin());
    cmd.arg("--show-stats")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_DIR", tempdir.path())
        .env_remove("SCCACHE_LOG_MILLIS");

    let output = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Pattern for timestamp without milliseconds: [2025-10-09T14:42:35Z DEBUG ...]
    let timestamp_regex = Regex::new(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+\w+\s+").unwrap();

    // Check that we have at least one log line with the expected format
    assert!(
        timestamp_regex.is_match(&stderr),
        "Expected timestamp format without milliseconds not found in stderr:\n{}",
        stderr
    );

    // Ensure NO milliseconds are present (no decimal point after seconds)
    let millis_regex = Regex::new(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z").unwrap();
    assert!(
        !millis_regex.is_match(&stderr),
        "Unexpected milliseconds found in timestamp when SCCACHE_LOG_MILLIS not set:\n{}",
        stderr
    );
}

#[test]
#[serial_test::serial]
fn test_log_timestamp_format_with_millis() {
    // Test that with SCCACHE_LOG_MILLIS, timestamps have millisecond precision
    let tempdir = TempDir::new().unwrap();

    let mut cmd = Command::new(sccache_bin());
    cmd.arg("--show-stats")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_LOG_MILLIS", "1")
        .env("SCCACHE_DIR", tempdir.path());

    let output = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Pattern for timestamp with milliseconds: [2025-10-09T14:44:56.628Z DEBUG ...]
    let millis_regex =
        Regex::new(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\s+\w+\s+").unwrap();

    // Check that we have at least one log line with millisecond precision
    assert!(
        millis_regex.is_match(&stderr),
        "Expected timestamp format with milliseconds not found in stderr:\n{}",
        stderr
    );
}

#[test]
#[serial_test::serial]
fn test_log_lines_carry_the_emitting_pid() {
    // Several sccache processes log to the same destination concurrently, so
    // every line has to say which process emitted it.
    let tempdir = TempDir::new().unwrap();

    let child = Command::new(sccache_bin())
        .arg("--show-stats")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_DIR", tempdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    let regex = log_line_regex();
    let mut log_lines = 0;
    for line in stderr.lines() {
        // Non-log output (panics, backtraces) is not our concern here.
        let Some(captures) = regex.captures(line) else {
            continue;
        };
        log_lines += 1;
        assert_eq!(
            captures.get(1).unwrap().as_str(),
            pid.to_string(),
            "log line attributed to the wrong pid (expected {}):\n{}",
            pid,
            line
        );
    }
    assert!(log_lines > 0, "no log lines found in stderr:\n{}", stderr);
}

#[test]
#[serial_test::serial]
fn test_error_log_receives_the_log_output() {
    // SCCACHE_ERROR_LOG is honoured by every process, not just the daemon:
    // in client-side mode the CLI is where the compile pipeline logs from.
    let tempdir = TempDir::new().unwrap();
    let log_path = tempdir.path().join("sccache.log");

    let child = Command::new(sccache_bin())
        .arg("--show-stats")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_ERROR_LOG", &log_path)
        .env("SCCACHE_DIR", tempdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();

    let logged = std::fs::read_to_string(&log_path).unwrap();
    let regex = log_line_regex();
    let matching = logged
        .lines()
        .filter(|line| {
            regex
                .captures(line)
                .is_some_and(|c| c.get(1).unwrap().as_str() == pid.to_string())
        })
        .count();
    assert!(
        matching > 0,
        "no log lines from pid {} in {}:\n{}",
        pid,
        log_path.display(),
        logged
    );

    // And stderr is left alone for the build's own output.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let leaked: Vec<_> = stderr.lines().filter(|l| regex.is_match(l)).collect();
    assert!(
        leaked.is_empty(),
        "log lines went to stderr as well as the error log:\n{:?}",
        leaked
    );
}

#[test]
#[serial_test::serial]
fn test_error_log_pid_placeholder_gives_a_per_process_file() {
    let tempdir = TempDir::new().unwrap();

    let child = Command::new(sccache_bin())
        .arg("--show-stats")
        .env("SCCACHE_LOG", "debug")
        .env("SCCACHE_ERROR_LOG", tempdir.path().join("sccache.%p.log"))
        .env("SCCACHE_DIR", tempdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    child.wait_with_output().unwrap();

    let log_path = tempdir.path().join(format!("sccache.{}.log", pid));
    let logged = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("{}: {}", log_path.display(), e));
    assert!(
        logged.lines().any(|line| log_line_regex().is_match(line)),
        "no log lines in {}:\n{}",
        log_path.display(),
        logged
    );
}

#[test]
#[serial_test::serial]
fn test_log_millis_flag_with_various_values() {
    // Test that SCCACHE_LOG_MILLIS accepts any value (not just "1")
    let tempdir = TempDir::new().unwrap();

    // Pattern for timestamp with milliseconds
    let millis_regex = Regex::new(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z").unwrap();

    for value in &["1", "true", "yes", "anything"] {
        let mut cmd = Command::new(sccache_bin());
        cmd.arg("--show-stats")
            .env("SCCACHE_LOG", "debug")
            .env("SCCACHE_LOG_MILLIS", value)
            .env("SCCACHE_DIR", tempdir.path());

        let output = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            millis_regex.is_match(&stderr),
            "Expected timestamp with milliseconds for SCCACHE_LOG_MILLIS={}, but not found in:\n{}",
            value,
            stderr
        );
    }
}
