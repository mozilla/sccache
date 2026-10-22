#[cfg(not(target_os = "macos"))]
use std::{net::TcpListener, process::Command};

#[cfg(not(target_os = "macos"))]
use serial_test::serial;

#[test]
#[serial]
// test fails intermittently on macos:
// https://github.com/mozilla/sccache/issues/234
#[cfg(not(target_os = "macos"))]
fn test_server_port_in_use() {
    // Bind an arbitrary free port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sccache = env!("CARGO_BIN_EXE_sccache");
    let output = Command::new(sccache)
        .arg("--start-server")
        .env(
            "SCCACHE_SERVER_PORT",
            listener.local_addr().unwrap().port().to_string(),
        )
        .env_remove("SCCACHE_SERVER_UDS")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let s = String::from_utf8_lossy(&output.stderr);
    const MSG: &str = "Server startup failed:";
    assert!(
        s.contains(MSG),
        "Output did not contain '{}':\n========\n{}\n========",
        MSG,
        s
    );
}

#[test]
#[serial]
#[cfg(not(target_os = "macos"))]
fn test_server_writes_trace_file() {
    let tempdir = tempfile::tempdir().unwrap();
    let trace_file = tempdir.path().join("trace.json");
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let sccache = |arg: &str| {
        Command::new(env!("CARGO_BIN_EXE_sccache"))
            .arg(arg)
            .env("SCCACHE_SERVER_PORT", &port)
            .env("SCCACHE_DIR", tempdir.path().join("cache"))
            .env("SCCACHE_TRACE", &trace_file)
            .env_remove("SCCACHE_SERVER_UDS")
            .output()
            .unwrap()
    };

    let output = sccache("--start-server");
    assert!(output.status.success(), "{output:?}");
    let output = sccache("--stop-server");
    assert!(output.status.success(), "{output:?}");

    // The server finalizes the file while shutting down, after replying to
    // --stop-server.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let events = loop {
        let parsed = std::fs::read(&trace_file)
            .ok()
            .and_then(|data| serde_json::from_slice::<Vec<serde_json::Value>>(&data).ok());
        match parsed {
            Some(events) => break events,
            None if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            None => panic!("no valid trace file at {}", trace_file.display()),
        }
    };
    assert!(
        events
            .iter()
            .any(|e| e["ph"] == "M" && e["name"] == "process_name"),
        "{events:?}"
    );
}
