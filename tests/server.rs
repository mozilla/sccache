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
