#[cfg(not(target_os = "macos"))]
use std::{net::TcpListener, process::Command};

#[cfg(not(target_os = "macos"))]
use serial_test::serial;

#[cfg(not(target_os = "macos"))]
use test_case::test_case;

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

#[test_case(false ; "start and stop")]
#[test_case(true ; "with compilations")]
#[serial]
#[cfg(not(target_os = "macos"))]
fn test_server_writes_trace_file(compile: bool) {
    let tempdir = tempfile::tempdir().unwrap();
    let trace_file = tempdir.path().join("trace.json");
    std::fs::write(
        tempdir.path().join("trace_me.rs"),
        "pub fn trace_me() -> u32 { 0 }\n",
    )
    .unwrap();
    std::fs::create_dir(tempdir.path().join("out")).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let sccache = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sccache"))
            .args(args)
            .current_dir(tempdir.path())
            .env("SCCACHE_SERVER_PORT", &port)
            .env("SCCACHE_DIR", tempdir.path().join("cache"))
            .env("SCCACHE_TRACE", &trace_file)
            .env_remove("SCCACHE_SERVER_UDS")
            .output()
            .unwrap()
    };

    let output = sccache(&["--start-server"]);
    assert!(output.status.success(), "{output:?}");
    if compile {
        for _ in 0..2 {
            let output = sccache(&[
                "rustc",
                "--crate-name",
                "trace_me",
                "--crate-type",
                "lib",
                "--emit=link",
                "--out-dir=out",
                "trace_me.rs",
            ]);
            assert!(output.status.success(), "{output:?}");
        }
    }
    let output = sccache(&["--stop-server"]);
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

    let mut compiles: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| {
            e["ph"] == "X"
                && e["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("compile: "))
        })
        .collect();
    compiles.sort_by(|a, b| a["ts"].as_f64().partial_cmp(&b["ts"].as_f64()).unwrap());
    if !compile {
        assert!(compiles.is_empty(), "{events:?}");
        return;
    }
    assert_eq!(compiles.len(), 2, "{events:?}");
    assert_eq!(compiles[0]["args"]["result"], "Miss", "{events:?}");
    assert_eq!(compiles[1]["args"]["result"], "Hit", "{events:?}");
    for span in &compiles {
        assert_eq!(span["pid"], 1);
        assert!(span["tid"].as_u64().unwrap() >= 1);
        assert_eq!(span["args"]["compiler"], "Rust");
    }
    assert_eq!(compiles[0]["tid"], compiles[1]["tid"]);
}
