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

#[cfg(not(target_os = "macos"))]
fn run_traced_server(
    dir: &std::path::Path,
    run: impl FnOnce(&dyn Fn(&[&str]) -> std::process::Output),
) -> Vec<serde_json::Value> {
    let trace_file = dir.join("trace.json");
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let sccache = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sccache"))
            .args(args)
            .current_dir(dir)
            .env("SCCACHE_SERVER_PORT", &port)
            .env("SCCACHE_DIR", dir.join("cache"))
            .env("SCCACHE_TRACE", &trace_file)
            .env_remove("SCCACHE_SERVER_UDS")
            .output()
            .unwrap()
    };

    let output = sccache(&["--start-server"]);
    assert!(output.status.success(), "{output:?}");
    run(&sccache);
    let output = sccache(&["--stop-server"]);
    assert!(output.status.success(), "{output:?}");

    // The server finalizes the file while shutting down, after replying to
    // --stop-server.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let parsed = std::fs::read(&trace_file)
            .ok()
            .and_then(|data| serde_json::from_slice::<Vec<serde_json::Value>>(&data).ok());
        match parsed {
            Some(events) => {
                assert!(
                    events
                        .iter()
                        .any(|e| e["ph"] == "M" && e["name"] == "process_name"),
                    "{events:?}"
                );
                return events;
            }
            None if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            None => panic!("no valid trace file at {}", trace_file.display()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn compile_spans(events: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    let mut compiles: Vec<_> = events
        .iter()
        .filter(|e| {
            e["ph"] == "X"
                && e["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("compile: "))
        })
        .collect();
    compiles.sort_by(|a, b| a["ts"].as_f64().partial_cmp(&b["ts"].as_f64()).unwrap());
    compiles
}

#[cfg(not(target_os = "macos"))]
fn span_bounds(span: &serde_json::Value) -> (f64, f64) {
    let ts = span["ts"].as_f64().unwrap();
    (ts, ts + span["dur"].as_f64().unwrap())
}

/// Complete spans named `name` on the same track as `parent` and inside its interval.
#[cfg(not(target_os = "macos"))]
fn spans_within<'a>(
    events: &'a [serde_json::Value],
    name: &str,
    parent: &serde_json::Value,
) -> Vec<&'a serde_json::Value> {
    let (start, end) = span_bounds(parent);
    events
        .iter()
        .filter(|e| {
            e["ph"] == "X"
                && e["name"] == name
                && e["pid"] == parent["pid"]
                && e["tid"] == parent["tid"]
        })
        .filter(|e| {
            let (s, t) = span_bounds(e);
            s >= start && t <= end
        })
        .collect()
}

#[test_case(false ; "start and stop")]
#[test_case(true ; "with compilations")]
#[serial]
#[cfg(not(target_os = "macos"))]
fn test_server_writes_trace_file(compile: bool) {
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::write(
        tempdir.path().join("trace_me.rs"),
        "pub fn trace_me() -> u32 { 0 }\n",
    )
    .unwrap();
    std::fs::create_dir(tempdir.path().join("out")).unwrap();
    let events = run_traced_server(tempdir.path(), |sccache| {
        if !compile {
            return;
        }
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
    });

    let compiles = compile_spans(&events);
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
        assert_eq!(spans_within(&events, "parse_dependencies", span).len(), 1);
    }
    assert_eq!(compiles[0]["tid"], compiles[1]["tid"]);

    let parse_args: Vec<_> = events
        .iter()
        .filter(|e| e["ph"] == "X" && e["name"] == "parse_arguments")
        .collect();
    assert_eq!(parse_args.len(), 2, "{events:?}");
    assert!(parse_args.iter().all(|e| e["tid"] == compiles[0]["tid"]));
}

#[test]
#[serial]
#[cfg(all(unix, not(target_os = "macos")))]
fn test_server_traces_preprocessor_cache() {
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::write(
        tempdir.path().join("trace_me.h"),
        "static inline int trace_me(void) { return 0; }\n",
    )
    .unwrap();
    std::fs::write(
        tempdir.path().join("trace_me.c"),
        "#include \"trace_me.h\"\nint main(void) { return trace_me(); }\n",
    )
    .unwrap();
    let events = run_traced_server(tempdir.path(), |sccache| {
        for _ in 0..2 {
            let output = sccache(&["cc", "-c", "trace_me.c", "-o", "trace_me.o"]);
            assert!(output.status.success(), "{output:?}");
        }
    });

    let compiles = compile_spans(&events);
    assert_eq!(compiles.len(), 2, "{events:?}");
    assert_eq!(compiles[0]["args"]["result"], "Miss", "{events:?}");
    assert_eq!(compiles[1]["args"]["result"], "Hit", "{events:?}");
    assert_eq!(
        spans_within(&events, "parse_preprocessor_includes", compiles[0]).len(),
        1,
        "{events:?}"
    );
    assert!(
        !spans_within(&events, "scan_file", compiles[1]).is_empty(),
        "{events:?}"
    );
}
