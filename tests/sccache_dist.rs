#![cfg(all(
    feature = "dist-server",
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "freebsd",
    ),
))]

use assert_cmd::assert::OutputAssertExt;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use predicates::str::contains;
use reqwest::StatusCode;
use serde_json::json;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

async fn jwks_server(
    status: StatusCode,
    gates: Option<(Arc<Notify>, Arc<Notify>)>,
) -> (SocketAddr, AbortOnDropHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "JWK request ended before its headers");
            request.extend_from_slice(&buffer[..read]);
        }
        if let Some((requested, release)) = gates {
            requested.notify_one();
            release.notified().await;
        }
        let body = r#"{"keys":[]}"#;
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            status.as_u16(),
            status.canonical_reason().unwrap(),
            body.len(),
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    (address, AbortOnDropHandle::new(server))
}

#[tokio::test]
async fn scheduler_jwt_startup_after_daemonization() {
    for (status, expected_error, expected_cause) in [
        (
            StatusCode::OK,
            "Failed to start http server for sccache scheduler",
            "Address already in use",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to create a checker for valid JWTs",
            "Could not retrieve JWKs, HTTP error: 503",
        ),
    ] {
        let (jwks_address, _jwks_server) = jwks_server(status, None).await;

        // Force startup to exit at binding, after authentication and runtime initialization.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let config_path = tempdir.path().join("scheduler.json");
        let config = json!({
            "public_addr": listener.local_addr().unwrap(),
            "client_auth": {
                "type": "jwt_validate",
                "audience": "test",
                "issuer": "test",
                "jwks_url": format!("http://{jwks_address}/jwks"),
            },
            "server_auth": { "type": "token", "token": "test" },
        });
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

        let output = tokio::time::timeout(
            Duration::from_secs(10),
            Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
                .arg("scheduler")
                .arg("--config")
                .arg(&config_path)
                .env("SCCACHE_NO_DAEMON", "1")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("scheduler startup must finish")
        .unwrap();
        output
            .assert()
            .failure()
            .stderr(contains(expected_error))
            .stderr(contains(expected_cause));
    }
}

fn scheduler_command(
    public_addr: SocketAddr,
    jwks_address: SocketAddr,
) -> (tempfile::TempDir, Command) {
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir.path().join("scheduler.json");
    let config = json!({
        "public_addr": public_addr,
        "client_auth": {
            "type": "jwt_validate",
            "audience": "test",
            "issuer": "test",
            "jwks_url": format!("http://{jwks_address}/jwks"),
        },
        "server_auth": { "type": "token", "token": "test" },
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sccache-dist"));
    command
        .arg("scheduler")
        .arg("--config")
        .arg(config_path)
        .env_remove("SCCACHE_NO_DAEMON")
        .env("SCCACHE_LOG", "debug")
        .kill_on_drop(true);
    (tempdir, command)
}

struct SchedulerDaemon(Pid);

impl SchedulerDaemon {
    fn from_stderr(stderr: &[u8]) -> Option<Self> {
        String::from_utf8_lossy(stderr).lines().find_map(|line| {
            let (_, pid) = line.split_once("Scheduler daemon ready (pid ")?;
            let pid = pid.strip_suffix(')')?.parse::<i32>().ok()?;
            (pid > 0).then(|| Self(Pid::from_raw(pid)))
        })
    }
}

impl Drop for SchedulerDaemon {
    fn drop(&mut self) {
        let _ = kill(self.0, Signal::SIGTERM);
    }
}

async fn scheduler_output(
    mut launcher: Child,
    daemon: &mut Option<SchedulerDaemon>,
) -> io::Result<Output> {
    let mut stdout = launcher.stdout.take().unwrap();
    let mut stderr = BufReader::new(launcher.stderr.take().unwrap());
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let read_stderr = async {
        let mut line = Vec::new();
        while stderr.read_until(b'\n', &mut line).await? != 0 {
            if daemon.is_none() {
                *daemon = SchedulerDaemon::from_stderr(&line);
            }
            stderr_bytes.extend_from_slice(&line);
            line.clear();
        }
        Ok::<_, io::Error>(())
    };
    let (status, _, _) = tokio::try_join!(
        launcher.wait(),
        stdout.read_to_end(&mut stdout_bytes),
        read_stderr,
    )?;
    Ok(Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}

#[tokio::test]
async fn scheduler_daemon_startup_errors_reach_launcher() {
    for (status, expected_error, expected_cause) in [
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to create a checker for valid JWTs",
            "Could not retrieve JWKs, HTTP error: 503",
        ),
        (
            StatusCode::OK,
            "Failed to start http server for sccache scheduler",
            "Address already in use",
        ),
    ] {
        let (jwks_address, _jwks_server) = jwks_server(status, None).await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (_tempdir, mut command) =
            scheduler_command(listener.local_addr().unwrap(), jwks_address);
        let output = tokio::time::timeout(Duration::from_secs(10), command.output())
            .await
            .expect("scheduler startup must finish")
            .unwrap();
        let _daemon = SchedulerDaemon::from_stderr(&output.stderr);
        output
            .assert()
            .failure()
            .stderr(contains(expected_error))
            .stderr(contains(expected_cause));
    }
}

#[tokio::test]
async fn scheduler_daemon_waits_for_jwks_and_serves_status_on_return() {
    let requested = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (jwks_address, _jwks_server) = jwks_server(
        StatusCode::OK,
        Some((Arc::clone(&requested), Arc::clone(&release))),
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let public_addr = listener.local_addr().unwrap();
    let (_tempdir, mut command) = scheduler_command(public_addr, jwks_address);
    drop(listener);
    let mut launcher = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request_received = tokio::time::timeout(Duration::from_secs(5), requested.notified()).await;
    let launcher_pending = tokio::time::timeout(Duration::from_millis(200), launcher.wait())
        .await
        .is_err();

    // Release startup before assertions so a failed wait check cannot strand the daemon.
    release.notify_one();
    let mut daemon = None;
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        scheduler_output(launcher, &mut daemon),
    )
    .await
    .expect("scheduler startup must finish after JWK retrieval")
    .unwrap();
    output.assert().success();
    let _daemon = daemon.expect("scheduler must log Scheduler daemon ready (pid PID)");
    assert!(request_received.is_ok(), "scheduler must request JWKs");
    assert!(
        launcher_pending,
        "launcher exited before JWK retrieval completed"
    );

    let status = tokio::task::spawn_blocking(move || {
        let body = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get(format!("http://{public_addr}/api/v1/scheduler/status"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .expect("scheduler must be reachable immediately after launcher success")
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        serde_json::from_str::<serde_json::Value>(&body).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(status["num_servers"], json!(0));
}
