#![cfg(feature = "dist-server")]

use base64::Engine;
#[cfg(target_os = "linux")]
use nix::sys::prctl;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use reqwest::{Client, StatusCode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use sccache::dist::{AllocJobResult, SchedulerStatusResult, Toolchain};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use serde_json::{Value, json};
use serial_test::serial;
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as AsyncTcpListener;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};
use tokio_util::task::AbortOnDropHandle;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

struct JwksServer {
    address: SocketAddr,
    requested: Arc<Notify>,
    release: Arc<Notify>,
    _task: AbortOnDropHandle<()>,
}

impl JwksServer {
    async fn new(status: StatusCode, body: Value) -> Self {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requested = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let task = tokio::spawn({
            let requested = Arc::clone(&requested);
            let release = Arc::clone(&release);
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0, "JWK request ended before its headers");
                    request.extend_from_slice(&buffer[..read]);
                }
                assert!(request.starts_with(b"GET /jwks HTTP/1.1\r\n"));
                requested.notify_one();
                release.notified().await;
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    status.as_u16(),
                    status.canonical_reason().unwrap(),
                    body.len(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            requested,
            release,
            _task: AbortOnDropHandle::new(task),
        }
    }
}

fn scheduler_command(
    public_addr: SocketAddr,
    jwks_address: SocketAddr,
    server_auth: serde_json::Value,
) -> (TempDir, Command) {
    let directory = tempdir().unwrap();
    let config_path = directory.path().join("scheduler.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&json!({
            "public_addr": public_addr,
            "client_auth": {
                "type": "jwt_validate",
                "audience": "test-audience",
                "issuer": "test-issuer",
                "jwks_url": format!("http://{jwks_address}/jwks"),
            },
            "server_auth": server_auth,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sccache-dist"));
    for (name, _) in env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"SCCACHE_") {
            command.env_remove(name);
        }
    }
    command
        .args(["scheduler", "--config"])
        .arg(config_path)
        .env_remove("CARGO_BUILD_INCREMENTAL")
        .env_remove("CARGO_INCREMENTAL")
        .env("NO_PROXY", "*")
        .env("SCCACHE_LOG", "debug");
    (directory, command)
}

struct SchedulerProcess {
    launcher: Child,
    directory: TempDir,
}

impl SchedulerProcess {
    fn spawn(directory: TempDir, mut command: Command) -> Self {
        #[cfg(target_os = "linux")]
        prctl::set_child_subreaper(true).unwrap();
        let log = fs::File::create(directory.path().join("scheduler.log")).unwrap();
        let launcher = command
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        Self {
            launcher,
            directory,
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(self.directory.path().join("scheduler.log")).unwrap()
    }

    async fn wait(&mut self) -> ExitStatus {
        loop {
            if let Some(status) = self.launcher.try_wait().unwrap() {
                return status;
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn detached_pid(&self) -> Pid {
        loop {
            let children: Vec<_> = linux::children()
                .unwrap()
                .into_iter()
                .filter(|pid| pid.as_raw() as u32 != self.launcher.id())
                .collect();
            if !children.is_empty() {
                assert_eq!(children.len(), 1, "expected one adopted scheduler daemon");
                return children[0];
            }
            sleep(POLL_INTERVAL).await;
        }
    }
}

impl Drop for SchedulerProcess {
    fn drop(&mut self) {
        let _ = self.launcher.kill();
        let _ = self.launcher.wait();
        #[cfg(target_os = "linux")]
        if let Err(error) = linux::cleanup() {
            if thread::panicking() {
                eprintln!("failed to clean up scheduler processes: {error}");
            } else {
                panic!("failed to clean up scheduler processes: {error}");
            }
        }
        // Without Linux subreaping, cleanup can only identify a daemon after its readiness report.
        #[cfg(target_os = "freebsd")]
        if let Ok(log) = fs::read_to_string(self.directory.path().join("scheduler.log")) {
            for line in log.lines() {
                if let Some((_, pid)) = line.split_once("Scheduler daemon ready (pid ")
                    && let Some(pid) = pid.strip_suffix(')').and_then(|pid| pid.parse().ok())
                {
                    let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::errno::Errno;
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use std::collections::BTreeSet;
    use std::process;
    use std::time::Instant;

    pub fn children() -> io::Result<Vec<Pid>> {
        let mut children = BTreeSet::new();
        for task in fs::read_dir(format!("/proc/{}/task", process::id()))? {
            match fs::read_to_string(task?.path().join("children")) {
                Ok(contents) => {
                    for child in contents.split_whitespace() {
                        children.insert(child.parse::<i32>().map_err(io::Error::other)?);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(children.into_iter().map(Pid::from_raw).collect())
    }

    pub async fn wait_for_exit(pid: Pid, expected_code: i32) {
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => sleep(POLL_INTERVAL).await,
                status => {
                    assert_eq!(status, Ok(WaitStatus::Exited(pid, expected_code)));
                    return;
                }
            }
        }
    }

    pub fn cleanup() -> io::Result<()> {
        // Every process-spawning test in this binary is serialized: adopted children belong to it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            for pid in children()? {
                let _ = kill(pid, Signal::SIGKILL);
            }
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Err(Errno::ECHILD) => return Ok(()),
                Ok(WaitStatus::StillAlive) => thread::sleep(POLL_INTERVAL),
                Ok(_) | Err(Errno::EINTR) => {}
                Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "scheduler children did not exit",
        ))
    }
}

async fn startup_errors(foreground: bool) {
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
        let jwks = JwksServer::new(status, json!({ "keys": [] })).await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (directory, mut command) = scheduler_command(
            listener.local_addr().unwrap(),
            jwks.address,
            json!({ "type": "DANGEROUSLY_INSECURE" }),
        );
        if foreground {
            command.env("SCCACHE_NO_DAEMON", "1");
        }
        let mut scheduler = SchedulerProcess::spawn(directory, command);
        timeout(TEST_TIMEOUT, async {
            jwks.requested.notified().await;
            #[cfg(target_os = "linux")]
            let daemon = if foreground {
                assert_eq!(
                    linux::children().unwrap(),
                    [Pid::from_raw(scheduler.launcher.id() as i32)],
                    "foreground initialization must not fork"
                );
                None
            } else {
                Some(scheduler.detached_pid().await)
            };
            jwks.release.notify_one();
            assert_eq!(
                scheduler.wait().await.code(),
                Some(2),
                "{}",
                scheduler.log()
            );
            let log = scheduler.log();
            assert!(
                log.contains("Scheduler starting with DANGEROUSLY_INSECURE server authentication"),
                "{log}"
            );
            assert!(log.contains(expected_error), "{log}");
            assert!(log.contains(expected_cause), "{log}");
            #[cfg(target_os = "linux")]
            if let Some(pid) = daemon {
                linux::wait_for_exit(pid, 2).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("startup error was not reported: {}", scheduler.log()));
    }
}

#[tokio::test]
#[serial]
async fn scheduler_foreground_reports_startup_errors() {
    startup_errors(true).await;
}

#[tokio::test]
#[serial]
async fn scheduler_daemon_startup_errors_reach_launcher() {
    startup_errors(false).await;
}

#[tokio::test]
#[serial]
async fn scheduler_daemon_waits_for_jwks_and_serves_authenticated_requests() {
    for closed_stdio in [false, true] {
        let rsa = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let jwks = JwksServer::new(
            StatusCode::OK,
            json!({ "keys": [{
            "kid": "test-key",
            "kty": "RSA",
            "n": BASE64_URL_SAFE_ENGINE.encode(rsa.n().to_bytes_be()),
            "e": BASE64_URL_SAFE_ENGINE.encode(rsa.e().to_bytes_be()),
        }] }),
        )
        .await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (directory, mut command) = scheduler_command(
            address,
            jwks.address,
            json!({ "type": "token", "token": "server-token" }),
        );
        drop(listener);
        if closed_stdio {
            // SAFETY: only the child closes its standard streams before exec.
            unsafe {
                command.pre_exec(|| {
                    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
                        if libc::close(fd) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
        let mut scheduler = SchedulerProcess::spawn(directory, command);
        timeout(TEST_TIMEOUT, async {
            jwks.requested.notified().await;
            #[cfg(target_os = "linux")]
            {
                use nix::unistd::{getpgid, getsid};
                let pid = scheduler.detached_pid().await;
                let session = getsid(Some(pid)).unwrap();
                assert_ne!(
                    session,
                    getsid(None).unwrap(),
                    "daemon must detach its session"
                );
                assert_ne!(session, pid, "final daemon must not lead its session");
                assert_eq!(getpgid(Some(pid)).unwrap(), session);
            }
            assert!(
                timeout(Duration::from_millis(200), scheduler.wait())
                    .await
                    .is_err(),
                "launcher exited before JWKS retrieval completed: {}",
                scheduler.log()
            );
            jwks.release.notify_one();
            assert!(scheduler.wait().await.success(), "{}", scheduler.log());

            let client = Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let base_url = format!("http://{address}/api/v1/scheduler");
            let status = client
                .get(format!("{base_url}/status"))
                .header("accept", "application/json")
                .send()
                .await
                .expect("scheduler must be reachable immediately after launcher success")
                .error_for_status()
                .unwrap()
                .json::<SchedulerStatusResult>()
                .await
                .unwrap();
            assert_eq!(
                (status.num_servers, status.num_cpus, status.in_progress),
                (0, 0, 0)
            );

            let mut header = jwt::Header::new(jwt::Algorithm::RS256);
            header.kid = Some("test-key".to_owned());
            let token = jwt::encode(
                &header,
                &json!({
                    "aud": "test-audience",
                    "iss": "test-issuer",
                    "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
                }),
                &jwt::EncodingKey::from_rsa_pem(
                    rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes(),
                )
                .unwrap(),
            )
            .unwrap();
            let (claims, _) = token.rsplit_once('.').unwrap();
            let wrong_signature = format!("{claims}.{}", BASE64_URL_SAFE_ENGINE.encode([0; 256]));
            let body = bincode::serialize(&Toolchain {
                archive_id: blake3::hash(b"test-toolchain").to_hex().to_string(),
            })
            .unwrap();
            for (token, expected) in [
                ("not-a-jwt", StatusCode::UNAUTHORIZED),
                (wrong_signature.as_str(), StatusCode::UNAUTHORIZED),
                (token.as_str(), StatusCode::OK),
            ] {
                let response = client
                    .post(format!("{base_url}/alloc_job"))
                    .bearer_auth(token)
                    .header("content-type", "application/octet-stream")
                    .header("accept", "application/json")
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected);
                if expected == StatusCode::OK {
                    let AllocJobResult::Fail { msg } = response.json().await.unwrap() else {
                        panic!("expected no capacity without build servers");
                    };
                    assert_eq!(msg, "Insufficient capacity across 0 available servers");
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("scheduler startup timed out: {}", scheduler.log()));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[serial]
async fn scheduler_daemon_exits_when_launcher_dies_during_jwks_retrieval() {
    let jwks = JwksServer::new(StatusCode::OK, json!({ "keys": [] })).await;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (directory, command) = scheduler_command(
        listener.local_addr().unwrap(),
        jwks.address,
        json!({ "type": "token", "token": "server-token" }),
    );
    let mut scheduler = SchedulerProcess::spawn(directory, command);
    timeout(TEST_TIMEOUT, async {
        jwks.requested.notified().await;
        let daemon = scheduler.detached_pid().await;
        scheduler.launcher.kill().unwrap();
        assert!(!scheduler.wait().await.success());
        // Leave JWKS blocked: only the startup watchdog can make this daemon exit.
        linux::wait_for_exit(daemon, 2).await;
        assert!(linux::children().unwrap().is_empty());
    })
    .await
    .unwrap_or_else(|_| panic!("abandoned startup did not exit: {}", scheduler.log()));
}
