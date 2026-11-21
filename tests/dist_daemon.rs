#![cfg(all(target_os = "linux", feature = "dist-server"))]

use base64::Engine;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, getpgid, getsid};
use sccache::dist::{AllocJobResult, SchedulerStatusResult, Toolchain};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::task::AbortOnDropHandle;

fn children_of(pid: u32) -> Vec<Pid> {
    let mut children = BTreeSet::new();
    for task in fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        // A runtime thread can exit between listing its task and reading its children.
        if let Ok(contents) = fs::read_to_string(task.unwrap().path().join("children")) {
            for child in contents.split_whitespace() {
                children.insert(child.parse::<i32>().unwrap());
            }
        }
    }
    children.into_iter().map(Pid::from_raw).collect()
}

struct SchedulerProcess(Child);

impl SchedulerProcess {
    fn spawn(config: &Path, log: &Path) -> Self {
        let log = fs::File::create(log).unwrap();
        Self(
            Command::new(env!("CARGO_BIN_EXE_sccache-dist"))
                .args(["scheduler", "--config"])
                .arg(config)
                .env_remove("SCCACHE_NO_DAEMON")
                .env_remove("CARGO_BUILD_INCREMENTAL")
                .env_remove("CARGO_INCREMENTAL")
                .env("NO_PROXY", "*")
                .env("SCCACHE_LOG", "debug")
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        )
    }

    async fn detached_pid(&self) -> Pid {
        let pid = loop {
            let children: Vec<_> = children_of(std::process::id())
                .into_iter()
                .filter(|pid| pid.as_raw() as u32 != self.0.id())
                .collect();
            if !children.is_empty() {
                assert_eq!(children.len(), 1, "expected one adopted scheduler daemon");
                break children[0];
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let session = getsid(Some(pid)).unwrap();
        assert_ne!(
            session,
            getsid(None).unwrap(),
            "daemon must detach its session"
        );
        assert_ne!(
            session, pid,
            "double-forked daemon must not lead its session"
        );
        assert_eq!(getpgid(Some(pid)).unwrap(), session);
        pid
    }

    async fn wait(&mut self) -> ExitStatus {
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for SchedulerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            // setsid() escapes the launcher's process group; the subreaper owns its descendants.
            for pid in children_of(std::process::id()) {
                let _ = kill(pid, Signal::SIGKILL);
            }
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Err(Errno::ECHILD) => return,
                Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(10)),
                Ok(_) | Err(Errno::EINTR) => {}
                Err(error) => panic!("failed to reap scheduler processes: {error}"),
            }
        }
        if std::thread::panicking() {
            eprintln!("timed out reaping scheduler processes");
        } else {
            panic!("timed out reaping scheduler processes");
        }
    }
}

#[tokio::test]
async fn test_dist_scheduler_initializes_jwks_after_daemonizing() {
    // Subreaping must stay in a dedicated test binary, away from unrelated tests' children.
    nix::sys::prctl::set_child_subreaper(true).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let scheduler_addr = reserved.local_addr().unwrap();
    let config = directory.path().join("scheduler.toml");
    let log = directory.path().join("scheduler.log");
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let jwks = serde_json::json!({
        "keys": [{
            "kid": "test-key",
            "kty": "RSA",
            "n": BASE64_URL_SAFE_ENGINE.encode(rsa.n().to_vec()),
            "e": BASE64_URL_SAFE_ENGINE.encode(rsa.e().to_vec()),
        }],
    });
    let requests = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Semaphore::new(0));
    let (requested_tx, mut requested_rx) = mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let jwks_addr = listener.local_addr().unwrap();
    let _server = AbortOnDropHandle::new(tokio::spawn({
        let requests = Arc::clone(&requests);
        let release = Arc::clone(&release);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0, "JWKS request ended before its headers");
                    request.extend_from_slice(&buffer[..read]);
                }
                assert!(request.starts_with(b"GET /jwks HTTP/1.1\r\n"));
                let attempt = requests.fetch_add(1, Ordering::SeqCst) + 1;
                requested_tx.send(attempt).unwrap();
                release.acquire().await.unwrap().forget();
                let status = if attempt == 1 {
                    reqwest::StatusCode::SERVICE_UNAVAILABLE
                } else {
                    reqwest::StatusCode::OK
                };
                let body = jwks.to_string();
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    status.as_u16(),
                    status.canonical_reason().unwrap(),
                    body.len(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        }
    }));
    fs::write(
        &config,
        format!(
            r#"public_addr = "{scheduler_addr}"
[client_auth]
type = "jwt_validate"
audience = "test-audience"
issuer = "test-issuer"
jwks_url = "http://{jwks_addr}/jwks"
[server_auth]
type = "token"
token = "server-token"
"#,
        ),
    )
    .unwrap();

    let mut phase = "waiting for initial JWKS request";
    tokio::time::timeout(Duration::from_secs(15), async {
        {
            let mut failed = SchedulerProcess::spawn(&config, &log);
            tokio::select! {
                request = requested_rx.recv() => assert_eq!(request, Some(1)),
                status = failed.wait() => panic!("scheduler exited before fetching JWKS: {status}\n{}", fs::read_to_string(&log).unwrap()),
            }
            assert!(failed.0.try_wait().unwrap().is_none());
            let failed_pid = failed.detached_pid().await;
            release.add_permits(1);
            phase = "waiting for failed initialization to exit";
            assert_eq!(failed.wait().await.code(), Some(2));
            let stderr = fs::read_to_string(&log).unwrap();
            assert!(
                stderr.contains("Failed to create a checker for valid JWTs"),
                "{stderr}"
            );
            assert!(stderr.contains("Could not retrieve JWKs, HTTP error: 503"), "{stderr}");
            phase = "waiting for the failed daemon to exit";
            // The error handshake can finish before the daemon exits and becomes reapable.
            loop {
                match waitpid(failed_pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Ok(WaitStatus::Exited(_, 2)) => break,
                    status => panic!("unexpected failed daemon exit: {status:?}"),
                }
            }
            assert!(children_of(std::process::id()).is_empty());
        }

        let (mut inherited_reader, inherited_writer) = UnixStream::pair().unwrap();
        assert_eq!(
            unsafe { libc::fcntl(inherited_writer.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        phase = "waiting for successful JWKS request";
        let mut daemon = SchedulerProcess::spawn(&config, &log);
        drop(inherited_writer);
        tokio::select! {
            request = requested_rx.recv() => assert_eq!(request, Some(2)),
            status = daemon.wait() => panic!("scheduler exited before fetching JWKS: {status}\n{}", fs::read_to_string(&log).unwrap()),
        }
        assert!(daemon.0.try_wait().unwrap().is_none());
        let daemon_pid = daemon.detached_pid().await;
        drop(reserved);
        release.add_permits(1);
        phase = "waiting for the launcher to report readiness";
        assert!(daemon.wait().await.success());
        phase = "waiting for the detached scheduler's HTTP server";

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let base_url = format!("http://{scheduler_addr}/api/v1/scheduler");
        let response = client
            .get(format!("{base_url}/status"))
            .header("accept", "application/json")
            .send()
            .await
            .expect("scheduler must serve HTTP immediately after launcher success");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let status = response.json::<SchedulerStatusResult>().await.unwrap();
        assert_eq!(
            (status.num_servers, status.num_cpus, status.in_progress),
            (0, 0, 0)
        );
        let children = children_of(std::process::id());
        assert_eq!(children.len(), 1, "expected one adopted scheduler daemon");
        let pid = children[0];
        assert_ne!(pid.as_raw() as u32, daemon.0.id());
        assert_eq!(pid, daemon_pid, "initialization must run in the final daemon");
        inherited_reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(
            inherited_reader.read(&mut [0]).unwrap(),
            0,
            "daemon must close unrelated inherited descriptors"
        );

        let mut header = jwt::Header::new(jwt::Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        let token = jwt::encode(
            &header,
            &serde_json::json!({
                "aud": "test-audience",
                "iss": "test-issuer",
                "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
            }),
            &jwt::EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap(),
        )
        .unwrap();
        let body = bincode::serialize(&Toolchain {
            archive_id: blake3::hash(b"test-toolchain").to_hex().to_string(),
        })
        .unwrap();
        for (token, expected) in [
            ("not-a-jwt", reqwest::StatusCode::UNAUTHORIZED),
            (token.as_str(), reqwest::StatusCode::OK),
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
            if expected == reqwest::StatusCode::OK {
                let result = response.json::<AllocJobResult>().await.unwrap();
                let AllocJobResult::Fail { msg } = result else {
                    panic!("expected no capacity without build servers")
                };
                assert_eq!(msg, "Insufficient capacity across 0 available servers");
            }
        }
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        // Exercise cancellation cleanup without waiting for the outer startup deadline.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), async move {
                let _daemon = daemon;
                std::future::pending::<()>().await;
            })
            .await
            .is_err()
        );
        assert!(children_of(std::process::id()).is_empty());
    })
    .await
    .unwrap_or_else(|_| {
        panic!("timed out {phase}\n{}", fs::read_to_string(&log).unwrap());
    });
}
