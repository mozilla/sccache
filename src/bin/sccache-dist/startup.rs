//! Scheduler startup handshake between the launcher and its daemon.
//!
//! Initialization runs after daemonization so Tokio workers and HTTP clients are not
//! carried across a fork. The launcher waits for authentication and listener binding,
//! then acknowledges readiness; the watchdog confirms the acknowledgment before the
//! launcher returns success and kills the daemon if the launcher abandons startup.

use anyhow::{Context, Result, anyhow, bail, ensure};
use daemonix::{Daemonize, Outcome};
use sccache::util::daemonize_cleanup;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE_SIZE: u64 = 64 * 1024;
const STARTUP_ACK: u8 = 1;

#[derive(Serialize, Deserialize)]
enum StartupStatus {
    Ready { pid: u32 },
    // Outermost context first, root cause last. Messages preserve diagnostics across
    // processes, but not concrete error types, downcasting, or backtraces.
    Error(Vec<String>),
}

/// Owns the daemon's one-shot status sender; foreground mode has no launcher to notify.
pub struct StartupNotifier {
    stream: Option<UnixStream>,
}

impl StartupNotifier {
    /// Uses a dedicated thread so abandonment is detected even if runtime startup or
    /// authentication blocks. The cloned socket stays alive after `send` consumes its copy.
    fn watch_launcher(&self, timeout: Duration) -> Result<()> {
        let mut stream = self
            .stream
            .as_ref()
            .context("missing scheduler startup channel")?
            .try_clone()?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        std::thread::Builder::new()
            .name("scheduler-startup".into())
            .spawn(move || {
                let mut ack = [0];
                if stream.read_exact(&mut ack).is_err()
                    || ack[0] != STARTUP_ACK
                    || stream.write_all(&[STARTUP_ACK]).is_err()
                {
                    // Unwinding could wait indefinitely for a blocking DNS lookup during runtime shutdown.
                    std::process::exit(2);
                }
            })
            .context("failed to watch scheduler launcher")?;
        Ok(())
    }

    /// Call only after authentication succeeds and the listener is bound, so launcher
    /// success means requests can be served without a separate readiness poll.
    pub fn ready(&mut self) -> Result<()> {
        self.send(StartupStatus::Ready {
            pid: std::process::id(),
        })
    }

    /// Consumes the sender to prevent a later failure from reporting a second status.
    /// A newline frames the JSON without waiting for the watchdog's socket copy to close.
    fn send(&mut self, status: StartupStatus) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.set_write_timeout(Some(STARTUP_TIMEOUT))?;
            let mut message = serde_json::to_vec(&status)?;
            message.push(b'\n');
            if message.len() as u64 > MAX_RESPONSE_SIZE {
                bail!("scheduler startup response exceeds size limit");
            }
            stream
                .write_all(&message)
                .context("failed to report scheduler startup status")?;
        }
        Ok(())
    }
}

/// Chooses foreground or daemon execution before initialization can create worker threads.
/// Both modes retain the existing FD cleanup and crash setup; only background mode forks.
pub fn run(initialize: impl FnOnce(&mut StartupNotifier) -> Result<Infallible>) -> Result<i32> {
    if std::env::var("SCCACHE_NO_DAEMON").as_deref() == Ok("1") {
        daemonize_cleanup(&[])?;
        return initialize(&mut StartupNotifier { stream: None }).map(|never| match never {});
    }

    let (launcher, daemon) = UnixStream::pair().context("failed to create startup channel")?;
    // If code closes stdin/stdout/stderr after Rust initializes them, socketpair
    // can reuse fd 0, 1, or 2. During daemonization, dup2 redirects those slots
    // to /dev/null, closing the socket endpoint and breaking the handshake.
    // Reject this state before forking so the invoking process reports an error.
    ensure!(
        launcher.as_raw_fd() > libc::STDERR_FILENO && daemon.as_raw_fd() > libc::STDERR_FILENO,
        "startup sockets must not occupy standard file descriptors"
    );
    match Daemonize::new().execute() {
        Outcome::Parent(result) => {
            drop(daemon);
            result.context("failed to daemonize scheduler")?;
            wait_for_startup(launcher, STARTUP_TIMEOUT)?;
            Ok(0)
        }
        Outcome::Child(result) => {
            drop(launcher);
            let fd = daemon.as_raw_fd();
            let mut notifier = StartupNotifier {
                stream: Some(daemon),
            };
            let result = result
                .context("failed to daemonize scheduler")
                .and_then(|_| {
                    // Cleanup closes inherited descriptors, but the startup socket must
                    // survive so initialization failures can still reach the launcher.
                    daemonize_cleanup(&[fd])?;
                    notifier.watch_launcher(STARTUP_TIMEOUT)?;
                    initialize(&mut notifier)
                });
            if let Err(error) = &result {
                let _ = notifier.send(StartupStatus::Error(
                    error.chain().map(ToString::to_string).collect(),
                ));
            }
            result.map(|never| match never {})
        }
    }
}

/// Bounds the launcher's wait and validates the complete readiness exchange, rather
/// than treating a successful fork or a closed startup socket as successful startup.
fn wait_for_startup(mut stream: UnixStream, timeout: Duration) -> Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut message = Vec::new();
    // Read one extra byte to detect oversized messages without unbounded allocation.
    if let Err(error) =
        BufReader::new((&mut stream).take(MAX_RESPONSE_SIZE + 1)).read_until(b'\n', &mut message)
    {
        let context = if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            "timed out waiting for scheduler startup"
        } else {
            "failed to receive scheduler startup status"
        };
        return Err(error).context(context);
    }
    if message.is_empty() {
        bail!("scheduler exited before reporting startup status");
    }
    if message.len() as u64 > MAX_RESPONSE_SIZE {
        bail!("scheduler startup response exceeds size limit");
    }
    match serde_json::from_slice(&message).context("invalid scheduler startup response")? {
        StartupStatus::Ready { pid } => {
            debug!("Scheduler daemon ready (pid {pid})");
            stream
                .write_all(&[STARTUP_ACK])
                .context("failed to acknowledge scheduler startup")?;
            // Do not return until the watchdog has accepted the ACK; otherwise it
            // could still terminate a daemon whose launcher already reported success.
            let mut confirmation = [0];
            stream
                .read_exact(&mut confirmation)
                .context("scheduler exited before confirming startup")?;
            if confirmation[0] != STARTUP_ACK {
                bail!("invalid scheduler startup confirmation");
            }
            Ok(())
        }
        StartupStatus::Error(messages) => {
            // Rebuild from the root cause outward to retain the original chain order.
            let mut messages = messages.into_iter().rev();
            let mut error = anyhow!(messages.next().context("empty scheduler startup error")?);
            for message in messages {
                error = error.context(message);
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process::{Command, Output, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;
    use tokio::runtime::Runtime;

    fn run_test_subprocess(command: &mut Command) -> Output {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("test subprocess timed out: {output:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    }

    #[test]
    fn startup_rejects_sockets_on_standard_descriptors() {
        const CHILD_ENV: &str = "SCCACHE_TEST_CLOSED_STDIN";
        if env::var_os(CHILD_ENV).is_some() {
            // SAFETY: only this isolated test subprocess closes fd 0, after Rust
            // startup has initialized it; nothing subsequently uses it as stdin.
            assert_eq!(unsafe { libc::close(libc::STDIN_FILENO) }, 0);
            let error = run(|_| panic!("initialization must not be reached")).unwrap_err();
            assert_eq!(
                error.to_string(),
                "startup sockets must not occupy standard file descriptors"
            );
            return;
        }
        let output = run_test_subprocess(
            Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "startup::tests::startup_rejects_sockets_on_standard_descriptors",
                ])
                .env(CHILD_ENV, "1")
                .env("SCCACHE_NO_DAEMON", "0"),
        );
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn foreground_startup_runs_cleanup() {
        use std::os::fd::IntoRawFd;

        const CHILD_ENV: &str = "SCCACHE_TEST_FOREGROUND_STARTUP";
        if std::env::var_os(CHILD_ENV).is_some() {
            // Transfer ownership because startup must close this FD before initialization.
            let fd = tempfile::tempfile().unwrap().into_raw_fd();
            assert_ne!(
                unsafe { libc::signal(libc::SIGILL, libc::SIG_IGN) },
                libc::SIG_ERR
            );
            let error = run(|notifier| {
                notifier.ready()?;
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
                let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGILL, std::ptr::null(), &mut action) },
                    0
                );
                assert_ne!(action.sa_sigaction, libc::SIG_IGN);
                assert_ne!(action.sa_sigaction, libc::SIG_DFL);
                Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into())
            })
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::Interrupted
            );
            return;
        }

        // FD cleanup and signal changes must not affect the test runner itself.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "startup::tests::foreground_startup_runs_cleanup"])
            .env(CHILD_ENV, "1")
            .env("SCCACHE_NO_DAEMON", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn ready_reports_success() {
        let (launcher, daemon) = UnixStream::pair().unwrap();
        let mut acknowledgment = daemon.try_clone().unwrap();
        acknowledgment
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let watchdog = std::thread::spawn(move || {
            let mut ack = [0];
            acknowledgment.read_exact(&mut ack).unwrap();
            assert_eq!(ack, [STARTUP_ACK]);
            acknowledgment.write_all(&[STARTUP_ACK]).unwrap();
        });
        StartupNotifier {
            stream: Some(daemon),
        }
        .ready()
        .unwrap();
        wait_for_startup(launcher, Duration::from_secs(1)).unwrap();
        watchdog.join().unwrap();
    }

    #[test]
    fn readiness_requires_watchdog_confirmation() {
        for (confirmation, expected) in [
            (None, "scheduler exited before confirming startup"),
            (Some(0), "invalid scheduler startup confirmation"),
        ] {
            let (launcher, mut daemon) = UnixStream::pair().unwrap();
            daemon
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let peer = thread::spawn(move || {
                let mut message = serde_json::to_vec(&StartupStatus::Ready {
                    pid: std::process::id(),
                })
                .unwrap();
                message.push(b'\n');
                daemon.write_all(&message).unwrap();
                let mut ack = [0];
                daemon.read_exact(&mut ack).unwrap();
                assert_eq!(ack, [STARTUP_ACK]);
                if let Some(confirmation) = confirmation {
                    daemon.write_all(&[confirmation]).unwrap();
                }
            });
            let error = wait_for_startup(launcher, Duration::from_secs(1)).unwrap_err();
            assert_eq!(error.to_string(), expected, "{confirmation:?}");
            peer.join().unwrap();
        }
    }

    #[test]
    fn invalid_startup_responses_are_rejected() {
        let mut oversized = br#"{"Error":["failure"]}"#.to_vec();
        oversized.resize(MAX_RESPONSE_SIZE as usize + 1, b' ');
        for (case, message, expected) in [
            (
                "malformed JSON",
                b"not json\n".to_vec(),
                "invalid scheduler startup response",
            ),
            (
                "truncated JSON at EOF",
                br#"{"Ready":{"pid":1}"#.to_vec(),
                "invalid scheduler startup response",
            ),
            (
                "oversized valid JSON",
                oversized,
                "scheduler startup response exceeds size limit",
            ),
            (
                "empty error chain",
                b"{\"Error\":[]}\n".to_vec(),
                "empty scheduler startup error",
            ),
        ] {
            let (launcher, mut daemon) = UnixStream::pair().unwrap();
            daemon
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let peer = thread::spawn(move || daemon.write_all(&message).unwrap());
            let error = wait_for_startup(launcher, Duration::from_secs(1)).unwrap_err();
            assert_eq!(error.to_string(), expected, "{case}");
            peer.join().unwrap();
        }
    }

    #[test]
    fn startup_errors_preserve_their_chain() {
        let (launcher, daemon) = UnixStream::pair().unwrap();
        let error = anyhow!("root cause").context("startup failed");
        StartupNotifier {
            stream: Some(daemon),
        }
        .send(StartupStatus::Error(
            error.chain().map(ToString::to_string).collect(),
        ))
        .unwrap();
        let error = wait_for_startup(launcher, Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            error.chain().map(ToString::to_string).collect::<Vec<_>>(),
            ["startup failed", "root cause"]
        );
    }

    #[test]
    fn eof_before_readiness_is_an_error() {
        let (launcher, daemon) = UnixStream::pair().unwrap();
        drop(daemon);
        let error = wait_for_startup(launcher, Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "scheduler exited before reporting startup status"
        );
    }

    /// Encodes watchdog subprocess scenarios so unknown modes cannot silently act as timeouts.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum WatchdogMode {
        Disconnect,
        Timeout,
        Acknowledge,
    }

    #[test]
    fn watchdog_stops_abandoned_startup() {
        const CHILD_ENV: &str = "SCCACHE_TEST_STARTUP_WATCHDOG";
        if let Ok(mode) = std::env::var(CHILD_ENV) {
            let mode: WatchdogMode = serde_json::from_str(&mode).unwrap();
            let (launcher, daemon) = UnixStream::pair().unwrap();
            let notifier = StartupNotifier {
                stream: Some(daemon),
            };
            if matches!(mode, WatchdogMode::Acknowledge) {
                launcher
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                (&launcher).write_all(&[STARTUP_ACK]).unwrap();
                notifier.watch_launcher(Duration::from_millis(20)).unwrap();
                let mut confirmation = [0];
                (&launcher).read_exact(&mut confirmation).unwrap();
                assert_eq!(confirmation, [STARTUP_ACK]);
                drop(launcher);
                std::thread::sleep(Duration::from_millis(100));
                return;
            }
            let runtime = Runtime::new().unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            runtime.spawn_blocking(move || {
                started_tx.send(()).unwrap();
                thread::sleep(Duration::from_secs(2));
            });
            started_rx.recv().unwrap();
            notifier.watch_launcher(Duration::from_millis(20)).unwrap();
            if matches!(mode, WatchdogMode::Disconnect) {
                drop(launcher);
            }
            drop(runtime);
            panic!("startup watchdog did not terminate the daemon");
        }
        for mode in [
            WatchdogMode::Disconnect,
            WatchdogMode::Timeout,
            WatchdogMode::Acknowledge,
        ] {
            let output = run_test_subprocess(
                Command::new(env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "startup::tests::watchdog_stops_abandoned_startup",
                    ])
                    .env(CHILD_ENV, serde_json::to_string(&mode).unwrap()),
            );
            let expected = match mode {
                WatchdogMode::Acknowledge => 0,
                WatchdogMode::Disconnect | WatchdogMode::Timeout => 2,
            };
            assert_eq!(output.status.code(), Some(expected), "{mode:?}: {output:?}");
        }
    }

    #[test]
    fn missing_response_times_out() {
        let (launcher, _daemon) = UnixStream::pair().unwrap();
        let error = wait_for_startup(launcher, Duration::from_millis(20)).unwrap_err();
        assert_eq!(error.to_string(), "timed out waiting for scheduler startup");
    }
}
