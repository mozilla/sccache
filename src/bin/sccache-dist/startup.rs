use anyhow::{Context, Result, anyhow, bail};
use daemonix::Outcome;
use sccache::util::{daemonize, daemonize_cleanup, daemonize_with_parent};
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
    Error(Vec<String>),
}

pub struct StartupNotifier {
    stream: Option<UnixStream>,
}

impl StartupNotifier {
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

    pub fn ready(&mut self) -> Result<()> {
        self.send(StartupStatus::Ready {
            pid: std::process::id(),
        })
    }

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

pub fn run(initialize: impl FnOnce(&mut StartupNotifier) -> Result<Infallible>) -> Result<i32> {
    if std::env::var("SCCACHE_NO_DAEMON").as_deref() == Ok("1") {
        daemonize(&[])?;
        return initialize(&mut StartupNotifier { stream: None }).map(|never| match never {});
    }

    let (launcher, daemon) = UnixStream::pair().context("failed to create startup channel")?;
    match daemonize_with_parent() {
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

fn wait_for_startup(mut stream: UnixStream, timeout: Duration) -> Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut message = Vec::new();
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
        let (launcher, mut daemon) = UnixStream::pair().unwrap();
        daemon
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let peer = std::thread::spawn(move || {
            let mut message = serde_json::to_vec(&StartupStatus::Ready {
                pid: std::process::id(),
            })
            .unwrap();
            message.push(b'\n');
            daemon.write_all(&message).unwrap();
            let mut ack = [0];
            daemon.read_exact(&mut ack).unwrap();
            assert_eq!(ack, [STARTUP_ACK]);
        });
        let error = wait_for_startup(launcher, Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "scheduler exited before confirming startup"
        );
        peer.join().unwrap();
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
            StartupNotifier {
                stream: Some(daemon),
            }
            .watch_launcher(Duration::from_millis(20))
            .unwrap();
            match mode {
                WatchdogMode::Acknowledge => {
                    (&launcher).write_all(&[STARTUP_ACK]).unwrap();
                    let mut confirmation = [0];
                    (&launcher).read_exact(&mut confirmation).unwrap();
                    assert_eq!(confirmation, [STARTUP_ACK]);
                    drop(launcher);
                    std::thread::sleep(Duration::from_millis(100));
                    return;
                }
                WatchdogMode::Disconnect => drop(launcher),
                WatchdogMode::Timeout => (),
            }
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.spawn_blocking(|| std::thread::sleep(Duration::from_secs(2)));
            drop(runtime);
            panic!("startup watchdog did not terminate the daemon");
        }
        for mode in [
            WatchdogMode::Disconnect,
            WatchdogMode::Timeout,
            WatchdogMode::Acknowledge,
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "startup::tests::watchdog_stops_abandoned_startup",
                ])
                .env(CHILD_ENV, serde_json::to_string(&mode).unwrap())
                .output()
                .unwrap();
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
