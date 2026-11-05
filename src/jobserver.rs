use std::io;
use std::process::Command;
use std::sync::Arc;

use futures::StreamExt;
use futures::channel::mpsc;
use futures::channel::oneshot;

use crate::errors::*;

// The execution model of sccache is that on the first run it spawns a server
// in the background and detaches it.
// When normally executing the rust compiler from either cargo or make, it
// will use cargo/make's jobserver and limit its resource usage accordingly.
// When executing the rust compiler through the sccache server, that jobserver
// is not available, and spawning as many rustc as there are CPUs can lead to
// a quadratic use of the CPU resources (each rustc spawning as many threads
// as there are CPUs).
// One way around this issue is to inherit the jobserver from cargo or make
// when the sccache server is spawned, but that means that in some cases, the
// cargo or make process can't terminate until the sccache server terminates
// after its idle timeout (which also never happens if SCCACHE_IDLE_TIMEOUT=0).
// Also, if the sccache server ends up shared between multiple runs of
// cargo/make, then which jobserver is used doesn't make sense anymore.
// Ideally, the sccache client would give a handle to the jobserver it has
// access to, so that the rust compiler would "just" use the jobserver it
// would have used if it had run without sccache, but that adds some extra
// complexity, and requires to use Unix domain sockets.
// What we do instead is to arbitrary use our own jobserver.
// Unfortunately, that doesn't absolve us from having to deal with the original
// jobserver, because make may give us file descriptors to its pipes, and the
// simple fact of keeping them open can block it. That is handled by closing
// every inherited descriptor when the server detaches; see
// `util::close_inherited_fds`.

#[derive(Clone)]
pub struct Client {
    helper: Option<Arc<jobserver::HelperThread>>,
    tx: Option<mpsc::UnboundedSender<oneshot::Sender<io::Result<jobserver::Acquired>>>>,
    inner: jobserver::Client,
    fifo: bool,
}

pub struct Acquired {
    _token: Option<jobserver::Acquired>,
}

impl Client {
    pub fn new() -> Client {
        Client::new_num(crate::util::num_cpus())
    }

    /// The jobserver of the build that ran us, if it is one opened by path
    /// (`--jobserver-auth=fifo:PATH`, GNU make 4.4 and later). The problems
    /// above are about inherited pipe descriptors; a path holds nothing of
    /// the build's open, so the client, which lives only as long as one
    /// compile, can use it and hand it on to what it runs. Whoever ran us
    /// already holds a token for this compile, so none is taken per spawn.
    pub fn from_env_fifo() -> Option<Client> {
        if !env_names_fifo() {
            return None;
        }
        // SAFETY: a `fifo:` jobserver is opened by path; no inherited file
        // descriptors are taken over.
        let inner = unsafe { jobserver::Client::from_env() }?;
        Some(Client::_new(inner, true))
    }

    pub fn new_num(num: usize) -> Client {
        let inner = jobserver::Client::new(num).expect("failed to create jobserver");
        Client::_new(inner, false)
    }

    fn _new(inner: jobserver::Client, fifo: bool) -> Client {
        let (helper, tx) = if fifo {
            (None, None)
        } else {
            let (tx, mut rx) = mpsc::unbounded::<oneshot::Sender<_>>();
            let helper = inner
                .clone()
                .into_helper_thread(move |token| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap();
                    rt.block_on(async {
                        if let Some(sender) = rx.next().await {
                            drop(sender.send(token));
                        }
                    });
                })
                .expect("failed to spawn helper thread");
            (Some(Arc::new(helper)), Some(tx))
        };

        Client {
            inner,
            helper,
            tx,
            fifo,
        }
    }

    /// Whether this is the build's own jobserver, opened by path (see
    /// [`Client::from_env_fifo`]), rather than a private pool.
    pub fn is_fifo(&self) -> bool {
        self.fifo
    }

    /// Configures this jobserver to be inherited by the specified command
    pub fn configure(&self, cmd: &mut Command) {
        self.inner.configure(cmd);
    }

    /// Returns a future that represents an acquired jobserver token.
    ///
    /// This should be invoked before any "work" is spawned (for whatever the
    /// definition of "work" is) to ensure that the system is properly
    /// rate-limiting itself.
    pub async fn acquire(&self) -> Result<Acquired> {
        let (helper, tx) = match (self.helper.as_ref(), self.tx.as_ref()) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(Acquired { _token: None }),
        };
        let (mytx, myrx) = oneshot::channel();
        helper.request_token();
        tx.unbounded_send(mytx).unwrap();

        let acquired = myrx
            .await
            .context("jobserver helper panicked")?
            .context("failed to acquire jobserver token")?;

        Ok(Acquired {
            _token: Some(acquired),
        })
    }
}

/// Whether the jobserver in our environment, as `jobserver::Client::from_env`
/// would pick it, is opened by path.
fn env_names_fifo() -> bool {
    ["CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"]
        .iter()
        .find_map(std::env::var_os)
        .is_some_and(|flags| flags.to_str().is_some_and(names_fifo))
}

fn names_fifo(flags: &str) -> bool {
    flags
        .split_ascii_whitespace()
        .any(|arg| arg.starts_with("--jobserver-auth=fifo:"))
}

#[cfg(test)]
mod test {
    use super::{Client, names_fifo};

    #[test]
    fn fifo_jobserver_flags() {
        assert!(names_fifo("-j8 --jobserver-auth=fifo:/tmp/GMfifo1234"));
        assert!(names_fifo(" -j --jobserver-auth=fifo:/dev/steve"));
        assert!(!names_fifo("-j8 --jobserver-fds=3,4 --jobserver-auth=3,4"));
        assert!(!names_fifo("-j8"));
        assert!(!names_fifo(""));
    }

    #[test]
    fn private_pool_is_not_fifo() {
        assert!(!Client::new_num(1).is_fifo());
    }
}
