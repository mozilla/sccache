use std::io;
use std::process::{Command, ExitStatus};
use std::sync::Arc;

use futures::StreamExt;
use futures::channel::mpsc;
use futures::channel::oneshot;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

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
    fifo: Option<jobserver::Client>,
    current: Option<Arc<watch::Sender<Arc<Pool>>>>,
    // Caps our children across pool replacements, while older pools drain.
    slots: Option<Arc<Semaphore>>,
    limit: usize,
}

struct Pool {
    // Close the sender before joining a helper waiting for a request.
    tx: mpsc::UnboundedSender<oneshot::Sender<io::Result<jobserver::Acquired>>>,
    helper: jobserver::HelperThread,
    inner: jobserver::Client,
}

pub struct Acquired {
    _token: Option<jobserver::Acquired>,
    pool: Option<Arc<Pool>>,
    client: Client,
    shared: bool,
    exited: bool,
    _slot: Option<OwnedSemaphorePermit>,
}

impl Pool {
    fn new(num: usize) -> Result<Pool> {
        let inner = jobserver::Client::new(num).context("failed to create jobserver")?;
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
            .context("failed to spawn jobserver helper thread")?;
        Ok(Pool { tx, helper, inner })
    }
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
        Some(Client {
            fifo: Some(inner),
            current: None,
            slots: None,
            limit: 0,
        })
    }

    pub fn new_num(num: usize) -> Client {
        let pool = Pool::new(num).expect("failed to create jobserver");
        Client {
            fifo: None,
            current: Some(Arc::new(watch::Sender::new(Arc::new(pool)))),
            slots: Some(Arc::new(Semaphore::new(num))),
            limit: num,
        }
    }

    /// Whether this is the build's own jobserver, opened by path (see
    /// [`Client::from_env_fifo`]), rather than a private pool.
    pub fn is_fifo(&self) -> bool {
        self.fifo.is_some()
    }

    /// Returns a future that represents an acquired jobserver token.
    ///
    /// This should be invoked before any "work" is spawned (for whatever the
    /// definition of "work" is) to ensure that the system is properly
    /// rate-limiting itself.
    pub async fn acquire(&self) -> Result<Acquired> {
        let (Some(current), Some(slots)) = (&self.current, &self.slots) else {
            return Ok(Acquired {
                _token: None,
                pool: None,
                client: self.clone(),
                shared: false,
                exited: false,
                _slot: None,
            });
        };
        let slot = slots
            .clone()
            .acquire_owned()
            .await
            .context("jobserver slots closed")?;
        let mut current = current.subscribe();
        loop {
            let pool = current.borrow_and_update().clone();
            let (mytx, myrx) = oneshot::channel();
            pool.tx.unbounded_send(mytx).unwrap();
            pool.helper.request_token();
            tokio::select! {
                acquired = myrx => {
                    let acquired = acquired
                        .context("jobserver helper panicked")?
                        .context("failed to acquire jobserver token")?;
                    if !Arc::ptr_eq(&pool, &current.borrow()) {
                        continue;
                    }
                    return Ok(Acquired {
                        _token: Some(acquired),
                        pool: Some(pool),
                        client: self.clone(),
                        shared: false,
                        exited: false,
                        _slot: Some(slot),
                    });
                }
                // A retired pool may never get another token.
                _ = current.changed() => {}
            }
        }
    }

    fn retire(&self, pool: &Arc<Pool>) {
        if let Some(current) = &self.current {
            current.send_if_modified(|current| {
                if !Arc::ptr_eq(current, pool) {
                    return false;
                }
                match Pool::new(self.limit) {
                    Ok(fresh) => {
                        warn!("A compiler sharing the jobserver did not exit on its own; using a fresh token pool");
                        *current = Arc::new(fresh);
                        true
                    }
                    Err(e) => {
                        warn!("Keeping a jobserver that may have lost tokens: {e:?}");
                        false
                    }
                }
            });
        }
    }
}

impl Acquired {
    pub fn configure(&mut self, cmd: &mut Command) {
        if let Some(pool) = &self.pool {
            self.shared = true;
            pool.inner.configure(cmd);
        } else if let Some(fifo) = &self.client.fifo {
            fifo.configure(cmd);
        }
    }

    pub fn exited(&mut self, status: Option<&ExitStatus>) {
        #[cfg(unix)]
        let on_its_own =
            status.is_some_and(|s| std::os::unix::process::ExitStatusExt::signal(s).is_none());
        #[cfg(not(unix))]
        let on_its_own = status.is_some();
        self.exited = on_its_own;
    }
}

impl Drop for Acquired {
    fn drop(&mut self) {
        // A killed compiler may have taken tokens directly from the pipe.
        if self.shared
            && !self.exited
            && let Some(pool) = &self.pool
        {
            self.client.retire(pool);
        }
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
