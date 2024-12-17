use std::io;
use std::process::Command;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::StreamExt;

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
// simple fact of keeping them open can block it.
// So if it does give us those file descriptors, close the preemptively.
//
// unsafe because it can use the wrong fds.
#[cfg(not(windows))]
pub unsafe fn discard_inherited_jobserver() {
    if let Some(value) = ["CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"]
        .into_iter()
        .find_map(|env| std::env::var(env).ok())
    {
        if let Some(auth) = value.rsplit(' ').find_map(|arg| {
            arg.strip_prefix("--jobserver-auth=")
                .or_else(|| arg.strip_prefix("--jobserver-fds="))
        }) {
            if !auth.starts_with("fifo:") {
                let mut parts = auth.splitn(2, ',');
                let read = parts.next().unwrap();
                let write = match parts.next() {
                    Some(w) => w,
                    None => return,
                };
                let read = read.parse().unwrap();
                let write = write.parse().unwrap();
                if read < 0 || write < 0 {
                    return;
                }
                unsafe {
                    if libc::fcntl(read, libc::F_GETFD) == -1 {
                        return;
                    }
                    if libc::fcntl(write, libc::F_GETFD) == -1 {
                        return;
                    }
                    libc::close(read);
                    libc::close(write);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Client {
    helper: Option<Arc<jobserver::HelperThread>>,
    tx: Option<mpsc::UnboundedSender<oneshot::Sender<io::Result<jobserver::Acquired>>>>,
    inner: jobserver::Client,
}

pub struct Acquired {
    _token: Option<jobserver::Acquired>,
}

impl Client {
    pub fn new() -> Client {
        Client::new_num(num_cpus::get())
    }

    pub fn new_num(num: usize) -> Client {
        let inner = jobserver::Client::new(num).expect("failed to create jobserver");
        Client::_new(inner, false)
    }

    fn _new(inner: jobserver::Client, inherited: bool) -> Client {
        let (helper, tx) = if inherited {
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

        Client { inner, helper, tx }
    }

    /// Configures this jobserver to be inherited by the specified command
    pub fn configure(&self, cmd: &mut Command) {
        self.inner.configure(cmd)
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
