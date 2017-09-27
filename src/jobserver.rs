extern crate jobserver;

use std::io;
use std::process::Command;
use std::sync::Arc;

use futures::prelude::*;
use futures::sync::mpsc;
use futures::sync::oneshot;
use num_cpus;

use errors::*;

pub use self::jobserver::Acquired;

#[derive(Clone)]
pub struct Client {
    helper: Arc<jobserver::HelperThread>,
    inner: jobserver::Client,
    tx: mpsc::UnboundedSender<oneshot::Sender<io::Result<Acquired>>>
}

impl Client {
    // unsafe because `from_env` is unsafe (can use the wrong fds)
    pub unsafe fn new() -> Client {
        match jobserver::Client::from_env() {
            Some(c) => Client::_new(c),
            None => Client::new_num(num_cpus::get()),
        }
    }

    pub fn new_num(num: usize) -> Client {
        let inner = jobserver::Client::new(num)
                .expect("failed to create jobserver");
        Client::_new(inner)
    }

    fn _new(inner: jobserver::Client) -> Client {
        let (tx, rx) = mpsc::unbounded::<oneshot::Sender<_>>();
        let mut rx = rx.wait();
        let helper = inner.clone().into_helper_thread(move |token| {
            if let Some(Ok(sender)) = rx.next() {
                drop(sender.send(token));
            }
        }).expect("failed to spawn helper thread");

        Client {
            inner: inner,
            helper: Arc::new(helper),
            tx: tx,
        }
    }

    /// Configures this jobserver to be inherited by the specified command
    pub fn configure(&self, cmd: &mut Command) {
        self.inner.configure(cmd)
    }

    /// Returns a future that represents an acquired jobserver token.
    ///
    /// This should be invoked before any "work" is spawend (for whatever the
    /// defnition of "work" is) to ensure that the system is properly
    /// rate-limiting itself.
    pub fn acquire(&self) -> SFuture<Acquired> {
        let (tx, rx) = oneshot::channel();
        self.helper.request_token();
        self.tx.unbounded_send(tx).unwrap();
        Box::new(rx.chain_err(|| "jobserver helper panicked")
                   .and_then(|t| t.chain_err(|| "failed to acquire jobserver token")))
    }
}
