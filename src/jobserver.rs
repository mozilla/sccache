use std::io;
use std::process::Command;
use std::sync::Arc;

use futures::future;
use futures::prelude::*;
use futures::sync::mpsc;
use futures::sync::oneshot;

use crate::errors::*;

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
    // unsafe because `from_env` is unsafe (can use the wrong fds)
    pub unsafe fn new() -> Client {
        match jobserver::Client::from_env() {
            Some(c) => Client::_new(c, true),
            None => Client::new_num(num_cpus::get()),
        }
    }

    pub fn new_num(num: usize) -> Client {
        let inner = jobserver::Client::new(num).expect("failed to create jobserver");
        Client::_new(inner, false)
    }

    fn _new(inner: jobserver::Client, inherited: bool) -> Client {
        let (helper, tx) = if inherited {
            (None, None)
        } else {
            let (tx, rx) = mpsc::unbounded::<oneshot::Sender<_>>();
            let mut rx = rx.wait();
            let helper = inner
                .clone()
                .into_helper_thread(move |token| {
                    if let Some(Ok(sender)) = rx.next() {
                        drop(sender.send(token));
                    }
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
    pub fn acquire(&self) -> SFuture<Acquired> {
        let (helper, tx) = match (self.helper.as_ref(), self.tx.as_ref()) {
            (Some(a), Some(b)) => (a, b),
            _ => return Box::new(future::ok(Acquired { _token: None })),
        };
        let (mytx, myrx) = oneshot::channel();
        helper.request_token();
        tx.unbounded_send(mytx).unwrap();
        Box::new(
            myrx.chain_err(|| "jobserver helper panicked")
                .and_then(|t| t.chain_err(|| "failed to acquire jobserver token"))
                .map(|t| Acquired { _token: Some(t) }),
        )
    }
}
