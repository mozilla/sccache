use std::io;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::StreamExt;

use crate::errors::*;

#[derive(Clone)]
pub struct Client {
    helper: Option<Arc<jobslot::HelperThread>>,
    tx: Option<mpsc::UnboundedSender<oneshot::Sender<io::Result<jobslot::Acquired>>>>,
    inner: jobslot::Client,
}

pub struct Acquired {
    _token: Option<jobslot::Acquired>,
}

impl Client {
    // unsafe because `from_env` is unsafe (can use the wrong fds)
    pub unsafe fn new() -> Client {
        match jobslot::Client::from_env() {
            Some(c) => Client::_new(c, true),
            None => Client::new_num(num_cpus::get()),
        }
    }

    pub fn new_num(num: usize) -> Client {
        let inner = jobslot::Client::new(num).expect("failed to create jobserver");
        Client::_new(inner, false)
    }

    fn _new(inner: jobslot::Client, inherited: bool) -> Client {
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
    pub fn configure_and_run<Cmd, F, T>(&self, cmd: Cmd, f: F) -> io::Result<T>
    where
        // Cmd can be {std, tokio}::process::Command or
        // alias of them.
        Cmd: jobslot::Command,
        F: FnOnce(&mut Cmd) -> io::Result<T>,
    {
        self.inner.configure_make_and_run(cmd, f)
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
