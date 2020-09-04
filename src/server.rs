// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// For tokio_io::codec::length_delimited::Framed;
#![allow(deprecated)]

use crate::cache::{storage_from_config, Storage};
use crate::compiler::{
    get_compiler_info, CacheControl, CompileResult, Compiler, CompilerArguments, CompilerHasher,
    CompilerKind, CompilerProxy, DistType, MissType,
};
#[cfg(feature = "dist-client")]
use crate::config;
use crate::config::Config;
use crate::dist;
use crate::jobserver::Client;
use crate::mock_command::{CommandCreatorSync, ProcessCommandCreator};
use crate::protocol::{Compile, CompileFinished, CompileResponse, Request, Response};
use crate::util;
use anyhow::Context as _;
use filetime::FileTime;
use futures::sync::mpsc;
use futures::{future, stream, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use futures_03::compat::Compat;
use futures_03::executor::ThreadPool;
use number_prefix::{binary_prefix, Prefixed, Standalone};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::metadata;
use std::io::{self, Write};
#[cfg(feature = "dist-client")]
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{ExitStatus, Output};
use std::rc::Rc;
use std::sync::Arc;
#[cfg(feature = "dist-client")]
use std::sync::Mutex;
use std::task::{Context, Waker};
use std::time::Duration;
use std::time::Instant;
use std::u64;
use tokio_compat::runtime::current_thread::Runtime;
use tokio_io::codec::length_delimited;
use tokio_io::codec::length_delimited::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_tcp::TcpListener;
use tokio_timer::{Delay, Timeout};
use tower::Service;

use crate::errors::*;

/// If the server is idle for this many seconds, shut down.
const DEFAULT_IDLE_TIMEOUT: u64 = 600;

/// If the dist client couldn't be created, retry creation at this number
/// of seconds from now (or later)
#[cfg(feature = "dist-client")]
const DIST_CLIENT_RECREATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of background server startup.
#[derive(Debug, Serialize, Deserialize)]
pub enum ServerStartup {
    /// Server started successfully on `port`.
    Ok { port: u16 },
    /// Server Addr already in suse
    AddrInUse,
    /// Timed out waiting for server startup.
    TimedOut,
    /// Server encountered an error.
    Err { reason: String },
}

/// Get the time the server should idle for before shutting down.
fn get_idle_timeout() -> u64 {
    // A value of 0 disables idle shutdown entirely.
    env::var("SCCACHE_IDLE_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_IDLE_TIMEOUT)
}

fn notify_server_startup_internal<W: Write>(mut w: W, status: ServerStartup) -> Result<()> {
    util::write_length_prefixed_bincode(&mut w, status)
}

#[cfg(unix)]
fn notify_server_startup(name: &Option<OsString>, status: ServerStartup) -> Result<()> {
    use std::os::unix::net::UnixStream;
    let name = match *name {
        Some(ref s) => s,
        None => return Ok(()),
    };
    debug!("notify_server_startup({:?})", status);
    let stream = UnixStream::connect(name)?;
    notify_server_startup_internal(stream, status)
}

#[cfg(windows)]
fn notify_server_startup(name: &Option<OsString>, status: ServerStartup) -> Result<()> {
    use std::fs::OpenOptions;

    let name = match *name {
        Some(ref s) => s,
        None => return Ok(()),
    };
    let pipe = OpenOptions::new().write(true).read(true).open(name)?;
    notify_server_startup_internal(pipe, status)
}

#[cfg(unix)]
fn get_signal(status: ExitStatus) -> i32 {
    use std::os::unix::prelude::*;
    status.signal().expect("must have signal")
}
#[cfg(windows)]
fn get_signal(_status: ExitStatus) -> i32 {
    panic!("no signals on windows")
}

pub struct DistClientContainer {
    // The actual dist client state
    #[cfg(feature = "dist-client")]
    state: Mutex<DistClientState>,
}

#[cfg(feature = "dist-client")]
struct DistClientConfig {
    // Reusable items tied to an SccacheServer instance
    pool: ThreadPool,

    // From the static dist configuration
    scheduler_url: Option<config::HTTPUrl>,
    auth: config::DistAuth,
    cache_dir: PathBuf,
    toolchain_cache_size: u64,
    toolchains: Vec<config::DistToolchainConfig>,
    rewrite_includes_only: bool,
}

#[cfg(feature = "dist-client")]
enum DistClientState {
    #[cfg(feature = "dist-client")]
    Some(Box<DistClientConfig>, Arc<dyn dist::Client>),
    #[cfg(feature = "dist-client")]
    FailWithMessage(Box<DistClientConfig>, String),
    #[cfg(feature = "dist-client")]
    RetryCreateAt(Box<DistClientConfig>, Instant),
    Disabled,
}

#[cfg(not(feature = "dist-client"))]
impl DistClientContainer {
    #[cfg(not(feature = "dist-client"))]
    fn new(config: &Config, _: &ThreadPool) -> Self {
        if config.dist.scheduler_url.is_some() {
            warn!("Scheduler address configured but dist feature disabled, disabling distributed sccache")
        }
        Self {}
    }

    pub fn new_disabled() -> Self {
        Self {}
    }

    pub fn reset_state(&self) {}

    pub fn get_status(&self) -> DistInfo {
        DistInfo::Disabled("dist-client feature not selected".to_string())
    }

    fn get_client(&self) -> Result<Option<Arc<dyn dist::Client>>> {
        Ok(None)
    }
}

#[cfg(feature = "dist-client")]
impl DistClientContainer {
    fn new(config: &Config, pool: &ThreadPool) -> Self {
        let config = DistClientConfig {
            pool: pool.clone(),
            scheduler_url: config.dist.scheduler_url.clone(),
            auth: config.dist.auth.clone(),
            cache_dir: config.dist.cache_dir.clone(),
            toolchain_cache_size: config.dist.toolchain_cache_size,
            toolchains: config.dist.toolchains.clone(),
            rewrite_includes_only: config.dist.rewrite_includes_only,
        };
        let state = Self::create_state(config);
        Self {
            state: Mutex::new(state),
        }
    }

    pub fn new_disabled() -> Self {
        Self {
            state: Mutex::new(DistClientState::Disabled),
        }
    }

    pub fn reset_state(&self) {
        let mut guard = self.state.lock();
        let state = guard.as_mut().unwrap();
        let state: &mut DistClientState = &mut **state;
        match mem::replace(state, DistClientState::Disabled) {
            DistClientState::Some(cfg, _)
            | DistClientState::FailWithMessage(cfg, _)
            | DistClientState::RetryCreateAt(cfg, _) => {
                warn!("State reset. Will recreate");
                *state =
                    DistClientState::RetryCreateAt(cfg, Instant::now() - Duration::from_secs(1));
            }
            DistClientState::Disabled => (),
        }
    }

    pub fn get_status(&self) -> DistInfo {
        let mut guard = self.state.lock();
        let state = guard.as_mut().unwrap();
        let state: &mut DistClientState = &mut **state;
        match state {
            DistClientState::Disabled => DistInfo::Disabled("disabled".to_string()),
            DistClientState::FailWithMessage(cfg, _) => DistInfo::NotConnected(
                cfg.scheduler_url.clone(),
                "enabled, auth not configured".to_string(),
            ),
            DistClientState::RetryCreateAt(cfg, _) => DistInfo::NotConnected(
                cfg.scheduler_url.clone(),
                "enabled, not connected, will retry".to_string(),
            ),
            DistClientState::Some(cfg, client) => match client.do_get_status().wait() {
                Ok(res) => DistInfo::SchedulerStatus(cfg.scheduler_url.clone(), res),
                Err(_) => DistInfo::NotConnected(
                    cfg.scheduler_url.clone(),
                    "could not communicate with scheduler".to_string(),
                ),
            },
        }
    }

    fn get_client(&self) -> Result<Option<Arc<dyn dist::Client>>> {
        let mut guard = self.state.lock();
        let state = guard.as_mut().unwrap();
        let state: &mut DistClientState = &mut **state;
        Self::maybe_recreate_state(state);
        let res = match state {
            DistClientState::Some(_, dc) => Ok(Some(dc.clone())),
            DistClientState::Disabled | DistClientState::RetryCreateAt(_, _) => Ok(None),
            DistClientState::FailWithMessage(_, msg) => Err(anyhow!(msg.clone())),
        };
        if res.is_err() {
            let config = match mem::replace(state, DistClientState::Disabled) {
                DistClientState::FailWithMessage(config, _) => config,
                _ => unreachable!(),
            };
            // The client is most likely mis-configured, make sure we
            // re-create on our next attempt.
            *state =
                DistClientState::RetryCreateAt(config, Instant::now() - Duration::from_secs(1));
        }
        res
    }

    fn maybe_recreate_state(state: &mut DistClientState) {
        if let DistClientState::RetryCreateAt(_, instant) = *state {
            if instant > Instant::now() {
                return;
            }
            let config = match mem::replace(state, DistClientState::Disabled) {
                DistClientState::RetryCreateAt(config, _) => config,
                _ => unreachable!(),
            };
            info!("Attempting to recreate the dist client");
            *state = Self::create_state(*config)
        }
    }

    // Attempt to recreate the dist client
    fn create_state(config: DistClientConfig) -> DistClientState {
        macro_rules! try_or_retry_later {
            ($v:expr) => {{
                match $v {
                    Ok(v) => v,
                    Err(e) => {
                        // `{:?}` prints the full cause chain and backtrace.
                        error!("{:?}", e);
                        return DistClientState::RetryCreateAt(
                            Box::new(config),
                            Instant::now() + DIST_CLIENT_RECREATE_TIMEOUT,
                        );
                    }
                }
            }};
        }

        macro_rules! try_or_fail_with_message {
            ($v:expr) => {{
                match $v {
                    Ok(v) => v,
                    Err(e) => {
                        // `{:?}` prints the full cause chain and backtrace.
                        let errmsg = format!("{:?}", e);
                        error!("{}", errmsg);
                        return DistClientState::FailWithMessage(
                            Box::new(config),
                            errmsg.to_string(),
                        );
                    }
                }
            }};
        }
        match config.scheduler_url {
            Some(ref addr) => {
                let url = addr.to_url();
                info!("Enabling distributed sccache to {}", url);
                let auth_token = match &config.auth {
                    config::DistAuth::Token { token } => Ok(token.to_owned()),
                    config::DistAuth::Oauth2CodeGrantPKCE { auth_url, .. }
                    | config::DistAuth::Oauth2Implicit { auth_url, .. } => {
                        Self::get_cached_config_auth_token(auth_url)
                    }
                };
                let auth_token = try_or_fail_with_message!(auth_token
                    .context("could not load client auth token, run |sccache --dist-auth|"));
                let dist_client = dist::http::Client::new(
                    &config.pool,
                    url,
                    &config.cache_dir.join("client"),
                    config.toolchain_cache_size,
                    &config.toolchains,
                    auth_token,
                    config.rewrite_includes_only,
                );
                let dist_client =
                    try_or_retry_later!(dist_client.context("failure during dist client creation"));
                use crate::dist::Client;
                match dist_client.do_get_status().wait() {
                    Ok(res) => {
                        info!(
                            "Successfully created dist client with {:?} cores across {:?} servers",
                            res.num_cpus, res.num_servers
                        );
                        DistClientState::Some(Box::new(config), Arc::new(dist_client))
                    }
                    Err(_) => {
                        warn!("Scheduler address configured, but could not communicate with scheduler");
                        DistClientState::RetryCreateAt(
                            Box::new(config),
                            Instant::now() + DIST_CLIENT_RECREATE_TIMEOUT,
                        )
                    }
                }
            }
            None => {
                info!("No scheduler address configured, disabling distributed sccache");
                DistClientState::Disabled
            }
        }
    }

    fn get_cached_config_auth_token(auth_url: &str) -> Result<String> {
        let cached_config = config::CachedConfig::reload()?;
        cached_config
            .with(|c| c.dist.auth_tokens.get(auth_url).map(String::to_owned))
            .with_context(|| format!("token for url {} not present in cached config", auth_url))
    }
}

/// Start an sccache server, listening on `port`.
///
/// Spins an event loop handling client connections until a client
/// requests a shutdown.
pub fn start_server(config: &Config, port: u16) -> Result<()> {
    info!("start_server: port: {}", port);
    let client = unsafe { Client::new() };
    let runtime = Runtime::new()?;
    let pool = ThreadPool::builder()
        .pool_size(std::cmp::max(20, 2 * num_cpus::get()))
        .create()?;
    let dist_client = DistClientContainer::new(config, &pool);
    let storage = storage_from_config(config, &pool);
    let res = SccacheServer::<ProcessCommandCreator>::new(
        port,
        pool,
        runtime,
        client,
        dist_client,
        storage,
    );
    let notify = env::var_os("SCCACHE_STARTUP_NOTIFY");
    match res {
        Ok(srv) => {
            let port = srv.port();
            info!("server started, listening on port {}", port);
            notify_server_startup(&notify, ServerStartup::Ok { port })?;
            srv.run(future::empty::<(), ()>())?;
            Ok(())
        }
        Err(e) => {
            error!("failed to start server: {}", e);
            match e.downcast_ref::<io::Error>() {
                Some(io_err) if io::ErrorKind::AddrInUse == io_err.kind() => {
                    notify_server_startup(&notify, ServerStartup::AddrInUse)?;
                }
                _ => {
                    let reason = e.to_string();
                    notify_server_startup(&notify, ServerStartup::Err { reason })?;
                }
            };
            Err(e)
        }
    }
}

pub struct SccacheServer<C: CommandCreatorSync> {
    runtime: Runtime,
    listener: TcpListener,
    rx: mpsc::Receiver<ServerMessage>,
    timeout: Duration,
    service: SccacheService<C>,
    wait: WaitUntilZero,
}

impl<C: CommandCreatorSync> SccacheServer<C> {
    pub fn new(
        port: u16,
        pool: ThreadPool,
        runtime: Runtime,
        client: Client,
        dist_client: DistClientContainer,
        storage: Arc<dyn Storage>,
    ) -> Result<SccacheServer<C>> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
        let listener = TcpListener::bind(&SocketAddr::V4(addr))?;

        // Prepare the service which we'll use to service all incoming TCP
        // connections.
        let (tx, rx) = mpsc::channel(1);
        let (wait, info) = WaitUntilZero::new();
        let service = SccacheService::new(dist_client, storage, &client, pool, tx, info);

        Ok(SccacheServer {
            runtime,
            listener,
            rx,
            service,
            timeout: Duration::from_secs(get_idle_timeout()),
            wait,
        })
    }

    /// Configures how long this server will be idle before shutting down.
    #[allow(dead_code)]
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set the storage this server will use.
    #[allow(dead_code)]
    pub fn set_storage(&mut self, storage: Arc<dyn Storage>) {
        self.service.storage = storage;
    }

    /// Returns a reference to a thread pool to run work on
    #[allow(dead_code)]
    pub fn pool(&self) -> &ThreadPool {
        &self.service.pool
    }

    /// Returns a reference to the command creator this server will use
    #[allow(dead_code)]
    pub fn command_creator(&self) -> &C {
        &self.service.creator
    }

    /// Returns the port that this server is bound to
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    /// Runs this server to completion.
    ///
    /// If the `shutdown` future resolves then the server will be shut down,
    /// otherwise the server may naturally shut down if it becomes idle for too
    /// long anyway.
    pub fn run<F>(self, shutdown: F) -> io::Result<()>
    where
        F: Future,
    {
        self._run(Box::new(shutdown.then(|_| Ok(()))))
    }

    fn _run<'a>(self, shutdown: Box<dyn Future<Item = (), Error = ()> + 'a>) -> io::Result<()> {
        let SccacheServer {
            mut runtime,
            listener,
            rx,
            service,
            timeout,
            wait,
        } = self;

        // Create our "server future" which will simply handle all incoming
        // connections in separate tasks.
        let server = listener.incoming().for_each(move |socket| {
            trace!("incoming connection");
            tokio_compat::runtime::current_thread::TaskExecutor::current()
                .spawn_local(Box::new(service.clone().bind(socket).map_err(|err| {
                    error!("{}", err);
                })))
                .unwrap();
            Ok(())
        });

        // Right now there's a whole bunch of ways to shut down this server for
        // various purposes. These include:
        //
        // 1. The `shutdown` future above.
        // 2. An RPC indicating the server should shut down
        // 3. A period of inactivity (no requests serviced)
        //
        // These are all encapsulated wih the future that we're creating below.
        // The `ShutdownOrInactive` indicates the RPC or the period of
        // inactivity, and this is then select'd with the `shutdown` future
        // passed to this function.

        let shutdown = shutdown.map(|a| {
            info!("shutting down due to explicit signal");
            a
        });

        let mut futures = vec![
            Box::new(server) as Box<dyn Future<Item = _, Error = _>>,
            Box::new(
                shutdown
                    .map_err(|()| io::Error::new(io::ErrorKind::Other, "shutdown signal failed")),
            ),
        ];

        let shutdown_idle = ShutdownOrInactive {
            rx,
            timeout: if timeout != Duration::new(0, 0) {
                Some(Delay::new(Instant::now() + timeout))
            } else {
                None
            },
            timeout_dur: timeout,
        };
        futures.push(Box::new(shutdown_idle.map(|a| {
            info!("shutting down due to being idle or request");
            a
        })));

        let server = future::select_all(futures);
        runtime.block_on(server).map_err(|p| p.0)?;

        info!(
            "moving into the shutdown phase now, waiting at most 10 seconds \
             for all client requests to complete"
        );

        // Once our server has shut down either due to inactivity or a manual
        // request we still need to give a bit of time for all active
        // connections to finish. This `wait` future will resolve once all
        // instances of `SccacheService` have been dropped.
        //
        // Note that we cap the amount of time this can take, however, as we
        // don't want to wait *too* long.
        runtime
            .block_on(Timeout::new(Compat::new(wait), Duration::new(30, 0)))
            .map_err(|e| {
                if e.is_inner() {
                    e.into_inner().unwrap()
                } else {
                    io::Error::new(io::ErrorKind::Other, e)
                }
            })?;

        info!("ok, fully shutting down now");

        Ok(())
    }
}

type CompilerMap<C> = HashMap<PathBuf, Option<CompilerCacheEntry<C>>>;

/// entry of the compiler cache
struct CompilerCacheEntry<C: CommandCreatorSync> {
    /// compiler argument trait obj
    pub compiler: Box<dyn Compiler<C>>,
    /// modification time of the compilers executable file
    pub mtime: FileTime,
    /// distributed compilation extra info
    pub dist_info: Option<(PathBuf, FileTime)>,
}

impl<C> CompilerCacheEntry<C>
where
    C: CommandCreatorSync,
{
    fn new(
        compiler: Box<dyn Compiler<C>>,
        mtime: FileTime,
        dist_info: Option<(PathBuf, FileTime)>,
    ) -> Self {
        Self {
            compiler,
            mtime,
            dist_info,
        }
    }
}
/// Service implementation for sccache
#[derive(Clone)]
struct SccacheService<C: CommandCreatorSync> {
    /// Server statistics.
    stats: Rc<RefCell<ServerStats>>,

    /// Distributed sccache client
    dist_client: Rc<DistClientContainer>,

    /// Cache storage.
    storage: Arc<dyn Storage>,

    /// A cache of known compiler info.
    compilers: Rc<RefCell<CompilerMap<C>>>,

    /// map the cwd with compiler proxy path to a proxy resolver, which
    /// will dynamically resolve the input compiler for the current context
    /// (usually file or current working directory)
    /// the associated `FileTime` is the modification time of
    /// the compiler proxy, in order to track updates of the proxy itself
    compiler_proxies: Rc<RefCell<HashMap<PathBuf, (Box<dyn CompilerProxy<C>>, FileTime)>>>,

    /// Thread pool to execute work in
    pool: ThreadPool,

    /// An object for creating commands.
    ///
    /// This is mostly useful for unit testing, where we
    /// can mock this out.
    creator: C,

    /// Message channel used to learn about requests received by this server.
    ///
    /// Note that messages sent along this channel will keep the server alive
    /// (reset the idle timer) and this channel can also be used to shut down
    /// the entire server immediately via a message.
    tx: mpsc::Sender<ServerMessage>,

    /// Information tracking how many services (connected clients) are active.
    info: ActiveInfo,
}

type SccacheRequest = Message<Request, Body<()>>;
type SccacheResponse = Message<Response, Body<Response>>;

/// Messages sent from all services to the main event loop indicating activity.
///
/// Whenever a request is receive a `Request` message is sent which will reset
/// the idle shutdown timer, and otherwise a `Shutdown` message indicates that
/// a server shutdown was requested via an RPC.
pub enum ServerMessage {
    /// A message sent whenever a request is received.
    Request,
    /// Message sent whenever a shutdown request is received.
    Shutdown,
}

impl<C> Service<SccacheRequest> for SccacheService<C>
where
    C: CommandCreatorSync + 'static,
{
    type Response = SccacheResponse;
    type Error = Error;
    type Future = SFuture<Self::Response>;

    fn call(&mut self, req: SccacheRequest) -> Self::Future {
        trace!("handle_client");

        // Opportunistically let channel know that we've received a request. We
        // ignore failures here as well as backpressure as it's not imperative
        // that every message is received.
        drop(self.tx.clone().start_send(ServerMessage::Request));

        let res: SFuture<Response> = match req.into_inner() {
            Request::Compile(compile) => {
                debug!("handle_client: compile");
                self.stats.borrow_mut().compile_requests += 1;
                return self.handle_compile(compile);
            }
            Request::GetStats => {
                debug!("handle_client: get_stats");
                Box::new(self.get_info().map(|i| Response::Stats(Box::new(i))))
            }
            Request::DistStatus => {
                debug!("handle_client: dist_status");
                Box::new(self.get_dist_status().map(Response::DistStatus))
            }
            Request::ZeroStats => {
                debug!("handle_client: zero_stats");
                self.zero_stats();
                Box::new(self.get_info().map(|i| Response::Stats(Box::new(i))))
            }
            Request::Shutdown => {
                debug!("handle_client: shutdown");
                let future = self
                    .tx
                    .clone()
                    .send(ServerMessage::Shutdown)
                    .then(|_| Ok(()));
                let info_future = self.get_info();
                return Box::new(future.join(info_future).map(move |(_, info)| {
                    Message::WithoutBody(Response::ShuttingDown(Box::new(info)))
                }));
            }
        };

        Box::new(res.map(Message::WithoutBody))
    }

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        Ok(Async::Ready(()))
    }
}

impl<C> SccacheService<C>
where
    C: CommandCreatorSync,
{
    pub fn new(
        dist_client: DistClientContainer,
        storage: Arc<dyn Storage>,
        client: &Client,
        pool: ThreadPool,
        tx: mpsc::Sender<ServerMessage>,
        info: ActiveInfo,
    ) -> SccacheService<C> {
        SccacheService {
            stats: Rc::new(RefCell::new(ServerStats::default())),
            dist_client: Rc::new(dist_client),
            storage,
            compilers: Rc::new(RefCell::new(HashMap::new())),
            compiler_proxies: Rc::new(RefCell::new(HashMap::new())),
            pool,
            creator: C::new(client),
            tx,
            info,
        }
    }

    fn bind<T>(mut self, socket: T) -> impl Future<Item = (), Error = Error>
    where
        T: AsyncRead + AsyncWrite + 'static,
    {
        let mut builder = length_delimited::Builder::new();
        if let Ok(max_frame_length_str) = env::var("SCCACHE_MAX_FRAME_LENGTH") {
            if let Ok(max_frame_length) = max_frame_length_str.parse::<usize>() {
                builder.max_frame_length(max_frame_length);
            } else {
                warn!("Content of SCCACHE_MAX_FRAME_LENGTH is  not a valid number, using default");
            }
        }
        let io = builder.new_framed(socket);

        let (sink, stream) = SccacheTransport {
            inner: WriteBincode::new(ReadBincode::new(io)),
        }
        .split();
        let sink = sink.sink_from_err::<Error>();

        stream
            .from_err::<Error>()
            .and_then(move |input| self.call(input))
            .and_then(|message| {
                let f: Box<dyn Stream<Item = _, Error = _>> = match message {
                    Message::WithoutBody(message) => Box::new(stream::once(Ok(Frame::Message {
                        message,
                        body: false,
                    }))),
                    Message::WithBody(message, body) => Box::new(
                        stream::once(Ok(Frame::Message {
                            message,
                            body: true,
                        }))
                        .chain(Compat::new(body).map(|chunk| Frame::Body { chunk: Some(chunk) }))
                        .chain(stream::once(Ok(Frame::Body { chunk: None }))),
                    ),
                };
                Ok(f.from_err::<Error>())
            })
            .flatten()
            .forward(sink)
            .map(|_| ())
    }

    /// Get dist status.
    fn get_dist_status(&self) -> SFuture<DistInfo> {
        f_ok(self.dist_client.get_status())
    }

    /// Get info and stats about the cache.
    fn get_info(&self) -> SFuture<ServerInfo> {
        let stats = self.stats.borrow().clone();
        let cache_location = self.storage.location();
        Box::new(
            self.storage
                .current_size()
                .join(self.storage.max_size())
                .map(move |(cache_size, max_cache_size)| ServerInfo {
                    stats,
                    cache_location,
                    cache_size,
                    max_cache_size,
                }),
        )
    }

    /// Zero stats about the cache.
    fn zero_stats(&self) {
        *self.stats.borrow_mut() = ServerStats::default();
    }

    /// Handle a compile request from a client.
    ///
    /// This will handle a compile request entirely, generating a response with
    /// the inital information and an optional body which will eventually
    /// contain the results of the compilation.
    fn handle_compile(&self, compile: Compile) -> SFuture<SccacheResponse> {
        let exe = compile.exe;
        let cmd = compile.args;
        let cwd: PathBuf = compile.cwd.into();
        let env_vars = compile.env_vars;
        let me = self.clone();

        Box::new(
            self.compiler_info(exe.into(), cwd.clone(), &env_vars)
                .map(move |info| me.check_compiler(info, cmd, cwd, env_vars)),
        )
    }

    /// Look up compiler info from the cache for the compiler `path`.
    /// If not cached, determine the compiler type and cache the result.
    fn compiler_info(
        &self,
        path: PathBuf,
        cwd: PathBuf,
        env: &[(OsString, OsString)],
    ) -> SFuture<Result<Box<dyn Compiler<C>>>> {
        trace!("compiler_info");

        let me = self.clone();
        let me1 = self.clone();

        // lookup if compiler proxy exists for the current compiler path

        let path2 = path.clone();
        let path1 = path.clone();
        let env = env
            .into_iter()
            .cloned()
            .collect::<Vec<(OsString, OsString)>>();

        let resolve_w_proxy = {
            let compiler_proxies_borrow = self.compiler_proxies.borrow();

            if let Some((compiler_proxy, _filetime)) = compiler_proxies_borrow.get(&path) {
                let fut = compiler_proxy.resolve_proxied_executable(
                    self.creator.clone(),
                    cwd.clone(),
                    env.as_slice(),
                );
                Box::new(fut.then(|res: Result<_>| Ok(res.ok())))
            } else {
                f_ok(None)
            }
        };

        // use the supplied compiler path as fallback, lookup its modification time too
        let w_fallback = resolve_w_proxy.then(move |res: Result<Option<(PathBuf, FileTime)>>| {
            let opt = match res {
                Ok(Some(x)) => Some(x), // TODO resolve the path right away
                _ => {
                    // fallback to using the path directly
                    metadata(&path2)
                        .map(|attr| FileTime::from_last_modification_time(&attr))
                        .ok()
                        .map(move |filetime| (path2.clone(), filetime))
                }
            };
            f_ok(opt)
        });

        let lookup_compiler = w_fallback.and_then(move |opt: Option<(PathBuf, FileTime)>| {
            let (resolved_compiler_path, mtime) =
                opt.expect("Must contain sane data, otherwise mtime is not avail");

            let dist_info = match me1.dist_client.get_client() {
                Ok(Some(ref client)) => {
                    if let Some(archive) = client.get_custom_toolchain(&resolved_compiler_path) {
                        match metadata(&archive)
                            .map(|attr| FileTime::from_last_modification_time(&attr))
                        {
                            Ok(mtime) => Some((archive, mtime)),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };

            let opt = match me1.compilers.borrow().get(&resolved_compiler_path) {
                // It's a hit only if the mtime and dist archive data matches.
                Some(&Some(ref entry)) => {
                    if entry.mtime == mtime && entry.dist_info == dist_info {
                        Some(entry.compiler.clone())
                    } else {
                        None
                    }
                }
                _ => None,
            };
            f_ok((resolved_compiler_path, mtime, opt, dist_info))
        });

        let obtain = lookup_compiler.and_then(
            move |(resolved_compiler_path, mtime, opt, dist_info): (
                PathBuf,
                FileTime,
                Option<Box<dyn Compiler<C>>>,
                Option<(PathBuf, FileTime)>,
            )| {
                match opt {
                    Some(info) => {
                        trace!("compiler_info cache hit");
                        f_ok(Ok(info))
                    }
                    None => {
                        trace!("compiler_info cache miss");
                        // Check the compiler type and return the result when
                        // finished. This generally involves invoking the compiler,
                        // so do it asynchronously.

                        // the compiler path might be compiler proxy, so it is important to use
                        // `path` (or its clone `path1`) to resolve using that one, not using `resolved_compiler_path`
                        let x = get_compiler_info::<C>(
                            me.creator.clone(),
                            &path1,
                            &cwd,
                            env.as_slice(),
                            &me.pool,
                            dist_info.clone().map(|(p, _)| p),
                        );

                        Box::new(x.then(
                            move |info: Result<(
                                Box<dyn Compiler<C>>,
                                Option<Box<dyn CompilerProxy<C>>>,
                            )>| {
                                match info {
                                    Ok((ref c, ref proxy)) => {
                                        // register the proxy for this compiler, so it will be used directly from now on
                                        // and the true/resolved compiler will create table hits in the hash map
                                        // based on the resolved path
                                        if let Some(proxy) = proxy {
                                            trace!(
                                                "Inserting new path proxy {:?} @ {:?} -> {:?}",
                                                &path,
                                                &cwd,
                                                resolved_compiler_path
                                            );
                                            let proxy: Box<dyn CompilerProxy<C>> =
                                                proxy.box_clone();
                                            me.compiler_proxies
                                                .borrow_mut()
                                                .insert(path, (proxy, mtime.clone()));
                                        }
                                        // TODO add some safety checks in case a proxy exists, that the initial `path` is not
                                        // TODO the same as the resolved compiler binary

                                        // cache
                                        let map_info =
                                            CompilerCacheEntry::new(c.clone(), mtime, dist_info);
                                        trace!(
                                            "Inserting POSSIBLY PROXIED cache map info for {:?}",
                                            &resolved_compiler_path
                                        );
                                        me.compilers
                                            .borrow_mut()
                                            .insert(resolved_compiler_path, Some(map_info));
                                    }
                                    Err(_) => {
                                        trace!("Inserting PLAIN cache map info for {:?}", &path);
                                        me.compilers.borrow_mut().insert(path, None);
                                    }
                                }
                                // drop the proxy information, response is compiler only
                                let r: Result<Box<dyn Compiler<C>>> = info.map(|info| info.0);
                                f_ok(r)
                            },
                        ))
                    }
                }
            },
        );

        return Box::new(obtain);
    }

    /// Check that we can handle and cache `cmd` when run with `compiler`.
    /// If so, run `start_compile_task` to execute it.
    fn check_compiler(
        &self,
        compiler: Result<Box<dyn Compiler<C>>>,
        cmd: Vec<OsString>,
        cwd: PathBuf,
        env_vars: Vec<(OsString, OsString)>,
    ) -> SccacheResponse {
        let mut stats = self.stats.borrow_mut();
        match compiler {
            Err(e) => {
                debug!("check_compiler: Unsupported compiler: {}", e.to_string());
                stats.requests_unsupported_compiler += 1;
                return Message::WithoutBody(Response::Compile(
                    CompileResponse::UnsupportedCompiler(OsString::from(e.to_string())),
                ));
            }
            Ok(c) => {
                debug!("check_compiler: Supported compiler");
                // Now check that we can handle this compiler with
                // the provided commandline.
                match c.parse_arguments(&cmd, &cwd) {
                    CompilerArguments::Ok(hasher) => {
                        debug!("parse_arguments: Ok: {:?}", cmd);
                        stats.requests_executed += 1;
                        let (tx, rx) = Body::pair();
                        self.start_compile_task(c, hasher, cmd, cwd, env_vars, tx);
                        let res = CompileResponse::CompileStarted;
                        return Message::WithBody(Response::Compile(res), rx);
                    }
                    CompilerArguments::CannotCache(why, extra_info) => {
                        if let Some(extra_info) = extra_info {
                            debug!(
                                "parse_arguments: CannotCache({}, {}): {:?}",
                                why, extra_info, cmd
                            )
                        } else {
                            debug!("parse_arguments: CannotCache({}): {:?}", why, cmd)
                        }
                        stats.requests_not_cacheable += 1;
                        *stats.not_cached.entry(why.to_string()).or_insert(0) += 1;
                    }
                    CompilerArguments::NotCompilation => {
                        debug!("parse_arguments: NotCompilation: {:?}", cmd);
                        stats.requests_not_compile += 1;
                    }
                }
            }
        }

        let res = CompileResponse::UnhandledCompile;
        Message::WithoutBody(Response::Compile(res))
    }

    /// Given compiler arguments `arguments`, look up
    /// a compile result in the cache or execute the compilation and store
    /// the result in the cache.
    fn start_compile_task(
        &self,
        compiler: Box<dyn Compiler<C>>,
        hasher: Box<dyn CompilerHasher<C>>,
        arguments: Vec<OsString>,
        cwd: PathBuf,
        env_vars: Vec<(OsString, OsString)>,
        tx: mpsc::Sender<Result<Response>>,
    ) {
        let force_recache = env_vars
            .iter()
            .any(|&(ref k, ref _v)| k.as_os_str() == OsStr::new("SCCACHE_RECACHE"));
        let cache_control = if force_recache {
            CacheControl::ForceRecache
        } else {
            CacheControl::Default
        };
        let out_pretty = hasher.output_pretty().into_owned();
        let color_mode = hasher.color_mode();
        let result = hasher.get_cached_or_compile(
            self.dist_client.get_client(),
            self.creator.clone(),
            self.storage.clone(),
            arguments,
            cwd,
            env_vars,
            cache_control,
            self.pool.clone(),
        );
        let me = self.clone();
        let kind = compiler.kind();
        let task = result.then(move |result| {
            let mut cache_write = None;
            let mut stats = me.stats.borrow_mut();
            let mut res = CompileFinished::default();
            res.color_mode = color_mode;
            match result {
                Ok((compiled, out)) => {
                    match compiled {
                        CompileResult::Error => {
                            stats.cache_errors.increment(&kind);
                        }
                        CompileResult::CacheHit(duration) => {
                            stats.cache_hits.increment(&kind);
                            stats.cache_read_hit_duration += duration;
                        }
                        CompileResult::CacheMiss(miss_type, dist_type, duration, future) => {
                            match dist_type {
                                DistType::NoDist => {}
                                DistType::Ok(id) => {
                                    let server = id.addr().to_string();
                                    let server_count =
                                        stats.dist_compiles.entry(server).or_insert(0);
                                    *server_count += 1;
                                }
                                DistType::Error => stats.dist_errors += 1,
                            }
                            match miss_type {
                                MissType::Normal => {}
                                MissType::ForcedRecache => {
                                    stats.forced_recaches += 1;
                                }
                                MissType::TimedOut => {
                                    stats.cache_timeouts += 1;
                                }
                                MissType::CacheReadError => {
                                    stats.cache_errors.increment(&kind);
                                }
                            }
                            stats.cache_misses.increment(&kind);
                            stats.cache_read_miss_duration += duration;
                            cache_write = Some(future);
                        }
                        CompileResult::NotCacheable => {
                            stats.cache_misses.increment(&kind);
                            stats.non_cacheable_compilations += 1;
                        }
                        CompileResult::CompileFailed => {
                            stats.compile_fails += 1;
                        }
                    };
                    let Output {
                        status,
                        stdout,
                        stderr,
                    } = out;
                    trace!("CompileFinished retcode: {}", status);
                    match status.code() {
                        Some(code) => res.retcode = Some(code),
                        None => res.signal = Some(get_signal(status)),
                    };
                    res.stdout = stdout;
                    res.stderr = stderr;
                }
                Err(err) => {
                    match err.downcast::<ProcessError>() {
                        Ok(ProcessError(output)) => {
                            debug!("Compilation failed: {:?}", output);
                            stats.compile_fails += 1;
                            match output.status.code() {
                                Some(code) => res.retcode = Some(code),
                                None => res.signal = Some(get_signal(output.status)),
                            };
                            res.stdout = output.stdout;
                            res.stderr = output.stderr;
                        }
                        Err(err) => match err.downcast::<HttpClientError>() {
                            Ok(HttpClientError(msg)) => {
                                me.dist_client.reset_state();
                                let errmsg =
                                    format!("[{:?}] http error status: {}", out_pretty, msg);
                                error!("{}", errmsg);
                                res.retcode = Some(1);
                                res.stderr = errmsg.as_bytes().to_vec();
                            }
                            Err(err) => {
                                use std::fmt::Write;

                                error!("[{:?}] fatal error: {}", out_pretty, err);

                                let mut error = "sccache: encountered fatal error\n".to_string();
                                let _ = writeln!(error, "sccache: error: {}", err);
                                for e in err.chain() {
                                    error!("[{:?}] \t{}", out_pretty, e);
                                    let _ = writeln!(error, "sccache: caused by: {}", e);
                                }
                                stats.cache_errors.increment(&kind);
                                //TODO: figure out a better way to communicate this?
                                res.retcode = Some(-2);
                                res.stderr = error.into_bytes();
                            }
                        },
                    }
                }
            };
            let send = tx.send(Ok(Response::CompileFinished(res)));

            let me = me.clone();
            let cache_write = cache_write.then(move |result| {
                match result {
                    Err(e) => {
                        debug!("Error executing cache write: {}", e);
                        me.stats.borrow_mut().cache_write_errors += 1;
                    }
                    //TODO: save cache stats!
                    Ok(Some(info)) => {
                        debug!(
                            "[{}]: Cache write finished in {}",
                            info.object_file_pretty,
                            util::fmt_duration_as_secs(&info.duration)
                        );
                        me.stats.borrow_mut().cache_writes += 1;
                        me.stats.borrow_mut().cache_write_duration += info.duration;
                    }

                    Ok(None) => {}
                }
                Ok(())
            });

            send.join(cache_write).then(|_| Ok(()))
        });

        tokio_compat::runtime::current_thread::TaskExecutor::current()
            .spawn_local(Box::new(task))
            .unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PerLanguageCount {
    counts: HashMap<String, u64>,
}

impl PerLanguageCount {
    fn increment(&mut self, kind: &CompilerKind) {
        let key = kind.lang_kind();
        let count = self.counts.entry(key).or_insert(0);
        *count += 1;
    }

    pub fn all(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn get(&self, key: &str) -> Option<&u64> {
        self.counts.get(key)
    }

    pub fn new() -> PerLanguageCount {
        Self::default()
    }
}

/// Statistics about the server.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerStats {
    /// The count of client compile requests.
    pub compile_requests: u64,
    /// The count of client requests that used an unsupported compiler.
    pub requests_unsupported_compiler: u64,
    /// The count of client requests that were not compilation.
    pub requests_not_compile: u64,
    /// The count of client requests that were not cacheable.
    pub requests_not_cacheable: u64,
    /// The count of client requests that were executed.
    pub requests_executed: u64,
    /// The count of errors handling compile requests (per language).
    pub cache_errors: PerLanguageCount,
    /// The count of cache hits for handled compile requests (per language).
    pub cache_hits: PerLanguageCount,
    /// The count of cache misses for handled compile requests (per language).
    pub cache_misses: PerLanguageCount,
    /// The count of cache misses because the cache took too long to respond.
    pub cache_timeouts: u64,
    /// The count of errors reading cache entries.
    pub cache_read_errors: u64,
    /// The count of compilations which were successful but couldn't be cached.
    pub non_cacheable_compilations: u64,
    /// The count of compilations which forcibly ignored the cache.
    pub forced_recaches: u64,
    /// The count of errors writing to cache.
    pub cache_write_errors: u64,
    /// The number of successful cache writes.
    pub cache_writes: u64,
    /// The total time spent writing cache entries.
    pub cache_write_duration: Duration,
    /// The total time spent reading cache hits.
    pub cache_read_hit_duration: Duration,
    /// The total time spent reading cache misses.
    pub cache_read_miss_duration: Duration,
    /// The count of compilation failures.
    pub compile_fails: u64,
    /// Counts of reasons why compiles were not cached.
    pub not_cached: HashMap<String, usize>,
    /// The count of compilations that were successfully distributed indexed
    /// by the server that ran those compilations.
    pub dist_compiles: HashMap<String, usize>,
    /// The count of compilations that were distributed but failed and had to be re-run locally
    pub dist_errors: u64,
}

/// Info and stats about the server.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerInfo {
    pub stats: ServerStats,
    pub cache_location: String,
    pub cache_size: Option<u64>,
    pub max_cache_size: Option<u64>,
}

/// Status of the dist client.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DistInfo {
    Disabled(String),
    #[cfg(feature = "dist-client")]
    NotConnected(Option<config::HTTPUrl>, String),
    #[cfg(feature = "dist-client")]
    SchedulerStatus(Option<config::HTTPUrl>, dist::SchedulerStatusResult),
}

impl Default for ServerStats {
    fn default() -> ServerStats {
        ServerStats {
            compile_requests: u64::default(),
            requests_unsupported_compiler: u64::default(),
            requests_not_compile: u64::default(),
            requests_not_cacheable: u64::default(),
            requests_executed: u64::default(),
            cache_errors: PerLanguageCount::new(),
            cache_hits: PerLanguageCount::new(),
            cache_misses: PerLanguageCount::new(),
            cache_timeouts: u64::default(),
            cache_read_errors: u64::default(),
            non_cacheable_compilations: u64::default(),
            forced_recaches: u64::default(),
            cache_write_errors: u64::default(),
            cache_writes: u64::default(),
            cache_write_duration: Duration::new(0, 0),
            cache_read_hit_duration: Duration::new(0, 0),
            cache_read_miss_duration: Duration::new(0, 0),
            compile_fails: u64::default(),
            not_cached: HashMap::new(),
            dist_compiles: HashMap::new(),
            dist_errors: u64::default(),
        }
    }
}

impl ServerStats {
    /// Print stats to stdout in a human-readable format.
    ///
    /// Return the formatted width of each of the (name, value) columns.
    fn print(&self) -> (usize, usize) {
        macro_rules! set_stat {
            ($vec:ident, $var:expr, $name:expr) => {{
                // name, value, suffix length
                $vec.push(($name.to_string(), $var.to_string(), 0));
            }};
        }

        macro_rules! set_lang_stat {
            ($vec:ident, $var:expr, $name:expr) => {{
                $vec.push(($name.to_string(), $var.all().to_string(), 0));
                let mut sorted_stats: Vec<_> = $var.counts.iter().collect();
                sorted_stats.sort_by_key(|v| v.0);
                for (lang, count) in sorted_stats.iter() {
                    $vec.push((format!("{} ({})", $name, lang), count.to_string(), 0));
                }
            }};
        }

        macro_rules! set_duration_stat {
            ($vec:ident, $dur:expr, $num:expr, $name:expr) => {{
                let s = if $num > 0 {
                    $dur / $num as u32
                } else {
                    Default::default()
                };
                // name, value, suffix length
                $vec.push(($name.to_string(), util::fmt_duration_as_secs(&s), 2));
            }};
        }

        let mut stats_vec = vec![];
        //TODO: this would be nice to replace with a custom derive implementation.
        set_stat!(stats_vec, self.compile_requests, "Compile requests");
        set_stat!(
            stats_vec,
            self.requests_executed,
            "Compile requests executed"
        );
        set_lang_stat!(stats_vec, self.cache_hits, "Cache hits");
        set_lang_stat!(stats_vec, self.cache_misses, "Cache misses");
        set_stat!(stats_vec, self.cache_timeouts, "Cache timeouts");
        set_stat!(stats_vec, self.cache_read_errors, "Cache read errors");
        set_stat!(stats_vec, self.forced_recaches, "Forced recaches");
        set_stat!(stats_vec, self.cache_write_errors, "Cache write errors");
        set_stat!(stats_vec, self.compile_fails, "Compilation failures");
        set_lang_stat!(stats_vec, self.cache_errors, "Cache errors");
        set_stat!(
            stats_vec,
            self.non_cacheable_compilations,
            "Non-cacheable compilations"
        );
        set_stat!(
            stats_vec,
            self.requests_not_cacheable,
            "Non-cacheable calls"
        );
        set_stat!(
            stats_vec,
            self.requests_not_compile,
            "Non-compilation calls"
        );
        set_stat!(
            stats_vec,
            self.requests_unsupported_compiler,
            "Unsupported compiler calls"
        );
        set_duration_stat!(
            stats_vec,
            self.cache_write_duration,
            self.cache_writes,
            "Average cache write"
        );
        set_duration_stat!(
            stats_vec,
            self.cache_read_miss_duration,
            self.cache_misses.all(),
            "Average cache read miss"
        );
        set_duration_stat!(
            stats_vec,
            self.cache_read_hit_duration,
            self.cache_hits.all(),
            "Average cache read hit"
        );
        set_stat!(
            stats_vec,
            self.dist_errors,
            "Failed distributed compilations"
        );
        let name_width = stats_vec
            .iter()
            .map(|&(ref n, _, _)| n.len())
            .max()
            .unwrap();
        let stat_width = stats_vec
            .iter()
            .map(|&(_, ref s, _)| s.len())
            .max()
            .unwrap();
        for (name, stat, suffix_len) in stats_vec {
            println!(
                "{:<name_width$} {:>stat_width$}",
                name,
                stat,
                name_width = name_width,
                stat_width = stat_width + suffix_len
            );
        }
        if !self.dist_compiles.is_empty() {
            println!("\nSuccessful distributed compiles");
            let mut counts: Vec<_> = self.dist_compiles.iter().collect();
            counts.sort_by(|(_, c1), (_, c2)| c1.cmp(c2).reverse());
            for (reason, count) in counts {
                println!(
                    "  {:<name_width$} {:>stat_width$}",
                    reason,
                    count,
                    name_width = name_width - 2,
                    stat_width = stat_width
                );
            }
        }
        if !self.not_cached.is_empty() {
            println!("\nNon-cacheable reasons:");
            let mut counts: Vec<_> = self.not_cached.iter().collect();
            counts.sort_by(|(_, c1), (_, c2)| c1.cmp(c2).reverse());
            for (reason, count) in counts {
                println!(
                    "{:<name_width$} {:>stat_width$}",
                    reason,
                    count,
                    name_width = name_width,
                    stat_width = stat_width
                );
            }
            println!();
        }
        (name_width, stat_width)
    }
}

impl ServerInfo {
    /// Print info to stdout in a human-readable format.
    pub fn print(&self) {
        let (name_width, stat_width) = self.stats.print();
        println!(
            "{:<name_width$} {}",
            "Cache location",
            self.cache_location,
            name_width = name_width
        );
        for &(name, val) in &[
            ("Cache size", &self.cache_size),
            ("Max cache size", &self.max_cache_size),
        ] {
            if let Some(val) = *val {
                let (val, suffix) = match binary_prefix(val as f64) {
                    Standalone(bytes) => (bytes.to_string(), "bytes".to_string()),
                    Prefixed(prefix, n) => (format!("{:.0}", n), format!("{}B", prefix)),
                };
                println!(
                    "{:<name_width$} {:>stat_width$} {}",
                    name,
                    val,
                    suffix,
                    name_width = name_width,
                    stat_width = stat_width
                );
            }
        }
    }
}

enum Frame<R, R1> {
    Body { chunk: Option<R1> },
    Message { message: R, body: bool },
}

struct Body<R> {
    receiver: mpsc::Receiver<Result<R>>,
}

impl<R> Body<R> {
    fn pair() -> (mpsc::Sender<Result<R>>, Self) {
        let (tx, rx) = mpsc::channel(0);
        (tx, Body { receiver: rx })
    }
}

impl<R> futures_03::Stream for Body<R> {
    type Item = Result<R>;
    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match Pin::new(&mut self.receiver).poll().unwrap() {
            Async::Ready(item) => std::task::Poll::Ready(item),
            Async::NotReady => std::task::Poll::Pending,
        }
    }
}

enum Message<R, B> {
    WithBody(R, B),
    WithoutBody(R),
}

impl<R, B> Message<R, B> {
    fn into_inner(self) -> R {
        match self {
            Message::WithBody(r, _) => r,
            Message::WithoutBody(r) => r,
        }
    }
}

/// Implementation of `Stream + Sink` that tokio-proto is expecting
///
/// This type is composed of a few layers:
///
/// * First there's `I`, the I/O object implementing `AsyncRead` and
///   `AsyncWrite`
/// * Next that's framed using the `length_delimited` module in tokio-io giving
///   us a `Sink` and `Stream` of `BytesMut`.
/// * Next that sink/stream is wrapped in `ReadBincode` which will cause the
///   `Stream` implementation to switch from `BytesMut` to `Request` by parsing
///   the bytes  bincode.
/// * Finally that sink/stream is wrapped in `WriteBincode` which will cause the
///   `Sink` implementation to switch from `BytesMut` to `Response` meaning that
///   all `Response` types pushed in will be converted to `BytesMut` and pushed
///   below.
struct SccacheTransport<I: AsyncRead + AsyncWrite> {
    inner: WriteBincode<ReadBincode<Framed<I>, Request>, Response>,
}

impl<I: AsyncRead + AsyncWrite> Stream for SccacheTransport<I> {
    type Item = Message<Request, Body<()>>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        let msg = try_ready!(self.inner.poll().map_err(|e| {
            error!("SccacheTransport::poll failed: {}", e);
            io::Error::new(io::ErrorKind::Other, e)
        }));
        Ok(msg.map(Message::WithoutBody).into())
    }
}

impl<I: AsyncRead + AsyncWrite> Sink for SccacheTransport<I> {
    type SinkItem = Frame<Response, Response>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, io::Error> {
        match item {
            Frame::Message { message, body } => match self.inner.start_send(message)? {
                AsyncSink::Ready => Ok(AsyncSink::Ready),
                AsyncSink::NotReady(message) => {
                    Ok(AsyncSink::NotReady(Frame::Message { message, body }))
                }
            },
            Frame::Body { chunk: Some(chunk) } => match self.inner.start_send(chunk)? {
                AsyncSink::Ready => Ok(AsyncSink::Ready),
                AsyncSink::NotReady(chunk) => {
                    Ok(AsyncSink::NotReady(Frame::Body { chunk: Some(chunk) }))
                }
            },
            Frame::Body { chunk: None } => Ok(AsyncSink::Ready),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        self.inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        self.inner.close()
    }
}

struct ShutdownOrInactive {
    rx: mpsc::Receiver<ServerMessage>,
    timeout: Option<Delay>,
    timeout_dur: Duration,
}

impl Future for ShutdownOrInactive {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            match self.rx.poll().unwrap() {
                Async::NotReady => break,
                // Shutdown received!
                Async::Ready(Some(ServerMessage::Shutdown)) => return Ok(().into()),
                Async::Ready(Some(ServerMessage::Request)) => {
                    if self.timeout_dur != Duration::new(0, 0) {
                        self.timeout = Some(Delay::new(Instant::now() + self.timeout_dur));
                    }
                }
                // All services have shut down, in theory this isn't possible...
                Async::Ready(None) => return Ok(().into()),
            }
        }
        match self.timeout {
            None => Ok(Async::NotReady),
            Some(ref mut timeout) => timeout
                .poll()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}

/// Helper future which tracks the `ActiveInfo` below. This future will resolve
/// once all instances of `ActiveInfo` have been dropped.
struct WaitUntilZero {
    info: Rc<RefCell<Info>>,
}

struct ActiveInfo {
    info: Rc<RefCell<Info>>,
}

struct Info {
    active: usize,
    waker: Option<Waker>,
}

impl WaitUntilZero {
    fn new() -> (WaitUntilZero, ActiveInfo) {
        let info = Rc::new(RefCell::new(Info {
            active: 1,
            waker: None,
        }));

        (WaitUntilZero { info: info.clone() }, ActiveInfo { info })
    }
}

impl Clone for ActiveInfo {
    fn clone(&self) -> ActiveInfo {
        self.info.borrow_mut().active += 1;
        ActiveInfo {
            info: self.info.clone(),
        }
    }
}

impl Drop for ActiveInfo {
    fn drop(&mut self) {
        let mut info = self.info.borrow_mut();
        info.active -= 1;
        if info.active == 0 {
            if let Some(waker) = info.waker.take() {
                waker.wake();
            }
        }
    }
}

impl std::future::Future for WaitUntilZero {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let mut info = self.info.borrow_mut();
        if info.active == 0 {
            std::task::Poll::Ready(Ok(()))
        } else {
            info.waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    }
}
