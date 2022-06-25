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
#[cfg(feature = "dist-client")]
use anyhow::Context as _;
use bytes::{buf::BufMut, Bytes, BytesMut};
use filetime::FileTime;
use futures::channel::mpsc;
use futures::future::FutureExt;
use futures::{future, stream, Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use futures_locks::RwLock;
use number_prefix::NumberPrefix;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::metadata;
use std::future::Future;
use std::io::{self, Write};
use std::marker::Unpin;
#[cfg(feature = "dist-client")]
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{ExitStatus, Output};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
#[cfg(feature = "dist-client")]
use std::time::Instant;
use std::u64;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    runtime::Runtime,
    time::{self, sleep, Sleep},
};
use tokio_serde::Framed;
use tokio_util::codec::{length_delimited, LengthDelimitedCodec};
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
    state: futures::lock::Mutex<DistClientState>,
}

#[cfg(feature = "dist-client")]
struct DistClientConfig {
    // Reusable items tied to an SccacheServer instance
    pool: tokio::runtime::Handle,

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
    fn new(config: &Config, _: &tokio::runtime::Handle) -> Self {
        if config.dist.scheduler_url.is_some() {
            warn!("Scheduler address configured but dist feature disabled, disabling distributed sccache")
        }
        Self {}
    }

    pub fn new_disabled() -> Self {
        Self {}
    }

    pub async fn reset_state(&self) {}

    pub async fn get_status(&self) -> DistInfo {
        DistInfo::Disabled("dist-client feature not selected".to_string())
    }

    async fn get_client(&self) -> Result<Option<Arc<dyn dist::Client>>> {
        Ok(None)
    }
}

#[cfg(feature = "dist-client")]
impl DistClientContainer {
    fn new(config: &Config, pool: &tokio::runtime::Handle) -> Self {
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
        let state = pool.block_on(state);
        Self {
            state: futures::lock::Mutex::new(state),
        }
    }

    pub fn new_disabled() -> Self {
        Self {
            state: futures::lock::Mutex::new(DistClientState::Disabled),
        }
    }

    pub async fn reset_state(&self) {
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
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

    pub async fn get_status(&self) -> DistInfo {
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        let (client, scheduler_url) = match state {
            DistClientState::Disabled => return DistInfo::Disabled("disabled".to_string()),
            DistClientState::FailWithMessage(cfg, _) => {
                return DistInfo::NotConnected(
                    cfg.scheduler_url.clone(),
                    "enabled, auth not configured".to_string(),
                )
            }
            DistClientState::RetryCreateAt(cfg, _) => {
                return DistInfo::NotConnected(
                    cfg.scheduler_url.clone(),
                    "enabled, not connected, will retry".to_string(),
                )
            }
            DistClientState::Some(cfg, client) => (Arc::clone(client), cfg.scheduler_url.clone()),
        };

        match client.do_get_status().await {
            Ok(res) => DistInfo::SchedulerStatus(scheduler_url.clone(), res),
            Err(_) => DistInfo::NotConnected(
                scheduler_url.clone(),
                "could not communicate with scheduler".to_string(),
            ),
        }
    }

    async fn get_client(&self) -> Result<Option<Arc<dyn dist::Client>>> {
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        Self::maybe_recreate_state(state).await;
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

    async fn maybe_recreate_state(state: &mut DistClientState) {
        if let DistClientState::RetryCreateAt(_, instant) = *state {
            if instant > Instant::now() {
                return;
            }
            let config = match mem::replace(state, DistClientState::Disabled) {
                DistClientState::RetryCreateAt(config, _) => config,
                _ => unreachable!(),
            };
            info!("Attempting to recreate the dist client");
            *state = Self::create_state(*config).await
        }
    }

    // Attempt to recreate the dist client
    async fn create_state(config: DistClientConfig) -> DistClientState {
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
                match dist_client.do_get_status().await {
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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(std::cmp::max(20, 2 * num_cpus::get()))
        .build()?;
    let pool = runtime.handle().clone();
    let dist_client = DistClientContainer::new(config, &pool);
    let storage = storage_from_config(config, &pool);
    let res =
        SccacheServer::<ProcessCommandCreator>::new(port, runtime, client, dist_client, storage);
    let notify = env::var_os("SCCACHE_STARTUP_NOTIFY");
    match res {
        Ok(srv) => {
            let port = srv.port();
            info!("server started, listening on port {}", port);
            notify_server_startup(&notify, ServerStartup::Ok { port })?;
            srv.run(future::pending::<()>())?;
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
        runtime: Runtime,
        client: Client,
        dist_client: DistClientContainer,
        storage: Arc<dyn Storage>,
    ) -> Result<SccacheServer<C>> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
        let listener = runtime.block_on(TcpListener::bind(&SocketAddr::V4(addr)))?;

        Ok(Self::with_listener(
            listener,
            runtime,
            client,
            dist_client,
            storage,
        ))
    }

    pub fn with_listener(
        listener: TcpListener,
        runtime: Runtime,
        client: Client,
        dist_client: DistClientContainer,
        storage: Arc<dyn Storage>,
    ) -> SccacheServer<C> {
        // Prepare the service which we'll use to service all incoming TCP
        // connections.
        let (tx, rx) = mpsc::channel(1);
        let (wait, info) = WaitUntilZero::new();
        let pool = runtime.handle().clone();
        let service = SccacheService::new(dist_client, storage, &client, pool, tx, info);

        SccacheServer {
            runtime,
            listener,
            rx,
            service,
            timeout: Duration::from_secs(get_idle_timeout()),
            wait,
        }
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
    pub fn pool(&self) -> &tokio::runtime::Handle {
        &self.service.rt
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
        C: Send,
    {
        let SccacheServer {
            runtime,
            listener,
            rx,
            service,
            timeout,
            wait,
        } = self;

        // Create our "server future" which will simply handle all incoming
        // connections in separate tasks.
        let server = async move {
            loop {
                let (socket, _) = listener.accept().await?;
                trace!("incoming connection");
                let conn = service.clone().bind(socket).map_err(|res| {
                    error!("Failed to bind socket: {}", res);
                });

                // We're not interested if the task panicked; immediately process
                // another connection
                let _ = tokio::spawn(conn);
            }
        };

        // Right now there's a whole bunch of ways to shut down this server for
        // various purposes. These include:
        //
        // 1. The `shutdown` future above.
        // 2. An RPC indicating the server should shut down
        // 3. A period of inactivity (no requests serviced)
        //
        // These are all encapsulated with the future that we're creating below.
        // The `ShutdownOrInactive` indicates the RPC or the period of
        // inactivity, and this is then select'd with the `shutdown` future
        // passed to this function.

        let shutdown = shutdown.map(|_| {
            info!("shutting down due to explicit signal");
        });

        let shutdown_idle = async {
            ShutdownOrInactive {
                rx,
                timeout: if timeout != Duration::new(0, 0) {
                    Some(Box::pin(sleep(timeout)))
                } else {
                    None
                },
                timeout_dur: timeout,
            }
            .await;
            info!("shutting down due to being idle or request");
        };

        runtime.block_on(async {
            futures::select! {
                server = server.fuse() => server,
                _res = shutdown.fuse() => Ok(()),
                _res = shutdown_idle.fuse() => Ok::<_, io::Error>(()),
            }
        })?;

        const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
        info!(
            "moving into the shutdown phase now, waiting at most {} seconds \
             for all client requests to complete",
            SHUTDOWN_TIMEOUT.as_secs()
        );

        // Once our server has shut down either due to inactivity or a manual
        // request we still need to give a bit of time for all active
        // connections to finish. This `wait` future will resolve once all
        // instances of `SccacheService` have been dropped.
        //
        // Note that we cap the amount of time this can take, however, as we
        // don't want to wait *too* long.
        runtime.block_on(async { time::timeout(SHUTDOWN_TIMEOUT, wait).await })?;

        info!("ok, fully shutting down now");

        Ok(())
    }
}

/// Maps a compiler proxy path to a compiler proxy and it's last modification time
type CompilerProxyMap<C> = HashMap<PathBuf, (Box<dyn CompilerProxy<C>>, FileTime)>;
type CompilerMap<C> = HashMap<PathBuf, Option<CompilerCacheEntry<C>>>;

/// entry of the compiler cache
struct CompilerCacheEntry<C> {
    /// compiler argument trait obj
    pub compiler: Box<dyn Compiler<C>>,
    /// modification time of the compilers executable file
    pub mtime: FileTime,
    /// distributed compilation extra info
    pub dist_info: Option<(PathBuf, FileTime)>,
}

impl<C> CompilerCacheEntry<C> {
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
struct SccacheService<C>
where
    C: Send,
{
    /// Server statistics.
    stats: Arc<RwLock<ServerStats>>,

    /// Distributed sccache client
    dist_client: Arc<DistClientContainer>,

    /// Cache storage.
    storage: Arc<dyn Storage>,

    /// A cache of known compiler info.
    compilers: Arc<RwLock<CompilerMap<C>>>,

    /// map the cwd with compiler proxy path to a proxy resolver, which
    /// will dynamically resolve the input compiler for the current context
    /// (usually file or current working directory)
    /// the associated `FileTime` is the modification time of
    /// the compiler proxy, in order to track updates of the proxy itself
    compiler_proxies: Arc<RwLock<CompilerProxyMap<C>>>,

    /// Task pool for blocking (used mostly for disk I/O-bound tasks) and
    // non-blocking tasks
    rt: tokio::runtime::Handle,

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
    /// This field causes [WaitUntilZero] to wait until this struct drops.
    #[allow(dead_code)]
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

impl<C> Service<SccacheRequest> for Arc<SccacheService<C>>
where
    C: CommandCreatorSync + Send + Sync + 'static,
{
    type Response = SccacheResponse;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send + 'static>>;

    fn call(&mut self, req: SccacheRequest) -> Self::Future {
        trace!("handle_client");

        // Opportunistically let channel know that we've received a request. We
        // ignore failures here as well as backpressure as it's not imperative
        // that every message is received.
        drop(self.tx.clone().start_send(ServerMessage::Request));

        let me = self.clone();
        Box::pin(async move {
            match req.into_inner() {
                Request::Compile(compile) => {
                    debug!("handle_client: compile");
                    me.stats.write().await.compile_requests += 1;
                    me.handle_compile(compile).await
                }
                Request::GetStats => {
                    debug!("handle_client: get_stats");
                    me.get_info()
                        .await
                        .map(|i| Response::Stats(Box::new(i)))
                        .map(Message::WithoutBody)
                }
                Request::DistStatus => {
                    debug!("handle_client: dist_status");
                    me.get_dist_status()
                        .await
                        .map(Response::DistStatus)
                        .map(Message::WithoutBody)
                }
                Request::ZeroStats => {
                    debug!("handle_client: zero_stats");
                    me.zero_stats().await;
                    me.get_info()
                        .await
                        .map(|i| Response::Stats(Box::new(i)))
                        .map(Message::WithoutBody)
                }
                Request::Shutdown => {
                    debug!("handle_client: shutdown");
                    let mut tx = me.tx.clone();
                    future::try_join(
                        async {
                            let _ = tx.send(ServerMessage::Shutdown).await;
                            Ok(())
                        },
                        me.get_info(),
                    )
                    .await
                    .map(move |(_, info)| {
                        Message::WithoutBody(Response::ShuttingDown(Box::new(info)))
                    })
                }
            }
        })
    }

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}

use futures::future::Either;
use futures::TryStreamExt;

impl<C> SccacheService<C>
where
    C: CommandCreatorSync + Clone + Send + Sync + 'static,
{
    pub fn new(
        dist_client: DistClientContainer,
        storage: Arc<dyn Storage>,
        client: &Client,
        rt: tokio::runtime::Handle,
        tx: mpsc::Sender<ServerMessage>,
        info: ActiveInfo,
    ) -> SccacheService<C> {
        SccacheService {
            stats: Arc::new(RwLock::new(ServerStats::default())),
            dist_client: Arc::new(dist_client),
            storage,
            compilers: Arc::new(RwLock::new(HashMap::new())),
            compiler_proxies: Arc::new(RwLock::new(HashMap::new())),
            rt,
            creator: C::new(client),
            tx,
            info,
        }
    }

    fn bind<T>(self, socket: T) -> impl Future<Output = Result<()>> + Send + Sized + 'static
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
            inner: Framed::new(io.sink_err_into().err_into(), BincodeCodec),
        }
        .split();
        let sink = sink.sink_err_into::<Error>();

        let me = Arc::new(self);
        stream
            .err_into::<Error>()
            .and_then(move |input| me.clone().call(input))
            .and_then(move |message| async move {
                let fut = match message {
                    Message::WithoutBody(message) => {
                        let stream = stream::once(async move { Ok(Frame::Message { message }) });
                        Either::Left(stream)
                    }
                    Message::WithBody(message, body) => {
                        let stream = stream::once(async move { Ok(Frame::Message { message }) })
                            .chain(body.map_ok(|chunk| Frame::Body { chunk: Some(chunk) }))
                            .chain(stream::once(async move { Ok(Frame::Body { chunk: None }) }));
                        Either::Right(stream)
                    }
                };
                Ok(Box::pin(fut))
            })
            .try_flatten()
            .forward(sink)
    }

    /// Get dist status.
    async fn get_dist_status(&self) -> Result<DistInfo> {
        Ok(self.dist_client.get_status().await)
    }

    /// Get info and stats about the cache.
    async fn get_info(&self) -> Result<ServerInfo> {
        let stats = self.stats.read().await.clone();
        let cache_location = self.storage.location();
        futures::try_join!(self.storage.current_size(), self.storage.max_size()).map(
            move |(cache_size, max_cache_size)| ServerInfo {
                stats,
                cache_location,
                cache_size,
                max_cache_size,
            },
        )
    }

    /// Zero stats about the cache.
    async fn zero_stats(&self) {
        *self.stats.write().await = ServerStats::default();
    }

    /// Handle a compile request from a client.
    ///
    /// This will handle a compile request entirely, generating a response with
    /// the initial information and an optional body which will eventually
    /// contain the results of the compilation.
    async fn handle_compile(&self, compile: Compile) -> Result<SccacheResponse> {
        let exe = compile.exe;
        let cmd = compile.args;
        let cwd: PathBuf = compile.cwd.into();
        let env_vars = compile.env_vars;
        let me = self.clone();

        let info = self.compiler_info(exe.into(), cwd.clone(), &env_vars).await;
        Ok(me.check_compiler(info, cmd, cwd, env_vars).await)
    }

    /// Look up compiler info from the cache for the compiler `path`.
    /// If not cached, determine the compiler type and cache the result.
    async fn compiler_info(
        &self,
        path: PathBuf,
        cwd: PathBuf,
        env: &[(OsString, OsString)],
    ) -> Result<Box<dyn Compiler<C>>> {
        trace!("compiler_info");

        let me = self.clone();
        let me1 = self.clone();
        // lookup if compiler proxy exists for the current compiler path

        let path2 = path.clone();
        let path1 = path.clone();
        let env = env.to_vec();

        let resolved_with_proxy = {
            let compiler_proxies_borrow = self.compiler_proxies.read().await;
            // Create an owned future - compiler proxy is not Send so we can't
            // really await while borrowing the proxy since rustc is too conservative
            let resolve_proxied_executable =
                compiler_proxies_borrow
                    .get(&path)
                    .map(|(compiler_proxy, _filetime)| {
                        compiler_proxy.resolve_proxied_executable(
                            self.creator.clone(),
                            cwd.clone(),
                            env.as_slice(),
                        )
                    });

            match resolve_proxied_executable {
                Some(fut) => fut.await.ok(),
                None => None,
            }
        };

        // use the supplied compiler path as fallback, lookup its modification time too
        let (resolved_compiler_path, mtime) = match resolved_with_proxy {
            Some(x) => x, // TODO resolve the path right away
            _ => {
                // fallback to using the path directly
                metadata(&path2)
                    .map(|attr| FileTime::from_last_modification_time(&attr))
                    .ok()
                    .map(move |filetime| (path2, filetime))
                    .expect("Must contain sane data, otherwise mtime is not avail")
            }
        };

        let dist_info = match me1.dist_client.get_client().await {
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

        let opt = match me1.compilers.read().await.get(&resolved_compiler_path) {
            // It's a hit only if the mtime and dist archive data matches.
            Some(&Some(ref entry)) => {
                if entry.mtime == mtime && entry.dist_info == dist_info {
                    Some(entry.compiler.box_clone())
                } else {
                    None
                }
            }
            _ => None,
        };

        match opt {
            Some(info) => {
                trace!("compiler_info cache hit");
                Ok(info)
            }
            None => {
                trace!("compiler_info cache miss");
                // Check the compiler type and return the result when
                // finished. This generally involves invoking the compiler,
                // so do it asynchronously.

                // the compiler path might be compiler proxy, so it is important to use
                // `path` (or its clone `path1`) to resolve using that one, not using `resolved_compiler_path`
                let info = get_compiler_info::<C>(
                    me.creator.clone(),
                    &path1,
                    &cwd,
                    env.as_slice(),
                    &me.rt,
                    dist_info.clone().map(|(p, _)| p),
                )
                .await;

                let (c, proxy) = match info {
                    Ok((c, proxy)) => (c.clone(), proxy.clone()),
                    Err(err) => {
                        trace!("Inserting PLAIN cache map info for {:?}", &path);
                        me.compilers.write().await.insert(path, None);

                        return Err(err);
                    }
                };

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
                    me.compiler_proxies
                        .write()
                        .await
                        .insert(path, (proxy, mtime));
                }
                // TODO add some safety checks in case a proxy exists, that the initial `path` is not
                // TODO the same as the resolved compiler binary

                // cache
                let map_info = CompilerCacheEntry::new(c.clone(), mtime, dist_info);
                trace!(
                    "Inserting POSSIBLY PROXIED cache map info for {:?}",
                    &resolved_compiler_path
                );
                me.compilers
                    .write()
                    .await
                    .insert(resolved_compiler_path, Some(map_info));

                // drop the proxy information, response is compiler only
                Ok(c)
            }
        }
    }

    /// Check that we can handle and cache `cmd` when run with `compiler`.
    /// If so, run `start_compile_task` to execute it.
    async fn check_compiler(
        &self,
        compiler: Result<Box<dyn Compiler<C>>>,
        cmd: Vec<OsString>,
        cwd: PathBuf,
        env_vars: Vec<(OsString, OsString)>,
    ) -> SccacheResponse {
        let mut stats = self.stats.write().await;
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
                match c.parse_arguments(&cmd, &cwd, &env_vars) {
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
        mut tx: mpsc::Sender<Result<Response>>,
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
        let me = self.clone();
        let kind = compiler.kind();
        let creator = self.creator.clone();
        let storage = self.storage.clone();
        let pool = self.rt.clone();

        let task = async move {
            let dist_client = me.dist_client.get_client().await;
            let result = match dist_client {
                Ok(client) => {
                    hasher
                        .get_cached_or_compile(
                            client,
                            creator,
                            storage,
                            arguments,
                            cwd,
                            env_vars,
                            cache_control,
                            pool,
                        )
                        .await
                }
                Err(e) => Err(e),
            };
            let mut cache_write = None;
            let mut res = CompileFinished {
                color_mode,
                ..Default::default()
            };
            match result {
                Ok((compiled, out)) => {
                    let mut stats = me.stats.write().await;
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
                    let mut stats = me.stats.write().await;
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
                                me.dist_client.reset_state().await;
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
            let send = tx
                .send(Ok(Response::CompileFinished(res)))
                .map_err(|e| anyhow!("send on finish failed").context(e));

            let me = me.clone();
            let cache_write = async move {
                if let Some(cache_write) = cache_write {
                    match cache_write.await {
                        Err(e) => {
                            debug!("Error executing cache write: {}", e);
                            me.stats.write().await.cache_write_errors += 1;
                        }
                        //TODO: save cache stats!
                        Ok(info) => {
                            debug!(
                                "[{}]: Cache write finished in {}",
                                info.object_file_pretty,
                                util::fmt_duration_as_secs(&info.duration)
                            );
                            let mut stats = me.stats.write().await;
                            stats.cache_writes += 1;
                            stats.cache_write_duration += info.duration;
                        }
                    }
                }
                Ok(())
            };

            futures::future::try_join(send, cache_write).await?;

            Ok::<_, Error>(())
        };

        self.rt.spawn(async move {
            task.await
                .unwrap_or_else(|e| warn!("Failed to execute task: {:?}", e));
        });
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
                let (val, suffix) = match NumberPrefix::binary(val as f64) {
                    NumberPrefix::Standalone(bytes) => (bytes.to_string(), "bytes".to_string()),
                    NumberPrefix::Prefixed(prefix, n) => {
                        (format!("{:.0}", n), format!("{}B", prefix))
                    }
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
    Message { message: R },
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

impl<R> futures::Stream for Body<R> {
    type Item = Result<R>;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
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

struct BincodeCodec;
impl<T> tokio_serde::Serializer<T> for BincodeCodec
where
    T: serde::Serialize,
{
    type Error = Error;

    fn serialize(self: Pin<&mut Self>, item: &T) -> std::result::Result<Bytes, Self::Error> {
        let mut bytes = BytesMut::new();
        bincode::serialize_into((&mut bytes).writer(), item)?;
        Ok(bytes.freeze())
    }
}

impl<T> tokio_serde::Deserializer<T> for BincodeCodec
where
    T: serde::de::DeserializeOwned,
{
    type Error = Error;

    fn deserialize(self: Pin<&mut Self>, buf: &BytesMut) -> std::result::Result<T, Self::Error> {
        let ret = bincode::deserialize(buf)?;
        Ok(ret)
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
struct SccacheTransport<I: AsyncRead + AsyncWrite + Unpin> {
    inner: Framed<
        futures::stream::ErrInto<
            futures::sink::SinkErrInto<
                tokio_util::codec::Framed<I, LengthDelimitedCodec>,
                Bytes,
                Error,
            >,
            Error,
        >,
        Request,
        Response,
        BincodeCodec,
    >,
}

impl<I: AsyncRead + AsyncWrite + Unpin> Stream for SccacheTransport<I> {
    type Item = Result<Message<Request, Body<()>>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner)
            .poll_next(cx)
            .map(|r| r.map(|s| s.map(Message::WithoutBody)))
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> Sink<Frame<Response, Response>> for SccacheTransport<I> {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Frame<Response, Response>) -> Result<()> {
        match item {
            Frame::Message { message } => Pin::new(&mut self.inner).start_send(message),
            Frame::Body { chunk: Some(chunk) } => Pin::new(&mut self.inner).start_send(chunk),
            Frame::Body { chunk: None } => Ok(()),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

struct ShutdownOrInactive {
    rx: mpsc::Receiver<ServerMessage>,
    timeout: Option<Pin<Box<Sleep>>>,
    timeout_dur: Duration,
}

impl Future for ShutdownOrInactive {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            match Pin::new(&mut self.rx).poll_next(cx) {
                Poll::Pending => break,
                // Shutdown received!
                Poll::Ready(Some(ServerMessage::Shutdown)) => return Poll::Ready(()),
                Poll::Ready(Some(ServerMessage::Request)) => {
                    if self.timeout_dur != Duration::new(0, 0) {
                        self.timeout = Some(Box::pin(sleep(self.timeout_dur)));
                    }
                }
                // All services have shut down, in theory this isn't possible...
                Poll::Ready(None) => return Poll::Ready(()),
            }
        }
        match self.timeout {
            None => Poll::Pending,
            Some(ref mut timeout) => timeout.as_mut().poll(cx),
        }
    }
}

/// Helper future which tracks the `ActiveInfo` below. This future will resolve
/// once all instances of `ActiveInfo` have been dropped.
struct WaitUntilZero {
    info: std::sync::Weak<Mutex<Info>>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ActiveInfo {
    info: Arc<Mutex<Info>>,
}

struct Info {
    waker: Option<Waker>,
}

impl Drop for Info {
    fn drop(&mut self) {
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
        }
    }
}

impl WaitUntilZero {
    #[rustfmt::skip]
    fn new() -> (WaitUntilZero, ActiveInfo) {
        let info = Arc::new(Mutex::new(Info { waker: None }));

        (WaitUntilZero { info: Arc::downgrade(&info) }, ActiveInfo { info })
    }
}

impl std::future::Future for WaitUntilZero {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        match self.info.upgrade() {
            None => std::task::Poll::Ready(()),
            Some(arc) => {
                let mut info = arc.lock().expect("we can't panic when holding lock");
                info.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }
}

#[test]
fn waits_until_zero() {
    let (wait, _active) = WaitUntilZero::new();
    assert_eq!(wait.now_or_never(), None);

    let (wait, active) = WaitUntilZero::new();
    let _active2 = active.clone();
    drop(active);
    assert_eq!(wait.now_or_never(), None);

    let (wait, _) = WaitUntilZero::new();
    assert_eq!(wait.now_or_never(), Some(()));

    let (wait, active) = WaitUntilZero::new();
    let active2 = active.clone();
    drop(active);
    drop(active2);
    assert_eq!(wait.now_or_never(), Some(()));
}
