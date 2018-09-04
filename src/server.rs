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

use cache::{
    Storage,
    storage_from_config,
};
use compiler::{
    CacheControl,
    Compiler,
    CompilerArguments,
    CompilerHasher,
    CompileResult,
    MissType,
    get_compiler_info,
};
use config::CONFIG;
use dist;
use filetime::FileTime;
use futures::future;
use futures::sync::mpsc;
use futures::task::{self, Task};
use futures::{Stream, Sink, Async, AsyncSink, Poll, StartSend, Future};
use futures_cpupool::CpuPool;
use jobserver::Client;
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
};
use number_prefix::{binary_prefix, Prefixed, Standalone};
use protocol::{Compile, CompileFinished, CompileResponse, Request, Response};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::metadata;
use std::io::{self, Write};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Output, ExitStatus};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use std::u64;
use tokio_core::net::TcpListener;
use tokio_core::reactor::{Handle, Core, Timeout};
use tokio_io::codec::length_delimited::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_proto::BindServer;
use tokio_proto::streaming::pipeline::{Frame, ServerProto, Transport};
use tokio_proto::streaming::{Body, Message};
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_service::Service;
use util; //::fmt_duration_as_secs;

use errors::*;

/// If the server is idle for this many seconds, shut down.
const DEFAULT_IDLE_TIMEOUT: u64 = 600;

/// Result of background server startup.
#[derive(Debug, Serialize, Deserialize)]
pub enum ServerStartup {
    /// Server started successfully on `port`.
    Ok { port: u16 },
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
    let pipe = try!(OpenOptions::new().write(true).read(true).open(name));
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

/// Start an sccache server, listening on `port`.
///
/// Spins an event loop handling client connections until a client
/// requests a shutdown.
pub fn start_server(port: u16) -> Result<()> {
    info!("start_server: port: {}", port);
    let client = unsafe { Client::new() };
    let core = Core::new()?;
    let pool = CpuPool::new(20);
    let dist_client: Arc<dist::Client> = match CONFIG.dist.scheduler_addr {
        #[cfg(feature = "dist-client")]
        Some(addr) => {
            info!("Enabling distributed sccache to {}", addr);
            Arc::new(dist::http::Client::new(
                &core.handle(),
                &pool,
                addr,
                &CONFIG.dist.cache_dir.join("client"),
                CONFIG.dist.toolchain_cache_size,
                &CONFIG.dist.custom_toolchains,
                &CONFIG.dist.auth,
            ))
        },
        #[cfg(not(feature = "dist-client"))]
        Some(_) => {
            warn!("Scheduler address configured but dist feature disabled, disabling distributed sccache");
            Arc::new(dist::NoopClient)
        },
        None => {
            info!("No scheduler address configured, disabling distributed sccache");
            Arc::new(dist::NoopClient)
        },
    };
    let storage = storage_from_config(&pool, &core.handle());
    let res = SccacheServer::<ProcessCommandCreator>::new(port, pool, core, client, dist_client, storage);
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
            let reason = e.to_string();
            notify_server_startup(&notify, ServerStartup::Err { reason })?;
            Err(e)
        }
    }
}

pub struct SccacheServer<C: CommandCreatorSync> {
    core: Core,
    listener: TcpListener,
    rx: mpsc::Receiver<ServerMessage>,
    timeout: Duration,
    service: SccacheService<C>,
    wait: WaitUntilZero,
}

impl<C: CommandCreatorSync> SccacheServer<C> {
    pub fn new(port: u16,
               pool: CpuPool,
               core: Core,
               client: Client,
               dist_client: Arc<dist::Client>,
               storage: Arc<Storage>) -> Result<SccacheServer<C>> {
        let handle = core.handle();
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
        let listener = TcpListener::bind(&SocketAddr::V4(addr), &handle)?;

        // Prepare the service which we'll use to service all incoming TCP
        // connections.
        let (tx, rx) = mpsc::channel(1);
        let (wait, info) = WaitUntilZero::new();
        let service = SccacheService::new(dist_client,
                                          storage,
                                          core.handle(),
                                          &client,
                                          pool,
                                          tx,
                                          info);

        Ok(SccacheServer {
            core: core,
            listener: listener,
            rx: rx,
            service: service,
            timeout: Duration::from_secs(get_idle_timeout()),
            wait: wait,
        })
    }

    /// Configures how long this server will be idle before shutting down.
    #[allow(dead_code)]
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set the storage this server will use.
    #[allow(dead_code)]
    pub fn set_storage(&mut self, storage: Arc<Storage>) {
        self.service.storage = storage;
    }

    /// Returns a reference to a thread pool to run work on
    #[allow(dead_code)]
    pub fn pool(&self) -> &CpuPool {
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
        where F: Future,
    {
        self._run(Box::new(shutdown.then(|_| Ok(()))))
    }

    fn _run<'a>(self, shutdown: Box<Future<Item = (), Error = ()> + 'a>)
                -> io::Result<()>
    {
        let SccacheServer { mut core, listener, rx, service, timeout, wait } = self;

        // Create our "server future" which will simply handle all incoming
        // connections in separate tasks.
        let handle = core.handle();
        let server = listener.incoming().for_each(move |(socket, _addr)| {
            trace!("incoming connection");
            SccacheProto.bind_server(&handle, socket, service.clone());
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
        let handle = core.handle();

        let shutdown = shutdown.map(|a| {
            info!("shutting down due to explicit signal");
            a
        });

	let mut futures = vec![
            Box::new(server) as Box<Future<Item=_, Error=_>>,
            Box::new(shutdown.map_err(|()| {
                io::Error::new(io::ErrorKind::Other, "shutdown signal failed")
            })),
        ];

        let shutdown_idle = ShutdownOrInactive {
            rx: rx,
            timeout: if timeout != Duration::new(0, 0) {
                Some(Timeout::new(timeout, &handle)?)
            } else {
                None
            },
            handle: handle.clone(),
            timeout_dur: timeout,
        };
        futures.push(Box::new(shutdown_idle.map(|a| {
            info!("shutting down due to being idle or request");
            a
        })));

        let server = future::select_all(futures);
        core.run(server)
            .map_err(|p| p.0)?;

        info!("moving into the shutdown phase now, waiting at most 10 seconds \
              for all client requests to complete");

        // Once our server has shut down either due to inactivity or a manual
        // request we still need to give a bit of time for all active
        // connections to finish. This `wait` future will resolve once all
        // instances of `SccacheService` have been dropped.
        //
        // Note that we cap the amount of time this can take, however, as we
        // don't want to wait *too* long.
        core.run(wait.select(Timeout::new(Duration::new(10, 0), &handle)?))
            .map_err(|p| p.0)?;

        info!("ok, fully shutting down now");

        Ok(())
    }
}

/// Service implementation for sccache
#[derive(Clone)]
struct SccacheService<C: CommandCreatorSync> {
    /// Server statistics.
    stats: Rc<RefCell<ServerStats>>,

    /// Distributed sccache client
    dist_client: Arc<dist::Client>,

    /// Cache storage.
    storage: Arc<Storage>,

    /// A cache of known compiler info.
    compilers: Rc<RefCell<HashMap<PathBuf, Option<(Box<Compiler<C>>, FileTime)>>>>,

    /// Thread pool to execute work in
    pool: CpuPool,

    /// Handle to the event loop that we're running on.
    handle: Handle,

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

type SccacheRequest = Message<Request, Body<(), Error>>;
type SccacheResponse = Message<Response, Body<Response, Error>>;

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

impl<C> Service for SccacheService<C>
    where C: CommandCreatorSync + 'static,
{
    type Request = SccacheRequest;
    type Response = SccacheResponse;
    type Error = Error;
    type Future = SFuture<Self::Response>;

    fn call(&self, req: Self::Request) -> Self::Future {
        trace!("handle_client");

        // Opportunistically let channel know that we've received a request. We
        // ignore failures here as well as backpressure as it's not imperative
        // that every message is received.
        drop(self.tx.clone().start_send(ServerMessage::Request));

        let res: SFuture<Response> = match req.into_inner() {
            Request::Compile(compile) => {
                debug!("handle_client: compile");
                self.stats.borrow_mut().compile_requests += 1;
                return self.handle_compile(compile)
            }
            Request::GetStats => {
                debug!("handle_client: get_stats");
                Box::new(self.get_info().map(Response::Stats))
            }
            Request::ZeroStats => {
                debug!("handle_client: zero_stats");
                self.zero_stats();
                Box::new(self.get_info().map(Response::Stats))
            }
            Request::Shutdown => {
                debug!("handle_client: shutdown");
                let future = self.tx.clone().send(ServerMessage::Shutdown).then(|_| Ok(()));
                let info_future = self.get_info();
                return Box::new(future.join(info_future)
                    .map(move |(_, info)| {
                        Message::WithoutBody(Response::ShuttingDown(info))
                    })
                )
            }
        };

        Box::new(res.map(Message::WithoutBody))
    }
}

impl<C> SccacheService<C>
    where C: CommandCreatorSync,
{
    pub fn new(dist_client: Arc<dist::Client>,
               storage: Arc<Storage>,
               handle: Handle,
               client: &Client,
               pool: CpuPool,
               tx: mpsc::Sender<ServerMessage>,
               info: ActiveInfo) -> SccacheService<C> {
        SccacheService {
            stats: Rc::new(RefCell::new(ServerStats::default())),
            dist_client,
            storage: storage,
            compilers: Rc::new(RefCell::new(HashMap::new())),
            pool: pool,
            creator: C::new(&handle, client),
            handle: handle,
            tx: tx,
            info: info,
        }
    }

    /// Get info and stats about the cache.
    fn get_info(&self) -> SFuture<ServerInfo> {
        let stats = self.stats.borrow().clone();
        let cache_location = self.storage.location();
        Box::new(self.storage.current_size().join(self.storage.max_size())
            .map(move |(cache_size, max_cache_size)| {
                ServerInfo {
                    stats,
                    cache_location,
                    cache_size,
                    max_cache_size,
                }
            })
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
    fn handle_compile(&self, compile: Compile)
                      -> SFuture<SccacheResponse>
    {
        let exe = compile.exe;
        let cmd = compile.args;
        let cwd = compile.cwd;
        let env_vars = compile.env_vars;
        let me = self.clone();
        Box::new(self.compiler_info(exe.into(), &env_vars).map(move |info| {
            me.check_compiler(info, cmd, cwd.into(), env_vars)
        }))
    }

    /// Look up compiler info from the cache for the compiler `path`.
    /// If not cached, determine the compiler type and cache the result.
    fn compiler_info(&self, path: PathBuf, env: &[(OsString, OsString)])
                     -> SFuture<Option<Box<Compiler<C>>>> {
        trace!("compiler_info");
        let mtime = ftry!(metadata(&path).map(|attr| FileTime::from_last_modification_time(&attr)));
        //TODO: properly handle rustup overrides. Currently this will
        // cache based on the rustup rustc path, ignoring overrides.
        // https://github.com/mozilla/sccache/issues/87
        let result = match self.compilers.borrow().get(&path) {
            // It's a hit only if the mtime matches.
            Some(&Some((ref c, ref cached_mtime))) if *cached_mtime == mtime => Some(Some(c.clone())),
            // We cache non-results.
            Some(&None) => Some(None),
            _ => None,
        };
        match result {
            Some(info) => {
                trace!("compiler_info cache hit");
                f_ok(info)
            }
            None => {
                trace!("compiler_info cache miss");
                // Check the compiler type and return the result when
                // finished. This generally involves invoking the compiler,
                // so do it asynchronously.
                let me = self.clone();

                let info = get_compiler_info(&self.creator, &path, env, &self.pool);
                Box::new(info.then(move |info| {
                    let info = info.ok();
                    me.compilers.borrow_mut().insert(path, info.clone().map(|i| (i, mtime)));
                    Ok(info)
                }))
            }
        }
    }

    /// Check that we can handle and cache `cmd` when run with `compiler`.
    /// If so, run `start_compile_task` to execute it.
    fn check_compiler(&self,
                      compiler: Option<Box<Compiler<C>>>,
                      cmd: Vec<OsString>,
                      cwd: PathBuf,
                      env_vars: Vec<(OsString, OsString)>) -> SccacheResponse
    {
        let mut stats = self.stats.borrow_mut();
        match compiler {
            None => {
                debug!("check_compiler: Unsupported compiler");
                stats.requests_unsupported_compiler += 1;
                return Message::WithoutBody(
                    Response::Compile(CompileResponse::UnsupportedCompiler)
                        );
            }
            Some(c) => {
                debug!("check_compiler: Supported compiler");
                // Now check that we can handle this compiler with
                // the provided commandline.
                match c.parse_arguments(&cmd, &cwd) {
                    CompilerArguments::Ok(hasher) => {
                        debug!("parse_arguments: Ok: {:?}", cmd);
                        stats.requests_executed += 1;
                        let (tx, rx) = Body::pair();
                        self.start_compile_task(hasher, cmd, cwd, env_vars, tx);
                        let res = CompileResponse::CompileStarted;
                        return Message::WithBody(Response::Compile(res), rx)
                    }
                    CompilerArguments::CannotCache(why, extra_info) => {
                        //TODO: save counts of why
                        if let Some(extra_info) = extra_info {
                            debug!("parse_arguments: CannotCache({}, {}): {:?}", why, extra_info, cmd)
                        } else {
                            debug!("parse_arguments: CannotCache({}): {:?}", why, cmd)
                        }
                        stats.requests_not_cacheable += 1;
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
    fn start_compile_task(&self,
                          hasher: Box<CompilerHasher<C>>,
                          arguments: Vec<OsString>,
                          cwd: PathBuf,
                          env_vars: Vec<(OsString, OsString)>,
                          tx: mpsc::Sender<Result<Response>>) {
        let force_recache = env_vars.iter().any(|&(ref k, ref _v)| {
            k.as_os_str() == OsStr::new("SCCACHE_RECACHE")
        });
        let cache_control = if force_recache {
            CacheControl::ForceRecache
        } else {
            CacheControl::Default
        };
        let out_pretty = hasher.output_pretty().into_owned();
        let color_mode = hasher.color_mode();
        let result = hasher.get_cached_or_compile(self.dist_client.clone(),
                                                  self.creator.clone(),
                                                  self.storage.clone(),
                                                  arguments,
                                                  cwd,
                                                  env_vars,
                                                  cache_control,
                                                  self.pool.clone(),
                                                  self.handle.clone());
        let me = self.clone();
        let task = result.then(move |result| {
            let mut cache_write = None;
            let mut stats = me.stats.borrow_mut();
            let mut res = CompileFinished::default();
            res.color_mode = color_mode;
            match result {
                Ok((compiled, out)) => {
                    match compiled {
                        CompileResult::Error => {
                            stats.cache_errors += 1;
                        }
                        CompileResult::CacheHit(duration) => {
                            stats.cache_hits += 1;
                            stats.cache_read_hit_duration += duration;
                        },
                        CompileResult::CacheMiss(miss_type, duration, future) => {
                            match miss_type {
                                MissType::Normal => {}
                                MissType::ForcedRecache => {
                                    stats.forced_recaches += 1;
                                }
                                MissType::TimedOut => {
                                    stats.cache_timeouts += 1;
                                }
                                MissType::CacheReadError => {
                                    stats.cache_errors += 1;
                                }
                            }
                            stats.cache_misses += 1;
                            stats.cache_read_miss_duration += duration;
                            cache_write = Some(future);
                        }
                        CompileResult::NotCacheable => {
                            stats.cache_misses += 1;
                            stats.non_cacheable_compilations += 1;
                        }
                        CompileResult::CompileFailed => {
                            stats.compile_fails += 1;
                        }
                    };
                    let Output { status, stdout, stderr } = out;
                    trace!("CompileFinished retcode: {}", status);
                    match status.code() {
                        Some(code) => res.retcode = Some(code),
                        None => res.signal = Some(get_signal(status)),
                    };
                    res.stdout = stdout;
                    res.stderr = stderr;
                }
                Err(Error(ErrorKind::ProcessError(output), _)) => {
                    debug!("Compilation failed: {:?}", output);
                    stats.compile_fails += 1;
                    match output.status.code() {
                        Some(code) => res.retcode = Some(code),
                        None => res.signal = Some(get_signal(output.status)),
                    };
                    res.stdout = output.stdout;
                    res.stderr = output.stderr;
                }
                Err(err) => {
                    use std::fmt::Write;

                    error!("[{:?}] fatal error: {}", out_pretty, err);

                    let mut error = format!("sccache: encountered fatal error\n");
                    drop(writeln!(error, "sccache: error : {}", err));
                    for e in err.iter() {
                        error!("[{:?}] \t{}", out_pretty, e);
                        drop(writeln!(error, "sccache:  cause: {}", e));
                    }
                    stats.cache_errors += 1;
                    //TODO: figure out a better way to communicate this?
                    res.retcode = Some(-2);
                    res.stderr = error.into_bytes();
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
                        debug!("[{}]: Cache write finished in {}",
                               info.object_file_pretty,
                               util::fmt_duration_as_secs(&info.duration));
                        me.stats.borrow_mut().cache_writes += 1;
                        me.stats.borrow_mut().cache_write_duration += info.duration;
                    }

                    Ok(None) => {}
                }
                Ok(())
            });

            send.join(cache_write).then(|_| Ok(()))
        });

        self.handle.spawn(task);
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
    /// The count of errors handling compile requests.
    pub cache_errors: u64,
    /// The count of cache hits for handled compile requests.
    pub cache_hits: u64,
    /// The count of cache misses for handled compile requests.
    pub cache_misses: u64,
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
}

/// Info and stats about the server.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerInfo {
    pub stats: ServerStats,
    pub cache_location: String,
    pub cache_size: Option<u64>,
    pub max_cache_size: Option<u64>,
}

impl Default for ServerStats {
    fn default() -> ServerStats {
        ServerStats {
            compile_requests: u64::default(),
            requests_unsupported_compiler: u64::default(),
            requests_not_compile: u64::default(),
            requests_not_cacheable: u64::default(),
            requests_executed: u64::default(),
            cache_errors: u64::default(),
            cache_hits: u64::default(),
            cache_misses: u64::default(),
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
                $vec.push(($name, $var.to_string(), 0));
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
                $vec.push(($name, util::fmt_duration_as_secs(&s), 2));
            }};
        }

        let mut stats_vec = vec!();
        //TODO: this would be nice to replace with a custom derive implementation.
        set_stat!(stats_vec, self.compile_requests, "Compile requests");
        set_stat!(stats_vec, self.requests_executed, "Compile requests executed");
        set_stat!(stats_vec, self.cache_hits, "Cache hits");
        set_stat!(stats_vec, self.cache_misses, "Cache misses");
        set_stat!(stats_vec, self.cache_timeouts, "Cache timeouts");
        set_stat!(stats_vec, self.cache_read_errors, "Cache read errors");
        set_stat!(stats_vec, self.forced_recaches, "Forced recaches");
        set_stat!(stats_vec, self.cache_write_errors, "Cache write errors");
        set_stat!(stats_vec, self.compile_fails, "Compilation failures");
        set_stat!(stats_vec, self.cache_errors, "Cache errors");
        set_stat!(stats_vec, self.non_cacheable_compilations, "Non-cacheable compilations");
        set_stat!(stats_vec, self.requests_not_cacheable, "Non-cacheable calls");
        set_stat!(stats_vec, self.requests_not_compile, "Non-compilation calls");
        set_stat!(stats_vec, self.requests_unsupported_compiler, "Unsupported compiler calls");
        set_duration_stat!(stats_vec, self.cache_write_duration, self.cache_writes, "Average cache write");
        set_duration_stat!(stats_vec, self.cache_read_miss_duration, self.cache_misses, "Average cache read miss");
        set_duration_stat!(stats_vec, self.cache_read_hit_duration, self.cache_hits, "Average cache read hit");
        let name_width = stats_vec.iter().map(|&(ref n, _, _)| n.len()).max().unwrap();
        let stat_width = stats_vec.iter().map(|&(_, ref s, _)| s.len()).max().unwrap();
        for (name, stat, suffix_len) in stats_vec {
            println!("{:<name_width$} {:>stat_width$}", name, stat, name_width=name_width, stat_width=stat_width + suffix_len);
        }
        (name_width, stat_width)
    }
}

impl ServerInfo {
    /// Print info to stdout in a human-readable format.
    pub fn print(&self) {
        let (name_width, stat_width) = self.stats.print();
        println!("{:<name_width$} {}", "Cache location", self.cache_location, name_width=name_width);
        for &(name, val) in &[("Cache size", &self.cache_size),
                             ("Max cache size", &self.max_cache_size)] {
            if let &Some(val) = val {
                let (val, suffix) = match binary_prefix(val as f64) {
                    Standalone(bytes) => (bytes.to_string(), "bytes".to_string()),
                    Prefixed(prefix, n) => (format!("{:.0}", n), format!("{}B", prefix)),
                };
                println!("{:<name_width$} {:>stat_width$} {}", name, val, suffix, name_width=name_width, stat_width=stat_width);
            }
        }
    }
}

/// tokio-proto protocol implementation for sccache
struct SccacheProto;

impl<I> ServerProto<I> for SccacheProto
    where I: AsyncRead + AsyncWrite + 'static,
{
    type Request = Request;
    type RequestBody = ();
    type Response = Response;
    type ResponseBody = Response;
    type Error = Error;
    type Transport = SccacheTransport<I>;
    type BindTransport = future::FutureResult<Self::Transport, io::Error>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        future::ok(SccacheTransport {
            inner: WriteBincode::new(ReadBincode::new(Framed::new(io))),
        })
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
    type Item = Frame<Request, (), Error>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        let msg = try_ready!(self.inner.poll().map_err(|e| {
            error!("SccacheTransport::poll failed: {}", e);
            io::Error::new(io::ErrorKind::Other, e)
        }));
        Ok(msg.map(|m| {
            Frame::Message {
                message: m,
                body: false,
            }
        }).into())
    }
}

impl<I: AsyncRead + AsyncWrite> Sink for SccacheTransport<I> {
    type SinkItem = Frame<Response, Response, Error>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem)
                  -> StartSend<Self::SinkItem, io::Error> {
        match item {
            Frame::Message { message, body } => {
                match self.inner.start_send(message)? {
                    AsyncSink::Ready => Ok(AsyncSink::Ready),
                    AsyncSink::NotReady(message) => {
                        Ok(AsyncSink::NotReady(Frame::Message {
                            message: message,
                            body: body,
                        }))
                    }
                }
            }
            Frame::Body { chunk: Some(chunk) } => {
                match self.inner.start_send(chunk)? {
                    AsyncSink::Ready => Ok(AsyncSink::Ready),
                    AsyncSink::NotReady(chunk) => {
                        Ok(AsyncSink::NotReady(Frame::Body {
                            chunk: Some(chunk),
                        }))
                    }
                }
            }
            Frame::Body { chunk: None } => Ok(AsyncSink::Ready),
            Frame::Error { error } => {
                error!("client hit an error:");
                for e in error.iter() {
                    error!("\t{}", e);
                }
                Err(io::Error::new(io::ErrorKind::Other, "application error"))
            }
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        self.inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        self.inner.close()
    }
}

impl<I: AsyncRead + AsyncWrite + 'static> Transport for SccacheTransport<I> {}

struct ShutdownOrInactive {
    rx: mpsc::Receiver<ServerMessage>,
    handle: Handle,
    timeout: Option<Timeout>,
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
                        self.timeout = Some(Timeout::new(self.timeout_dur, &self.handle)?);
                    }
                }
                // All services have shut down, in theory this isn't possible...
                Async::Ready(None) => return Ok(().into()),
            }
        }
        match self.timeout {
            None => Ok(Async::NotReady),
            Some(ref mut timeout) => timeout.poll(),
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
    blocker: Option<Task>,
}

impl WaitUntilZero {
    fn new() -> (WaitUntilZero, ActiveInfo) {
        let info = Rc::new(RefCell::new(Info {
            active: 1,
            blocker: None,
        }));

        (WaitUntilZero { info: info.clone() }, ActiveInfo { info: info })
    }
}

impl Clone for ActiveInfo {
    fn clone(&self) -> ActiveInfo {
        self.info.borrow_mut().active += 1;
        ActiveInfo { info: self.info.clone() }
    }
}

impl Drop for ActiveInfo {
    fn drop(&mut self) {
        let mut info = self.info.borrow_mut();
        info.active -= 1;
        if info.active == 0 {
            if let Some(task) = info.blocker.take() {
                task.notify();
            }
        }
    }
}

impl Future for WaitUntilZero {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        let mut info = self.info.borrow_mut();
        if info.active == 0 {
            Ok(().into())
        } else {
            info.blocker = Some(task::current());
            Ok(Async::NotReady)
        }
    }
}
