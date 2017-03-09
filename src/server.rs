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

use bytes::BytesMut;
use cache::{
    Storage,
    storage_from_environment,
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
use filetime::FileTime;
use futures::future;
use futures::sync::mpsc;
use futures::task::{self, Task};
use futures::{Stream, Sink, Async, AsyncSink, Poll, StartSend, Future};
use futures_cpupool::CpuPool;
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
};
use protobuf::{
    self,
    ProtobufError,
    RepeatedField,
    parse_length_delimited_from_bytes,
};
use protocol::{
    ClientRequest,
    CacheStats,
    CacheStatistic,
    Compile,
    CompileFinished,
    CompileStarted,
    ServerResponse,
    ShuttingDown,
    UnhandledCompile,
    UnknownCommand,
};
use std::collections::HashMap;
use std::cell::RefCell;
use std::env;
use std::ffi::OsString;
use std::fs::metadata;
use std::io::{self, Write};
use std::marker;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::process::Output;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio_core::reactor::{Handle, Core, Timeout};
use tokio_core::net::TcpListener;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Encoder, Decoder, Framed};
use tokio_proto::BindServer;
use tokio_proto::streaming::pipeline::{Frame, ServerProto, Transport};
use tokio_proto::streaming::{Body, Message};
use tokio_service::Service;
use util::fmt_duration_as_secs;

use errors::*;

/// If the server is idle for this many milliseconds, shut down.
const DEFAULT_IDLE_TIMEOUT: u64 = 600_000;

fn notify_server_startup_internal<W: Write>(mut w: W, success: bool) -> io::Result<()> {
    let data = [ if success { 0 } else { 1 }; 1];
    try!(w.write_all(&data));
    Ok(())
}

#[cfg(unix)]
fn notify_server_startup(name: &Option<OsString>, success: bool) -> io::Result<()> {
    use std::os::unix::net::UnixStream;
    let name = match *name {
        Some(ref s) => s,
        None => return Ok(()),
    };
    debug!("notify_server_startup(success: {})", success);
    let stream = try!(UnixStream::connect(name));
    notify_server_startup_internal(stream, success)
}

#[cfg(windows)]
fn notify_server_startup(name: &Option<OsString>, success: bool) -> io::Result<()> {
    use std::fs::OpenOptions;

    let name = match *name {
        Some(ref s) => s,
        None => return Ok(()),
    };
    let pipe = try!(OpenOptions::new().write(true).read(true).open(name));
    notify_server_startup_internal(pipe, success)
}

/// Start an sccache server, listening on `port`.
///
/// Spins an event loop handling client connections until a client
/// requests a shutdown.
pub fn start_server(port: u16) -> Result<()> {
    let core = Core::new()?;
    let pool = CpuPool::new(20);
    let storage = storage_from_environment(&pool, &core.handle());
    let res = SccacheServer::<ProcessCommandCreator>::new(port, pool, core, storage);
    let notify = env::var_os("SCCACHE_STARTUP_NOTIFY");
    match res {
        Ok(srv) => {
            notify_server_startup(&notify, true)?;
            srv.run(future::empty::<(), ()>())?;
            Ok(())
        }
        Err(e) => {
            notify_server_startup(&notify, false)?;
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
               storage: Arc<Storage>) -> Result<SccacheServer<C>> {
        let handle = core.handle();
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
        let listener = TcpListener::bind(&SocketAddr::V4(addr), &handle)?;

        // Prepare the service which we'll use to service all incoming TCP
        // connections.
        let (tx, rx) = mpsc::channel(1);
        let (wait, info) = WaitUntilZero::new();
        let service = SccacheService::new(storage, core.handle(), pool, tx, info);

        Ok(SccacheServer {
            core: core,
            listener: listener,
            rx: rx,
            service: service,
            timeout: Duration::from_millis(DEFAULT_IDLE_TIMEOUT),
            wait: wait,
        })
    }

    /// Configures how long this server will be idle before shutting down.
    #[allow(dead_code)]
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set the `force_recache` setting.
    #[allow(dead_code)]
    pub fn set_force_recache(&mut self, force_recache: bool) {
        self.service.force_recache = force_recache;
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
        let shutdown_idle = ShutdownOrInactive {
            rx: rx,
            timeout: Timeout::new(timeout, &handle)?,
            handle: handle.clone(),
            timeout_dur: timeout,
        };
        let shutdown_idle = shutdown_idle.map(|a| {
            info!("shutting down due to being idle");
            a
        });

        let shutdown = shutdown.map(|a| {
            info!("shutting down due to explicit signal");
            a
        });

        let server = future::select_all(vec![
            Box::new(server) as Box<Future<Item=_, Error=_>>,
            Box::new(shutdown_idle),
            Box::new(shutdown.map_err(|()| {
                io::Error::new(io::ErrorKind::Other, "shutdown signal failed")
            })),
        ]);
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

    /// Cache storage.
    storage: Arc<Storage>,

    /// A cache of known compiler info.
    compilers: Rc<RefCell<HashMap<String, Option<(Box<Compiler<C>>, FileTime)>>>>,

    /// True if all compiles should be forced, ignoring existing cache entries.
    ///
    /// This can be controlled with the `SCCACHE_RECACHE` environment variable.
    force_recache: bool,

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

type SccacheRequest = Message<ClientRequest, Body<(), Error>>;
type SccacheResponse = Message<ServerResponse, Body<ServerResponse, Error>>;

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
        let mut req = req.into_inner();
        trace!("handle_client");

        // Opportunistically let channel know that we've received a request. We
        // ignore failures here as well as backpressure as it's not imperative
        // that every message is received.
        drop(self.tx.clone().start_send(ServerMessage::Request));

        if req.has_compile() {
            debug!("handle_client: compile");
            self.stats.borrow_mut().compile_requests += 1;
            self.handle_compile(req.take_compile())
        } else {
            // Simple requests that can generate responses right away.
            let mut res = ServerResponse::new();
            if req.has_get_stats() {
                debug!("handle_client: get_stats");
                res.set_stats(self.get_stats());
            } else if req.has_zero_stats() {
                debug!("handle_client: zero_stats");
                res.set_stats(self.zero_stats());
            } else if req.has_shutdown() {
                debug!("handle_client: shutdown");
                let future = self.tx.clone().send(ServerMessage::Shutdown);
                let me = self.clone();
                return Box::new(future.then(move |_| {
                    let mut shutting_down = ShuttingDown::new();
                    shutting_down.set_stats(me.get_stats());
                    res.set_shutting_down(shutting_down);
                    Ok(Message::WithoutBody(res))
                }))
            } else {
                warn!("handle_client: unknown command");
                res.set_unknown(UnknownCommand::new());
            }

            f_ok(Message::WithoutBody(res))
        }
    }
}

impl<C> SccacheService<C>
    where C: CommandCreatorSync,
{
    pub fn new(storage: Arc<Storage>,
               handle: Handle,
               pool: CpuPool,
               tx: mpsc::Sender<ServerMessage>,
               info: ActiveInfo) -> SccacheService<C> {
        SccacheService {
            stats: Rc::new(RefCell::new(ServerStats::default())),
            storage: storage,
            compilers: Rc::new(RefCell::new(HashMap::new())),
            force_recache: env::var("SCCACHE_RECACHE").is_ok(),
            pool: pool,
            creator: C::new(&handle),
            handle: handle,
            tx: tx,
            info: info,
        }
    }

    /// Get stats about the cache.
    fn get_stats(&self) -> CacheStats {
        let mut stats = CacheStats::new();
        let mut stats_vec = self.stats.borrow().to_cache_statistics();

        let mut stat = CacheStatistic::new();
        stat.set_name(String::from("Cache location"));
        stat.set_str(self.storage.location());
        stats_vec.insert(0, stat);

        for &(s, v) in [("Cache size", self.storage.current_size()),
                       ("Max cache size", self.storage.max_size())].iter() {
            v.map(|val| {
                let mut stat = CacheStatistic::new();
                stat.set_name(String::from(s));
                stat.set_size(val as u64);
                stats_vec.insert(0, stat);
            });
        }

        stats.set_stats(RepeatedField::from_vec(stats_vec));
        stats
    }

    /// Zero and return stats about the cache.
    fn zero_stats(&self) -> CacheStats {
        *self.stats.borrow_mut() = ServerStats::default();
        self.get_stats()
    }


    /// Handle a compile request from a client.
    ///
    /// This will handle a compile request entirely, generating a response with
    /// the inital information and an optional body which will eventually
    /// contain the results of the compilation.
    fn handle_compile(&self, mut compile: Compile)
                      -> SFuture<SccacheResponse>
    {
        let exe = compile.take_exe();
        let cmd = compile.take_command().into_vec();
        let cwd = compile.take_cwd();
        let me = self.clone();
        Box::new(self.compiler_info(exe).map(move |info| {
            me.check_compiler(info, cmd, cwd)
        }))
    }

    /// Look up compiler info from the cache for the compiler `path`.
    /// If not cached, determine the compiler type and cache the result.
    fn compiler_info(&self, path: String)
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

                let info = get_compiler_info(&self.creator, &path, &self.pool);
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
                      cmd: Vec<String>,
                      cwd: String)
                      -> SccacheResponse {
        let mut res = ServerResponse::new();
        let mut stats = self.stats.borrow_mut();
        match compiler {
            None => {
                debug!("check_compiler: Unsupported compiler");
                stats.requests_unsupported_compiler += 1;
            }
            Some(c) => {
                debug!("check_compiler: Supported compiler");
                // Now check that we can handle this compiler with
                // the provided commandline.
                match c.parse_arguments(&cmd, cwd.as_ref()) {
                    CompilerArguments::Ok(hasher) => {
                        debug!("parse_arguments: Ok");
                        stats.requests_executed += 1;
                        res.set_compile_started(CompileStarted::new());
                        let (tx, rx) = Body::pair();
                        self.start_compile_task(hasher, cmd, cwd, tx);
                        return Message::WithBody(res, rx)
                    }
                    CompilerArguments::CannotCache => {
                        debug!("parse_arguments: CannotCache");
                        stats.requests_not_cacheable += 1;
                    }
                    CompilerArguments::NotCompilation => {
                        debug!("parse_arguments: NotCompilation");
                        stats.requests_not_compile += 1;
                    }
                }
            }
        }

        res.set_unhandled_compile(UnhandledCompile::new());
        Message::WithoutBody(res)
    }

    /// Given compiler arguments `arguments`, look up
    /// a compile result in the cache or execute the compilation and store
    /// the result in the cache.
    fn start_compile_task(&self,
                          hasher: Box<CompilerHasher<C>>,
                          arguments: Vec<String>,
                          cwd: String,
                          tx: mpsc::Sender<Result<ServerResponse>>) {
        let cache_control = if self.force_recache {
            CacheControl::ForceRecache
        } else {
            CacheControl::Default
        };
        let output = hasher.output_file().into_owned();
        let result = hasher.get_cached_or_compile(self.creator.clone(),
                                                  self.storage.clone(),
                                                  arguments,
                                                  cwd,
                                                  cache_control,
                                                  self.pool.clone(),
                                                  self.handle.clone());
        let me = self.clone();
        let task = result.then(move |result| {
            let mut res = ServerResponse::new();
            let mut finish = CompileFinished::new();
            let mut cache_write = None;
            let mut stats = me.stats.borrow_mut();
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
                                MissType::Normal => {
                                    stats.cache_misses += 1;
                                }
                                MissType::ForcedRecache => {
                                    stats.cache_misses += 1;
                                    stats.forced_recaches += 1;
                                }
                                MissType::TimedOut => {
                                    stats.cache_misses += 1;
                                    stats.cache_timeouts += 1;
                                }
                            }
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
                    status.code()
                        .map_or_else(
                            || trace!("CompileFinished missing retcode"),
                            |s| { trace!("CompileFinished retcode: {}", s); finish.set_retcode(s) });
                    //TODO: sort out getting signal return on Unix
                    finish.set_stdout(stdout);
                    finish.set_stderr(stderr);
                }
                Err(err) => {
                    debug!("[{:?}] compilation failed: {:?}",
                           err,
                           output);
                    for e in err.iter() {
                        error!("[{:?}] \t{}", e, output);
                    }
                    stats.cache_errors += 1;
                    //TODO: figure out a better way to communicate this?
                    finish.set_retcode(-2);
                }
            };
            res.set_compile_finished(finish);
            let send = tx.send(Ok(res));

            let me = me.clone();
            let cache_write = cache_write.then(move |result| {
                match result {
                    Err(e) => {
                        debug!("Error executing cache write: {}", e);
                        me.stats.borrow_mut().cache_write_errors += 1;
                    }
                    //TODO: save cache stats!
                    Ok(Some(info)) => {
                        debug!("[{}]: Cache write finished in {}", info.object_file, fmt_duration_as_secs(&info.duration));
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

/// Statistics about the cache.
struct ServerStats {
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
    fn to_cache_statistics(&self) -> Vec<CacheStatistic> {
        macro_rules! set_stat {
            ($vec:ident, $var:expr, $name:expr) => {{
                let mut stat = CacheStatistic::new();
                stat.set_name(String::from($name));
                stat.set_count($var);
                $vec.push(stat);
            }};
        }

        macro_rules! set_duration_stat {
            ($vec:ident, $dur:expr, $num:expr, $name:expr) => {{
                let mut stat = CacheStatistic::new();
                stat.set_name(String::from($name));
                if $num > 0 {
                    let duration = $dur / $num as u32;
                    stat.set_str(fmt_duration_as_secs(&duration));
                } else {
                    stat.set_str("0.000s".to_owned());
                }
                $vec.push(stat);
            }};
        }

        let mut stats_vec = vec!();
        set_stat!(stats_vec, self.compile_requests, "Compile requests");
        set_stat!(stats_vec, self.requests_executed, "Compile requests executed");
        set_stat!(stats_vec, self.cache_hits, "Cache hits");
        set_stat!(stats_vec, self.cache_misses, "Cache misses");
        set_stat!(stats_vec, self.cache_timeouts, "Cache timeouts");
        set_stat!(stats_vec, self.forced_recaches, "Forced recaches");
        set_stat!(stats_vec, self.cache_write_errors, "Cache write errors");
        set_stat!(stats_vec, self.compile_fails, "Compilation failures");
        set_stat!(stats_vec, self.cache_errors, "Cache errors");
        set_stat!(stats_vec, self.non_cacheable_compilations, "Successful compilations which could not be cached");
        set_stat!(stats_vec, self.requests_not_cacheable, "Non-cacheable calls");
        set_stat!(stats_vec, self.requests_not_compile, "Non-compilation calls");
        set_stat!(stats_vec, self.requests_unsupported_compiler, "Unsupported compiler calls");
        set_duration_stat!(stats_vec, self.cache_write_duration, self.cache_writes, "Average cache write");
        set_duration_stat!(stats_vec, self.cache_read_miss_duration, self.cache_misses, "Average cache read miss");
        set_duration_stat!(stats_vec, self.cache_read_hit_duration, self.cache_hits, "Average cache read hit");
        stats_vec
    }
}

/// tokio-proto protocol implementation for sccache
struct SccacheProto;

impl<I> ServerProto<I> for SccacheProto
    where I: AsyncRead + AsyncWrite + 'static,
{
    type Request = ClientRequest;
    type RequestBody = ();
    type Response = ServerResponse;
    type ResponseBody = ServerResponse;
    type Error = Error;
    type Transport = SccacheTransport<I>;
    type BindTransport = future::FutureResult<Self::Transport, io::Error>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        future::ok(SccacheTransport {
            inner: AsyncRead::framed(io, ProtobufCodec::new()),
        })
    }
}

/// Implementation of `Stream + Sink` that tokio-proto is expecting. This takes
/// a `Framed` instance using `ProtobufCodec` and performs a simple map
/// operation on the sink/stream halves to translate the protobuf message types
/// to the `Frame` types that tokio-proto expects.
struct SccacheTransport<I> {
    inner: Framed<I, ProtobufCodec<ClientRequest, ServerResponse>>,
}

impl<I: AsyncRead + AsyncWrite> Stream for SccacheTransport<I> {
    type Item = Frame<ClientRequest, (), Error>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        let msg = try_ready!(self.inner.poll());
        Ok(msg.map(|m| {
            Frame::Message {
                message: m,
                body: false,
            }
        }).into())
    }
}

impl<I: AsyncRead + AsyncWrite> Sink for SccacheTransport<I> {
    type SinkItem = Frame<ServerResponse, ServerResponse, Error>;
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

/// Simple tokio-core `Codec` which uses stock protobuf functions to
/// decode/encode protobuf messages.
struct ProtobufCodec<Request, Response> {
    _marker: marker::PhantomData<fn() -> (Request, Response)>,
}

impl<Request, Response> ProtobufCodec<Request, Response>
    where Request: protobuf::Message + protobuf::MessageStatic,
          Response: protobuf::Message,
{
    fn new() -> ProtobufCodec<Request, Response> {
        ProtobufCodec { _marker: marker::PhantomData }
    }
}

impl<Request, Response> Encoder for ProtobufCodec<Request, Response>
    where Request: protobuf::Message + protobuf::MessageStatic,
          Response: protobuf::Message,
{
    type Item = Response;
    type Error = io::Error;

    fn encode(&mut self, msg: Response, buf: &mut BytesMut) -> io::Result<()> {
        let bytes = msg.write_length_delimited_to_bytes().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })?;
        buf.extend(&bytes);
        Ok(())
    }
}

impl<Request, Response> Decoder for ProtobufCodec<Request, Response>
    where Request: protobuf::Message + protobuf::MessageStatic,
          Response: protobuf::Message,
{
    type Item = Request;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Request>> {
        if buf.len() == 0 {
            return Ok(None)
        }
        match parse_length_delimited_from_bytes::<Request>(&buf) {
            Ok(req) => {
                let size = req.write_length_delimited_to_bytes().unwrap().len();
                buf.split_to(size);
                Ok(Some(req))
            }
            // Unexpected EOF is OK, just means we haven't read enough
            // bytes. It would be nice if this were discriminated more
            // usefully.
            // Issue filed: https://github.com/stepancheg/rust-protobuf/issues/154
            Err(ProtobufError::WireError(s)) => {
                if s == "truncated message" {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, s))
                }
            }
            Err(ProtobufError::IoError(ioe)) => Err(ioe),
            Err(ProtobufError::MessageNotInitialized { message }) => {
                Err(io::Error::new(io::ErrorKind::Other, message))
            }
        }
    }
}

struct ShutdownOrInactive {
    rx: mpsc::Receiver<ServerMessage>,
    handle: Handle,
    timeout: Timeout,
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
                    self.timeout = Timeout::new(self.timeout_dur, &self.handle)?;
                }
                // All services have shut down, in theory this isn't possible...
                Async::Ready(None) => return Ok(().into()),
            }
        }
        self.timeout.poll()
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
                task.unpark();
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
            info.blocker = Some(task::park());
            Ok(Async::NotReady)
        }
    }
}
