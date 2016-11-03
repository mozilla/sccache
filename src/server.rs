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
    storage_from_environment,
};
use compiler::{
    CacheControl,
    CacheWriteFuture,
    CacheWriteResult,
    Compiler,
    CompilerArguments,
    CompileResult,
    MissType,
    ParsedArguments,
    get_compiler_info,
};
use filetime::FileTime;
use futures::Future;
use mio::*;
use mio::tcp::{
    TcpListener,
    TcpStream,
};
use mio::util::Slab;
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
};
use protobuf::{
    Message,
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
use std::env;
use std::error::Error;
use std::fs::metadata;
use std::io::{self,ErrorKind};
use std::net::{SocketAddr, SocketAddrV4};
use std::process::Output;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// If the server is idle for this many milliseconds, shut down.
const DEFAULT_IDLE_TIMEOUT: u64 = 600000;

/// A background task.
struct Task<C : CommandCreatorSync + 'static> {
    /// A callback to call when the task finishes.
    callback: Box<Fn(Token, TaskResult, &mut SccacheServer<C>, &mut EventLoop<SccacheServer<C>>)>,
}

/// Represents an sccache server instance.
pub struct SccacheServer<C: CommandCreatorSync + 'static> {
    /// The listen socket for the server.
    sock: TcpListener,

    /// The mio `Token` for `self.sock`.
    token: Token,

    /// A list of accepted connections.
    conns: Slab<ClientConnection<C>>,

    /// Cache storage.
    storage: Arc<Box<Storage>>,

    /// Server statistics.
    stats: ServerStats,

    /// True if the server is actively shutting down.
    shutting_down: bool,

    /// After this number of milliseconds with no client requests, shut down.
    idle_timeout: u64,

    /// A `Timeout` handle for the server idle shutdown timeout.
    timeout: Option<Timeout>,

    /// A cache of known compiler info.
    compilers: HashMap<String, Option<Compiler>>,

    /// True if all compiles should be forced, ignoring existing cache entries.
    ///
    /// This can be controlled with the `SCCACHE_RECACHE` environment variable.
    force_recache: bool,

    /// An object for creating commands.
    ///
    /// This is mostly useful for unit testing, where we
    /// can mock this out.
    creator: C,
}

/// Statistics about the cache.
#[derive(Default)]
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
    /// The count of compilations which were successful but couldn't be cached.
    pub non_cacheable_compilations: u64,
    /// The count of compilations which forcibly ignored the cache.
    pub forced_recaches: u64,
    /// The count of errors reading from cache.
    pub cache_read_errors: u64,
    /// The count of errors writing to cache.
    pub cache_write_errors: u64,
    /// The number of successful cache writes.
    pub cache_writes: u32,
    /// The total seconds spent writing cache entries.
    pub cache_write_duration_s: u64,
    /// The total nanoseconds spent writing cache entries.
    pub cache_write_duration_ns: u32,
    /// The count of compilation failures.
    pub compile_fails: u64,
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

        let mut stats_vec = vec!();
        set_stat!(stats_vec, self.compile_requests, "Compile requests");
        set_stat!(stats_vec, self.requests_executed, "Compile requests executed");
        set_stat!(stats_vec, self.cache_hits, "Cache hits");
        set_stat!(stats_vec, self.cache_misses, "Cache misses");
        set_stat!(stats_vec, self.forced_recaches, "Forced recaches");
        set_stat!(stats_vec, self.cache_read_errors, "Cache read errors");
        set_stat!(stats_vec, self.cache_write_errors, "Cache write errors");
        set_stat!(stats_vec, self.compile_fails, "Compilation failures");
        set_stat!(stats_vec, self.cache_errors, "Cache errors");
        set_stat!(stats_vec, self.non_cacheable_compilations, "Successful compilations which could not be cached");
        set_stat!(stats_vec, self.requests_not_cacheable, "Non-cacheable calls");
        set_stat!(stats_vec, self.requests_not_compile, "Non-compilation calls");
        set_stat!(stats_vec, self.requests_unsupported_compiler, "Unsupported compiler calls");
        // Set this as a string so we can view subsecond values.
        let mut stat = CacheStatistic::new();
        stat.set_name(String::from("Average cache write"));
        if self.cache_writes > 0 {
            let avg_write_duration = Duration::new(self.cache_write_duration_s, self.cache_write_duration_ns) / self.cache_writes;
            stat.set_str(format!("{}.{:03}s", avg_write_duration.as_secs(), avg_write_duration.subsec_nanos() / 1000));
        } else {
            stat.set_str(String::from("0s"));
        }
        stats_vec.push(stat);
        stats_vec
    }
}

impl<C : CommandCreatorSync + 'static> SccacheServer<C> {
    /// Create an `SccacheServer` bound to `port`, using `storage` as cache storage.
    fn new(port: u16, storage: Box<Storage>) -> io::Result<SccacheServer<C>> {
        let listener = try!(TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))));
        Ok(SccacheServer {
            sock: listener,
            token: Token(1),
            conns: Slab::new_starting_at(Token(2), 128),
            storage: Arc::new(storage),
            stats: ServerStats::default(),
            shutting_down: false,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            timeout: None,
            compilers: HashMap::new(),
            force_recache: env::var("SCCACHE_RECACHE").is_ok(),
            creator: C::new(),
        })
    }

    /// Get the port on which this server is listening for connections.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 { self.sock.local_addr().unwrap().port() }

    /// Set the idle shutdown timeout, in milliseconds.
    ///
    /// Note: Does not clear a pending shutdown timer! Intended for use
    /// in tests, where it will be called before `run_server`.
    #[allow(dead_code)]
    pub fn set_idle_timeout(&mut self, timeout: u64) {
        self.idle_timeout = timeout;
    }

    /// Set the `force_recache` setting.
    #[allow(dead_code)]
    pub fn set_force_recache(&mut self, force_recache: bool) {
        self.force_recache = force_recache;
    }

    /// Return a clone of the object implementing `CommandCreatorSync` that this server uses to create processes.
    ///
    /// This is intended for use in testing. In non-testing, this will
    /// just return a `ProcessCommandCreator` which is a unit struct.
    #[allow(dead_code)]
    pub fn command_creator(&self) -> C {
        self.creator.clone()
    }

    /// Register Server with the event loop.
    fn register(&mut self, mut event_loop: &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        event_loop.register(
            &self.sock,
            self.token,
            EventSet::readable(),
            PollOpt::edge() | PollOpt::oneshot()
        ).and_then(|_| {
            self.reset_idle_timer(&mut event_loop);
            Ok(())
        })
    }

    /// Re-register Server with the event loop.
    fn reregister(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) {
        if !self.shutting_down {
            event_loop.reregister(
                &self.sock,
                self.token,
                EventSet::readable(),
                PollOpt::edge() | PollOpt::oneshot()
             ).unwrap_or_else(|_e| {
                 let server_token = self.token;
                 self.reset_connection(event_loop, server_token);
             })
        }
    }

    /// Accept a new client connection.
    fn accept(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) {
        debug!("Client connecting");
        let sock = match self.sock.accept() {
            Ok(Some((sock, _addr))) => sock,
            Err(_) | Ok(None) => {
                self.reregister(event_loop);
                return;
            }
        };

        if let Some(token) = self.conns.insert_with(|token|
        {
            ClientConnection::new(sock, token)
        })
        {
            match self.conns[token].register(event_loop) {
                Ok(_) => {},
                Err(_e) => {
                    self.conns.remove(token);
                }
            }
        };


        self.reregister(event_loop);
    }

    /// Reset a connection, either the listen socket or a client socket.
    fn reset_connection(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>, token: Token) {
        if self.token == token {
            if !self.shutting_down {
                // Not actively trying to shut down, but something bad happened.
                event_loop.shutdown();
            }
        } else {
            debug!("reset connection; token={:?}", token);
            self.conns.remove(token);
            self.check_shutdown(event_loop);
        }
    }

    /// Check if the server is finished handling in-progress client requests.
    fn check_shutdown(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) {
        if self.shutting_down && self.conns.is_empty() {
            // All done.
            trace!("check_shutdown: shutting down");
            event_loop.shutdown();
        }
    }

    /// Start server shutdown.
    ///
    /// The server will stop accepting incoming requests, and shut down
    /// after it finishes processing any in-progress requests.
    fn initiate_shutdown(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) {
        trace!("initiate_shutdown");
        if !self.shutting_down {
            self.shutting_down = true;
        }
        self.check_shutdown(event_loop);
    }

    /// Run `task` on a background thread, sending the result back to `event_loop` when it completes.
    fn run_task<F, G>(&mut self, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>, task : F, callback : G) where
    F : FnOnce() -> TaskResult + Send + 'static,
    G : Fn(Token, TaskResult, &mut SccacheServer<C>, &mut EventLoop<SccacheServer<C>>) + 'static {
        trace!("run_task");
        let task_sender = event_loop.channel();
        match thread::Builder::new().spawn(move || {
            let msg = ServerMessage::TaskDone {
                res: task(),
                token: token
            };
            task_sender.send(msg).unwrap();
        }) {
            Ok(handle) => {
                // Save the callback in the ClientConnection.
                self.conns[token].set_task(Task { callback: Box::new(callback) });
                // Wait on the task thread handle as well.
                let wait_sender = event_loop.channel();
                thread::spawn(move || {
                    match handle.join() {
                        Ok(_) => {},
                        Err(e) => {
                            e.downcast::<String>()
                                .map(|s| error!("Task thread panicked: {}", s))
                                .unwrap_or_else(|_| error!("Task thread panicked (panic argument was not a String)"));
                            let msg = ServerMessage::TaskDone {
                                res: TaskResult::Panic,
                                token: token
                            };
                            wait_sender.send(msg).unwrap();
                        },
                    }
                });
            },
            //TODO: this should probably just disconnect the client.
            Err(e) => error!("Failed to spawn task: {}", e),
        }
    }

    /// Look up compiler info from the cache for the compiler `path`.
    fn compiler_info_cached(&mut self, path: &str) -> Option<Option<Compiler>> {
        trace!("compiler_info_cached");
        match metadata(path) {
            Ok(attr) => {
                let mtime = FileTime::from_last_modification_time(&attr);
                match self.compilers.get(path) {
                    // It's a hit only if the mtime matches.
                    Some(&Some(ref c)) if c.mtime == mtime => Some(Some(c.clone())),
                    // We cache non-results.
                    Some(&None) => Some(None),
                    _ => None,
                }
            }
            Err(_) => None,
        }
    }

    /// Store `info` in the compiler info cache for `path`.
    fn cache_compiler_info(&mut self, path : String, info : &Option<Compiler>) {
        self.compilers.insert(path, info.clone());
    }

    /// Send an `UnhandledCompile` response to the client at `token`.
    ///
    /// The server only supports a fixed set of compilers, and can't
    /// cache results for certain compiler options, so `UnhandledCompile`
    /// tells the client to just run the command locally.
    fn send_unhandled_compile(&mut self, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>) {
        let mut res = ServerResponse::new();
        res.set_unhandled_compile(UnhandledCompile::new());
        match self.conns[token].send(res, event_loop) {
            Ok(_) => {}
            Err(_) => {
                error!("Failed to send response");
            }
        };
    }

    /// Send a `CompileStarted` response to the client at `token`.
    ///
    /// This indicates that the server has started a compile with
    /// the requested commandline, and will send a `CompileFinished`
    /// message when it completes.
    fn send_compile_started(&mut self, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>) {
        let mut res = ServerResponse::new();
        res.set_compile_started(CompileStarted::new());
        match self.conns[token].send(res, event_loop) {
            Ok(_) => {}
            Err(_) => {
                error!("Failed to send response");
            }
        };
    }

    fn await_cache_write(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>, future: CacheWriteFuture) {
        // This would be much nicer if we rewrote the whole server
        // event loop to use futures!
        let sender = event_loop.channel();
        //TODO: should really keep track of these somewhere...
        thread::spawn(move || {
            sender.send(ServerMessage::CacheWriteDone(match future.wait() {
                Err(e) => Err(e.description().to_owned()),
                Ok(res) => res,
            })).unwrap();
        });
    }

    /// Send a `CompileFinished` response to the client at `token`.
    ///
    /// This indicates that the server has finished running a compile,
    /// and contains the process exit status and stdout/stderr.
    fn send_compile_finished(&mut self, result: Option<(CompileResult, Output)>, token: Token, mut event_loop: &mut EventLoop<SccacheServer<C>>) {
        let mut res = ServerResponse::new();
        let mut finish = CompileFinished::new();
        match result {
            Some((compiled, out)) => {
                match compiled {
                    CompileResult::Error => self.stats.cache_errors += 1,
                    CompileResult::CacheHit => self.stats.cache_hits += 1,
                    CompileResult::CacheMiss(miss_type, future) => {
                        match miss_type {
                            MissType::Normal => self.stats.cache_misses += 1,
                            MissType::CacheReadError => self.stats.cache_read_errors += 1,
                            MissType::ForcedRecache => {
                                self.stats.cache_misses += 1;
                                self.stats.forced_recaches += 1;
                            }
                        }
                        self.await_cache_write(&mut event_loop, future)
                    }
                    CompileResult::NotCacheable => {
                        self.stats.cache_misses += 1;
                        self.stats.non_cacheable_compilations += 1;
                    }
                    CompileResult::CompileFailed => self.stats.compile_fails += 1,
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
            None => {
                self.stats.cache_errors += 1;
                //TODO: figure out a better way to communicate this?
                finish.set_retcode(-2);
            }
        };
        res.set_compile_finished(finish);
        match self.conns[token].send(res, event_loop) {
            Ok(_) => {}
            Err(_) => {
                error!("Failed to send response");
            }
        };
    }


    /// Check that `compiler` is `Some` and can handle `cmd`.
    ///
    /// If `cmd` is `Some` and does not contain unsupported options
    /// (see `compiler_commandline_ok`), send the client a `CompileStarted`
    /// message and begin compilation on a background task. Otherwise,
    /// send the client an `UnhandledCompile` message.
    fn check_compiler(&mut self, compiler: Option<Compiler>, cmd: Vec<String>, cwd: String, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>) {
        match compiler {
            None => {
                debug!("check_compiler: Unsupported compiler");
                self.stats.requests_unsupported_compiler += 1;
                self.send_unhandled_compile(token, event_loop);
            }
            Some(c) => {
                debug!("check_compiler: Supported compiler");
                // Now check that we can handle this compiler with
                // the provided commandline.
                match c.parse_arguments(&cmd) {
                    CompilerArguments::Ok(args) => {
                        self.stats.requests_executed += 1;
                        self.send_compile_started(token, event_loop);
                        self.start_compile_task(c, args, cmd, cwd, token, event_loop);
                    }
                    CompilerArguments::CannotCache => {
                        self.stats.requests_not_cacheable += 1;
                        self.send_unhandled_compile(token, event_loop);
                    }
                    CompilerArguments::NotCompilation => {
                        self.stats.requests_not_compile += 1;
                        self.send_unhandled_compile(token, event_loop);
                    }
                }
            }
        }
    }

    /// Start running `cmd` in a background task, in `cwd`.
    fn start_compile_task(&mut self, compiler: Compiler, parsed_arguments: ParsedArguments, arguments: Vec<String>, cwd: String, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>) {
        let creator = self.creator.clone();
        let storage = self.storage.clone();
        let cache_control = if self.force_recache {
            CacheControl::ForceRecache
        } else {
            CacheControl::Default
        };
        self.run_task(token, event_loop,
                      // Task, runs on a background thread.
                      move || {
                          let parsed_args = parsed_arguments;
                          let args = arguments;
                          let c = cwd;
                          let res = compiler.get_cached_or_compile(creator, storage.as_ref().as_ref(), &args, &parsed_args, &c, cache_control);
                          TaskResult::Compiled(res.ok())
                      },
                      // Callback, runs on the event loop thread.
                      move |token, res, this, event_loop| {
                          match res {
                              TaskResult::Compiled(res) => {
                                  this.send_compile_finished(res, token, event_loop);
                              },
                              TaskResult::Panic => {
                                  error!("Compile task panic!");
                                  this.send_compile_finished(None, token, event_loop);
                              },
                              _ => error!("Unexpected task result!"),
                          };
                      })
    }

    /// Handle a compile request from a client.
    ///
    /// This will either start compilation and set a `CompileStarted`
    /// response in `res`, or set an `UnhandledCompile` response in `res`.
    fn handle_compile(&mut self, token: Token, mut compile: Compile, event_loop: &mut EventLoop<SccacheServer<C>>) {
        let exe = compile.take_exe();
        let cmd = compile.take_command().into_vec();
        let cwd = compile.take_cwd();
        // See if this compiler is already in the cache.
        match self.compiler_info_cached(&exe) {
            Some(c) => {
                trace!("compiler_info cache hit");
                self.check_compiler(c, cmd, cwd, token, event_loop);
            }
            None => {
                trace!("compiler_info cache miss");
                // Run a Task to check the compiler type.
                let exe = exe.clone();
                let creator = self.creator.clone();
                self.run_task(token, event_loop,
                              // Task, runs on a background thread.
                              move || {
                                  let c = get_compiler_info(creator, &exe);
                                  TaskResult::GetCompilerInfo(exe, c)
                              },
                              // Callback, runs on the event loop thread.
                              move |token, res, this, event_loop| {
                                  match res {
                                      TaskResult::GetCompilerInfo(path, c) => {
                                          this.cache_compiler_info(path, &c);
                                          //TODO: when FnBox is stable, can use that and avoid the clones here.
                                          this.check_compiler(c.clone(), cmd.clone(), cwd.clone(), token, event_loop);
                                      },
                                      TaskResult::Panic => {
                                          error!("Compiler detection task panic!");
                                          this.send_unhandled_compile(token, event_loop);
                                      },
                                      _ => error!("Unexpected task result!"),
                                  };
                              })
            }
        }
    }

    /// Get stats about the cache.
    fn get_stats(&self) -> CacheStats {
        let mut stats = CacheStats::new();
        let mut stats_vec = self.stats.to_cache_statistics();

        let mut stat = CacheStatistic::new();
        stat.set_name(String::from("Cache location"));
        stat.set_str(self.storage.get_location());
        stats_vec.insert(0, stat);

        stats.set_stats(RepeatedField::from_vec(stats_vec));
        stats
    }

    /// Reset the server timeout on client activity.
    fn reset_idle_timer(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) {
        if let Some(timeout) = self.timeout {
            event_loop.clear_timeout(timeout);
        }
        self.timeout = event_loop.timeout_ms((), self.idle_timeout).ok();
    }

    /// Handle one request from a client and possibly send a response.
    fn handle_request(&mut self, token: Token, mut req: ClientRequest, mut event_loop: &mut EventLoop<SccacheServer<C>>) {
        trace!("handle_request");
        self.reset_idle_timer(&mut event_loop);
        if req.has_compile() {
            // This may need to do some work before even
            // sending the initial response.
            debug!("handle_client: compile");
            self.stats.compile_requests += 1;
            self.handle_compile(token, req.take_compile(), event_loop);
        } else {
            // Simple requests that can generate responses right away.
            let mut res = ServerResponse::new();
            if req.has_get_stats() {
                debug!("handle_client: get_stats");
                res.set_stats(self.get_stats());
            } else if req.has_shutdown() {
                debug!("handle_client: shutdown");
                self.initiate_shutdown(event_loop);
                let mut shutting_down = ShuttingDown::new();
                shutting_down.set_stats(self.get_stats());
                res.set_shutting_down(shutting_down);
            } else {
                warn!("handle_client: unknown command");
                res.set_unknown(UnknownCommand::new());
            }
            match self.conns[token].send(res, event_loop) {
                Ok(_) => {}
                Err(_) => {
                    error!("Failed to send response");
                }
            };
        }
    }
}

/// Results from background tasks.
pub enum TaskResult {
    /// Compiler type detection.
    GetCompilerInfo(String, Option<Compiler>),
    /// Compile finished.
    Compiled(Option<(CompileResult, Output)>),
    /// Task `panic`ed.
    Panic,
}

/// Messages that can be sent to the server by way of the event loop.
#[allow(dead_code)]
pub enum ServerMessage {
    /// Request shutdown.
    Shutdown,
    /// Background task completed.
    TaskDone { res: TaskResult, token: Token },
    /// Background cache write completed.
    CacheWriteDone(CacheWriteResult),
}

impl<C : CommandCreatorSync + 'static> Handler for SccacheServer<C> {
    type Timeout = ();
    type Message = ServerMessage;

    /// Notifications from `Sender`s, either out-of-band shutdown notifications or `Task` results.
    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        trace!("notify");
        match msg {
            ServerMessage::Shutdown => self.initiate_shutdown(event_loop),
            ServerMessage::TaskDone { res, token } => {
                trace!("TaskDone: {:?}", token);
                if self.conns.get(token).is_none() {
                    // Probably the client just hung up on us.
                    warn!("Missing client at task completion!");
                } else {
                    match self.conns[token].take_task() {
                        Some(task) => (task.callback)(token, res, self, event_loop),
                        None => {
                            //FIXME: should probably hang up on client here.
                            error!("Client missing task: {:?}", token);
                        }
                    }
                }
            }
            ServerMessage::CacheWriteDone(res) => {
                match res {
                    Err(e) => {
                        debug!("Error executing cache write: {}", e);
                        self.stats.cache_write_errors += 1;
                    }
                    //TODO: save cache stats!
                    Ok(info) => {
                        debug!("[{}]: Cache write finished in {}.{:03}s", info.object_file, info.duration.as_secs(), info.duration.subsec_nanos() / 1000);
                        self.stats.cache_writes += 1;
                        self.stats.cache_write_duration_s += info.duration.as_secs();
                        self.stats.cache_write_duration_ns += info.duration.subsec_nanos();
                    }
                }
            }
        };
    }

    /// Handle `token` being ready for I/O.
    fn ready(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>, token: Token, events: EventSet) {
        trace!("Handler::ready: events = {:?}", events);
        assert!(token != Token(0), "[BUG]: Received event for Token(0)");

        if events.is_error() {
            self.reset_connection(event_loop, token);
            return;
        }

        if events.is_hup() {
            self.reset_connection(event_loop, token);
            return;
        }

        if events.is_writable() {
            assert!(self.token != token, "Received writable event for Server");
            trace!("Writing to {:?}", token);
            //FIXME: handle this more usefully? Might just need to kill
            // the client connection in this case.
            self.conns[token].write(event_loop).unwrap_or_else(|e| error!("Error writing client response: {}", e));
        }

        if events.is_readable() {
            if self.token == token && !self.shutting_down {
                self.accept(event_loop);
            } else {
                trace!("Reading from {:?}", token);
                match { self.conns[token].read(event_loop) } {
                    Ok(Some(req)) => self.handle_request(token, req, event_loop),
                    Ok(None) => { trace!("Nothing read?"); },
                    Err(e) => { error!("Error reading client request: {}", e); }
                }
            }
        }
    }

    /// Handle the server no-activity timeout.
    fn timeout(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>, _timeout: ()) {
        info!("Hit server idle timeout, shutting down");
        self.timeout = None;
        self.initiate_shutdown(event_loop);
    }
}

/// A connection to a single sccache client.
struct ClientConnection<C : CommandCreatorSync + 'static> {
    /// Client's socket.
    sock: TcpStream,

    /// mio `Token` mapping to this client.
    token: Token,

    /// Set of events we are interested in.
    interest: EventSet,

    /// Receive buffer.
    recv_buf: Vec<u8>,

    /// Queued messages to send.
    send_queue: Vec<Vec<u8>>,

    /// In-progress task.
    task: Option<Task<C>>,
}

impl<C : CommandCreatorSync + 'static> ClientConnection<C> {
    /// Create a new `ClientConnection`.
    fn new(sock: TcpStream, token: Token) -> ClientConnection<C> {
        ClientConnection {
            sock: sock,
            token: token,
            interest: EventSet::hup(),
            // Arbitrary, should ideally hold a full `ClientRequest`.
            recv_buf: Vec::with_capacity(2048),
            send_queue: vec!(),
            task: None,
        }
    }

    /// Handle read event from event loop.
    ///
    /// If a full request was read, return `Ok(Some(ClientRequest))`.
    /// If data was read but not a full request, return `Ok(None)`.
    fn read(&mut self, event_loop : &mut EventLoop<SccacheServer<C>>) -> io::Result<Option<ClientRequest>> {
        //FIXME: use something from bytes:
        // http://carllerche.github.io/bytes/bytes/index.html
        let mut buf : [u8; 2048] = [0; 2048];
        loop {
            match self.sock.try_read(&mut buf) {
                Ok(None) => {
                    // Read all available data.
                    trace!("try_read returned Ok(None)");
                    break;
                },
                Ok(Some(n)) => {
                    trace!("try_read read {} bytes", n);
                    self.recv_buf.extend_from_slice(&buf[..n])
                },
                Err(e) => {
                    error!("Error reading from client socket: {}", e);
                    return Err(e);
                }
            }
        }

        try!(self.reregister(event_loop));

        parse_length_delimited_from_bytes::<ClientRequest>(&self.recv_buf)
            .and_then(|req| {
                self.recv_buf.drain(..(req.compute_size() as usize));
                Ok(Some(req))
            })
            .or_else(|err| match err {
                // Unexpected EOF is OK, just means we haven't read enough
                // bytes. It would be nice if this were discriminated more
                // usefully.
                // Issue filed: https://github.com/stepancheg/rust-protobuf/issues/154
                ProtobufError::WireError(s) => {
                    if s == "truncated message" {
                        Ok(None)
                    } else {
                        Err(io::Error::new(ErrorKind::Other, s))
                    }
                },
                ProtobufError::IoError(ioe) => Err(ioe),
                ProtobufError::MessageNotInitialized { message } => Err(io::Error::new(ErrorKind::Other, message)),
            })
    }

    /// Handle a writable event from the event loop.
    fn write(&mut self, event_loop : &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        //FIXME: use something from bytes.
        // http://carllerche.github.io/bytes/bytes/index.html
        match self.send_queue.first_mut() {
            None => Err(io::Error::new(ErrorKind::Other,
                                   "Could not get item from send queue")),
            Some(buf) => {
                match self.sock.try_write(buf) {
                    Ok(None) => {
                        trace!("try_write wrote no bytes?");
                        // Try again
                        Ok(None)
                    },
                    Ok(Some(n)) => {
                        trace!("try_write wrote {} bytes", n);
                        if n == buf.len() {
                            Ok(Some(()))
                        } else {
                            buf.drain(..n);
                            Ok(None)
                        }
                    },
                    Err(e) => {
                        error!("Error writing to client socket: {}", e);
                        Err(e)
                    }
                }
            },
        }
        .and_then(|res : Option<()>| {
            match res {
                Some(_) => self.send_queue.pop()
                    .and(Some(()))
                    .ok_or_else(|| io::Error::new(ErrorKind::Other,
                                      "Could not pop item from send queue")),
                _ => Ok(()),
            }
        })
        .and_then(|_| {
            if self.send_queue.is_empty() {
                self.interest.remove(EventSet::writable());
            }
            self.reregister(event_loop)
        })
    }

    /// Queue an outgoing message to the client.
    fn send(&mut self, res: ServerResponse, event_loop: &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        let msg = try!(res.write_length_delimited_to_bytes().or_else(|err| {
            error!("Error serializing message: {:?}", err);
            match err {
                ProtobufError::IoError(ioe) => Err(ioe),
                ProtobufError::WireError(s) => Err(io::Error::new(ErrorKind::Other, s)),
                ProtobufError::MessageNotInitialized { message } => Err(io::Error::new(ErrorKind::Other, message)),
            }
        }));
        trace!("ClientConnection::send: queueing {} bytes", msg.len());
        self.send_queue.push(msg);
        self.interest.insert(EventSet::writable());
        self.reregister(event_loop)
    }

    /// Set `task` as this client's current background task.
    fn set_task(&mut self, task: Task<C>) {
        self.task = Some(task);
    }

    /// Take this client's current background task.
    fn take_task(&mut self) -> Option<Task<C>> {
        self.task.take()
    }

    /// Register interest in read events with the event_loop.
    fn register(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        self.interest.insert(EventSet::readable());

        event_loop.register(
            &self.sock,
            self.token,
            self.interest,
            PollOpt::edge() | PollOpt::oneshot()
        )
    }

    /// Re-register interest in read events with the event_loop.
    fn reregister(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        trace!("ClientConnection::reregister: interest: {:?}", self.interest);
        event_loop.reregister(
            &self.sock,
            self.token,
            self.interest,
            PollOpt::edge() | PollOpt::oneshot()
        )
    }
}

/// Create an sccache server, listening on `port`, using `storage` as cache storage.
pub fn create_server<C : CommandCreatorSync + 'static>(port: u16, storage: Box<Storage>) -> io::Result<(SccacheServer<C>, EventLoop<SccacheServer<C>>)> {
    EventLoop::new()
        .or_else(|e| {
            error!("event loop creation failed: {}", e); Err(e)
        })
        .and_then(|event_loop| {
            SccacheServer::new(port, storage).and_then(|server| Ok((server, event_loop)))
        })
}

/// Run `server`, handling client connections until shutdown is requested.
pub fn run_server<C : CommandCreatorSync + 'static>(mut server : SccacheServer<C>, mut event_loop : EventLoop<SccacheServer<C>>) -> io::Result<()> {
    try!(server.register(&mut event_loop).or_else(|e| {
        error!("server event loop registration failed: {}", e);
        Err(e)
    }));
    try!(event_loop.run(&mut server).or_else(|e| {
        error!("failed to run event loop: {}", e);
        Err(e)
    }));
    Ok(())
}

/// Start an sccache server, listening on `port`.
///
/// Spins an event loop handling client connections until a client
/// requests a shutdown.
pub fn start_server(port : u16) -> io::Result<()> {
    debug!("start_server");
    let (server, event_loop) = try!(create_server::<ProcessCommandCreator>(port, storage_from_environment()).or_else(|e| {
        error!("failed to create server: {}", e);
        Err(e)
    }));
    run_server(server, event_loop)
}
