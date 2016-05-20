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

use compiler::{
    Compiler,
    CompilerArguments,
    ParsedArguments,
    get_compiler_info,
};
use filetime::FileTime;
use mio::*;
use mio::tcp::{
    TcpListener,
    TcpStream,
};
use mio::util::Slab;
use mock_command::{
    CommandCreator,
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
use std::boxed::Box;
use std::collections::HashMap;
use std::fs::metadata;
use std::io::{self,Error,ErrorKind};
use std::net::{SocketAddr, SocketAddrV4};
use std::process::Output;
use std::thread;

/// A background task.
struct Task<C : CommandCreatorSync + 'static> {
    /// A callback to call when the task finishes.
    callback: Box<Fn(Token, TaskResult, &mut SccacheServer<C>, &mut EventLoop<SccacheServer<C>>)>,
}

/// Represents an sccache server instance.
pub struct SccacheServer<C : CommandCreatorSync + 'static> {
    /// The listen socket for the server.
    sock: TcpListener,

    /// The mio `Token` for `self.sock`.
    token: Token,

    /// A list of accepted connections.
    conns: Slab<ClientConnection<C>>,

    /// True if the server is actively shutting down.
    shutting_down: bool,

    /// A cache of known compiler info.
    compilers: HashMap<String, Option<Compiler>>,

    /// An object for creating commands.
    ///
    /// This is mostly useful for unit testing, where we
    /// can mock this out.
    creator: C,
}

impl<C : CommandCreatorSync + 'static> SccacheServer<C> {
    /// Create an `SccacheServer` bound to `port`.
    fn new(port : u16) -> io::Result<SccacheServer<C>> {
        let listener = try!(TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))));
        Ok(SccacheServer {
            sock: listener,
            token: Token(1),
            conns: Slab::new_starting_at(Token(2), 128),
            shutting_down: false,
            compilers: HashMap::new(),
            creator: C::new(),
        })
    }

    /// Get the port on which this server is listening for connections.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 { self.sock.local_addr().unwrap().port() }

    /// Return a clone of the object implementing `CommandCreatorSync` that this server uses to create processes.
    ///
    /// This is intended for use in testing. In non-testing, this will
    /// just return a `ProcessCommandCreator` which is a unit struct.
    #[allow(dead_code)]
    pub fn command_creator(&self) -> C {
        self.creator.clone()
    }

    /// Register Server with the event loop.
    fn register(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        event_loop.register(
            &self.sock,
            self.token,
            EventSet::readable(),
            PollOpt::edge() | PollOpt::oneshot()
        )
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

        match self.conns.insert_with(|token| {
            ClientConnection::new(sock, token)
        }) {
            Some(token) => {
                match self.conns[token].register(event_loop) {
                    Ok(_) => {},
                    Err(_e) => {
                        self.conns.remove(token);
                    }
                }
            },
            None => {},
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
            event_loop.shutdown();
        }
    }

    /// Start server shutdown.
    ///
    /// The server will stop accepting incoming requests, and shut down
    /// after it finishes processing any in-progress requests.
    fn initiate_shutdown(&mut self, event_loop: &mut EventLoop<SccacheServer<C>>) {
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

    /// Look up compiler info from the cache for the compiler in `cmd`.
    fn compiler_info_cached(&mut self, cmd : &Vec<String>) -> Cache<Option<Compiler>> {
        trace!("compiler_info_cached");
        match cmd.first() {
            Some(path) => {
                match metadata(path) {
                    Ok(attr) => {
                        let mtime = FileTime::from_last_modification_time(&attr);
                        match self.compilers.get(path) {
                            // It's a hit only if the mtime matches.
                            Some(&Some(ref c)) if c.mtime == mtime => Cache::Hit(Some(c.clone())),
                            // We cache non-results.
                            Some(&None) => Cache::Hit(None),
                            _ => Cache::Miss,
                        }
                    }
                    Err(_) => Cache::Miss,
                }
            }
            None => {
                warn!("Got empty compile commandline?");
                Cache::Miss
            },
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

    /// Send a `CompileFinished` response to the client at `token`.
    ///
    /// This indicates that the server has finished running a compile,
    /// and contains the process exit status and stdout/stderr.
    fn send_compile_finished(&mut self, output: Option<Output>, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>) {
        let mut res = ServerResponse::new();
        let mut finish = CompileFinished::new();
        match output {
            Some(out) => {
                let Output { status, stdout, stderr } = out;
                status.code().map(|s| finish.set_retcode(s));
                //TODO: sort out getting signal return on Unix
                finish.set_stdout(stdout);
                finish.set_stderr(stderr);
            }
            None => {
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
                trace!("check_compiler: Unsupported compiler");
                self.send_unhandled_compile(token, event_loop);
            }
            Some(c) => {
                trace!("check_compiler: Supported compiler");
                // Now check that we can handle this compiler with
                // the provided commandline.
                match c.parse_arguments(&cmd[1..]) {
                    CompilerArguments::Ok(args) => {
                        self.send_compile_started(token, event_loop);
                        self.start_compile_task(c, args, cmd, cwd, token, event_loop);
                    }
                    CompilerArguments::CannotCache => {
                        self.send_unhandled_compile(token, event_loop);
                    }
                    CompilerArguments::NotCompilation => {
                        self.send_unhandled_compile(token, event_loop);
                    }
                }
            }
        }
    }

    /// Start running `cmd` in a background task, in `cwd`.
    fn start_compile_task(&mut self, compiler: Compiler, parsed_arguments: ParsedArguments, arguments: Vec<String>, cwd: String, token: Token, event_loop: &mut EventLoop<SccacheServer<C>>) {
        let creator = self.creator.clone();
        self.run_task(token, event_loop,
                      // Task, runs on a background thread.
                      move || {
                          let parsed_args = parsed_arguments;
                          let args = arguments;
                          let c = cwd;
                          let res = compiler.get_cached_or_compile(creator, &args[1..], &parsed_args, &c);
                          TaskResult::Compiled(res.ok())
                      },
                      // Callback, runs on the event loop thread.
                      move |token, res, this, event_loop| {
                          match res {
                              TaskResult::Compiled(output) => {
                                  this.send_compile_finished(output, token, event_loop);
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
        let cmd = compile.take_command().into_vec();
        let cwd = compile.take_cwd();
        // See if this compiler is already in the cache.
        match self.compiler_info_cached(&cmd) {
            Cache::Hit(c) => {
                trace!("compiler_info Cache::Hit");
                self.check_compiler(c, cmd, cwd, token, event_loop);
            }
            Cache::Miss => {
                trace!("compiler_info Cache::Miss");
                // Run a Task to check the compiler type.
                let exe = cmd.first().unwrap().clone();
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
                                      _ => error!("Unexpected task result!"),
                                  };
                              })
            }
        }
    }

    /// Handle one request from a client and possibly send a response.
    fn handle_request(&mut self, token: Token, mut req: ClientRequest, event_loop: &mut EventLoop<SccacheServer<C>>) {
        trace!("handle_request");
        if req.has_compile() {
            // This may need to do some work before even
            // sending the initial response.
            debug!("handle_client: compile");
            self.handle_compile(token, req.take_compile(), event_loop);
        } else {
            // Simple requests that can generate responses right away.
            let mut res = ServerResponse::new();
            if req.has_get_stats() {
                debug!("handle_client: get_stats");
                res.set_stats(generate_stats());
            } else if req.has_shutdown() {
                debug!("handle_client: shutdown");
                self.initiate_shutdown(event_loop);
                let mut shutting_down = ShuttingDown::new();
                shutting_down.set_stats(generate_stats());
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
    Compiled(Option<Output>),
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
}

/// Result of a cache lookup.
enum Cache<T> {
    Hit(T),
    Miss,
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
}

/// Generate cache statistics.
///
/// Currently generating bogus data.
fn generate_stats() -> CacheStats {
    //TODO: actually populate this with real data
    let mut stats = CacheStats::new();
    let mut s1 = CacheStatistic::new();
    s1.set_name("stat 1".to_owned());
    s1.set_count(1000);
    let mut s2 = CacheStatistic::new();
    s2.set_name("stat 2".to_owned());
    s2.set_str("some/value".to_owned());
    let mut s3 = CacheStatistic::new();
    s3.set_name("stat 3".to_owned());
    s3.set_size(1024 * 1024 * 1024 * 3);
    stats.set_stats(RepeatedField::from_vec(vec!(s1, s2, s3)));
    stats
}

/// A connetion to a single sccache client.
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
                        Err(Error::new(ErrorKind::Other, s))
                    }
                },
                ProtobufError::IoError(ioe) => Err(ioe),
                ProtobufError::MessageNotInitialized { message } => Err(Error::new(ErrorKind::Other, message)),
            })
    }

    /// Handle a writable event from the event loop.
    fn write(&mut self, event_loop : &mut EventLoop<SccacheServer<C>>) -> io::Result<()> {
        //FIXME: use something from bytes.
        // http://carllerche.github.io/bytes/bytes/index.html
        match self.send_queue.first_mut() {
            None => Err(Error::new(ErrorKind::Other,
                                   "Could not get item from send queue")),
            Some(buf) => {
                match self.sock.try_write(&buf) {
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
                    .ok_or(Error::new(ErrorKind::Other,
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
                ProtobufError::WireError(s) => Err(Error::new(ErrorKind::Other, s)),
                ProtobufError::MessageNotInitialized { message } => Err(Error::new(ErrorKind::Other, message)),
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

/// Create an sccache server, listening on `port`.
pub fn create_server<C : CommandCreatorSync + 'static>(port : u16) -> io::Result<(SccacheServer<C>, EventLoop<SccacheServer<C>>)> {
    EventLoop::new()
        .or_else(|e| {
            error!("event loop creation failed: {}", e); Err(e)
        })
        .and_then(|event_loop| {
            SccacheServer::new(port).and_then(|server| Ok((server, event_loop)))
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
    let (server, event_loop) = try!(create_server::<ProcessCommandCreator>(port).or_else(|e| {
        error!("failed to create server: {}", e);
        Err(e)
    }));
    run_server(server, event_loop)
}
