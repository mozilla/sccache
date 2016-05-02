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
    can_handle_compile,
};
use mio::*;
use mio::tcp::{
    TcpListener,
    TcpStream,
};
use mio::util::Slab;
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
    ServerResponse,
    ShuttingDown,
    UnhandledCompile,
    UnknownCommand,
};
use std::io::{self,Error,ErrorKind};
use std::net::{SocketAddr, SocketAddrV4};

/// Represents an sccache server instance.
pub struct SccacheServer {
    /// The listen socket for the server.
    sock: TcpListener,

    /// The mio `Token` for `self.sock`.
    token: Token,

    /// A list of accepted connections.
    conns: Slab<ClientConnection>,

    /// True if the server is actively shutting down.
    shutting_down: bool,
}

impl SccacheServer {
    /// Create an `SccacheServer` bound to `port`.
    fn new(port : u16) -> io::Result<SccacheServer> {
        let listener = try!(TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))));
        Ok(SccacheServer {
            sock: listener,
            token: Token(1),
            conns: Slab::new_starting_at(Token(2), 128),
            shutting_down: false,
        })
    }

    /// Get the port on which this server is listening for connections.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 { self.sock.local_addr().unwrap().port() }

    /// Register Server with the event loop.
    fn register(&mut self, event_loop: &mut EventLoop<SccacheServer>) -> io::Result<()> {
        event_loop.register(
            &self.sock,
            self.token,
            EventSet::readable(),
            PollOpt::edge() | PollOpt::oneshot()
        )
    }

    /// Re-register Server with the event loop.
    fn reregister(&mut self, event_loop: &mut EventLoop<SccacheServer>) {
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
    fn accept(&mut self, event_loop: &mut EventLoop<SccacheServer>) {
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
    fn reset_connection(&mut self, event_loop: &mut EventLoop<SccacheServer>, token: Token) {
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
    fn check_shutdown(&mut self, event_loop: &mut EventLoop<SccacheServer>) {
        if self.shutting_down && self.conns.is_empty() {
            // All done.
            event_loop.shutdown();
        }
    }

    /// Start server shutdown.
    ///
    /// The server will stop accepting incoming requests, and shut down
    /// after it finishes processing any in-progress requests.
    fn initiate_shutdown(&mut self, event_loop: &mut EventLoop<SccacheServer>) {
        if !self.shutting_down {
            self.shutting_down = true;
        }
        self.check_shutdown(event_loop);
    }

    /// Handle a compile request from a client.
    ///
    /// This will either start compilation and set a `CompileStarted`
    /// response in `res`, or set an `UnhandledCompile` response in `res`.
    fn handle_compile(&mut self, _token: Token, mut compile: Compile, res: &mut ServerResponse, _event_loop: &mut EventLoop<SccacheServer>) {
        let cmd = compile.take_command().into_vec();
        match can_handle_compile(&cmd) {
            Some(_compiler) => {
                //TODO: check cache, run compile, etc
            }
            None => {
                res.set_unhandled_compile(UnhandledCompile::new());
            }
        }
    }

    /// Handle one request from a client and send a response.
    fn handle_request(&mut self, token: Token, mut req: ClientRequest, event_loop: &mut EventLoop<SccacheServer>) {
        trace!("handle_request");
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
        } else if req.has_compile() {
            debug!("handle_client: compile");
            self.handle_compile(token, req.take_compile(), &mut res, event_loop);
        } else {
            warn!("handle_client: unknown command");
            res.set_unknown(UnknownCommand::new());
        }
        match self.conns[token].send(res, event_loop) {
            Ok(_) => {}
            Err(_) => {} // should at least log this
        };
    }
}

/// Messages that can be sent to the server by way of the event loop.
#[allow(dead_code)]
pub enum ServerMessage {
    /// Request shutdown.
    Shutdown,
}

impl Handler for SccacheServer {
    type Timeout = ();
    type Message = ServerMessage;

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        match msg {
            ServerMessage::Shutdown => self.initiate_shutdown(event_loop),
        }
    }

    fn ready(&mut self, event_loop: &mut EventLoop<SccacheServer>, token: Token, events: EventSet) {
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

        // We never expect a write event for our `Server` token . A write event for any other token
        // should be handed off to that connection.
        if events.is_writable() {
            assert!(self.token != token, "Received writable event for Server");
            //XXX: should handle this more usefully
            trace!("Writing to {:?}", token);
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
struct ClientConnection {
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
}

impl ClientConnection {
    /// Create a new `ClientConnection`.
    fn new(sock: TcpStream, token: Token) -> ClientConnection {
        ClientConnection {
            sock: sock,
            token: token,
            interest: EventSet::hup(),
            // Arbitrary, should ideally hold a full `ClientRequest`.
            recv_buf: Vec::with_capacity(2048),
            send_queue: vec!(),
        }
    }

    /// Handle read event from event loop.
    ///
    /// If a full request was read, return `Ok(Some(ClientRequest))`.
    /// If data was read but not a full request, return `Ok(None)`.
    fn read(&mut self, event_loop : &mut EventLoop<SccacheServer>) -> io::Result<Option<ClientRequest>> {
        //FIXME: use something from bytes
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
                ProtobufError::WireError(s) => {
                    if s == "truncated message" {
                        Ok(None)
                    } else {
                        Err(Error::new(ErrorKind::Other, s))
                    }
                },
                ProtobufError::IoError(ioe) => Err(ioe),
            })
    }

    /// Handle a writable event from the event loop.
    fn write(&mut self, event_loop : &mut EventLoop<SccacheServer>) -> io::Result<()> {
        //FIXME: this is gross, should use something from bytes.
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
    fn send(&mut self, res: ServerResponse, event_loop: &mut EventLoop<SccacheServer>) -> io::Result<()> {
        let msg = try!(res.write_length_delimited_to_bytes().or_else(|err| {
            error!("Error serializing message: {:?}", err);
            match err {
                ProtobufError::IoError(ioe) => Err(ioe),
                ProtobufError::WireError(s) => Err(Error::new(ErrorKind::Other, s)),
            }
        }));
        trace!("ClientConnection::send: queueing {} bytes", msg.len());
        self.send_queue.push(msg);
        self.interest.insert(EventSet::writable());
        self.reregister(event_loop)
    }

    /// Register interest in read events with the event_loop.
    fn register(&mut self, event_loop: &mut EventLoop<SccacheServer>) -> io::Result<()> {
        self.interest.insert(EventSet::readable());

        event_loop.register(
            &self.sock,
            self.token,
            self.interest,
            PollOpt::edge() | PollOpt::oneshot()
        )
    }

    /// Re-register interest in read events with the event_loop.
    fn reregister(&mut self, event_loop: &mut EventLoop<SccacheServer>) -> io::Result<()> {
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
pub fn create_server(port : u16) -> io::Result<(SccacheServer, EventLoop<SccacheServer>)> {
    EventLoop::new()
        .or_else(|e| {
            error!("event loop creation failed: {}", e); Err(e)
        })
        .and_then(|event_loop| {
            SccacheServer::new(port).and_then(|server| Ok((server, event_loop)))
        })
}

/// Run `server`, handling client connections until shutdown is requested.
pub fn run_server(mut server : SccacheServer, mut event_loop : EventLoop<SccacheServer>) -> io::Result<()> {
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
    let (server, event_loop) = try!(create_server(port).or_else(|e| {
        error!("failed to create server: {}", e);
        Err(e)
    }));
    run_server(server, event_loop)
}
