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

use protobuf::{Message,ProtobufResult,parse_from_reader};
use protocol::{
    ClientRequest,
    ServerResponse,
};
use retry::retry;
use std::io;
use std::net::{Shutdown,TcpStream};

/// A connection to an sccache server.
pub struct ServerConnection {
    /// The socket connected to the server.
    stream : TcpStream,
}

impl ServerConnection {
    /// Send `request` to the server, read and return a `ServerResponse`.
    pub fn request(&mut self, request : ClientRequest)
                   -> ProtobufResult<ServerResponse> {
        println!("ServerConnection::request");
        try!(request.write_to_writer(&mut self.stream));
        //TODO: propogate error
        self.stream.shutdown(Shutdown::Write).unwrap();
        println!("ServerConnection::request: sent request, reading response");
        parse_from_reader::<ServerResponse>(&mut self.stream)
    }
}

/// Establish a TCP connection to an sccache server listening on `port`.
pub fn connect_to_server(port : u16) -> io::Result<ServerConnection> {
    let stream = try!(TcpStream::connect(("127.0.0.1", port)));
    Ok(ServerConnection { stream : stream })
}

/// Attempt to establish a TCP connection to an sccache server listening on `port`.
///
/// If the connection fails, retry a few times.
pub fn connect_with_retry(port : u16) -> io::Result<ServerConnection> {
    // TODOs:
    // * Pass the server Child in here, so we can stop retrying
    //   if the process exited.
    // * Send a pipe handle to the server process so it can notify
    //   us once it starts the server instead of us polling.
    match retry(10, 1, || connect_to_server(port), |res| res.is_ok()) {
        Ok(Ok(conn)) => Ok(conn),
        _ => Err(io::Error::new(io::ErrorKind::TimedOut,
                                "Connection to server timed out")),
    }
}
