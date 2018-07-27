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

use byteorder::{ByteOrder, BigEndian};
use protocol::{Request, Response};
use retry::retry;
use bincode;
use errors::*;
use std::io::{
    self,
    BufReader,
    BufWriter,
    Read,
};
use std::net::TcpStream;
use util;

/// A connection to an sccache server.
pub struct ServerConnection {
    /// A reader for the socket connected to the server.
    reader : BufReader<TcpStream>,
    /// A writer for the socket connected to the server.
    writer : BufWriter<TcpStream>,
}

impl ServerConnection {
    /// Create a new connection using `stream`.
    pub fn new(stream : TcpStream) -> io::Result<ServerConnection> {
        let writer = stream.try_clone()?;
        Ok(ServerConnection {
            reader : BufReader::new(stream),
            writer : BufWriter::new(writer),
        })
    }

    /// Send `request` to the server, read and return a `Response`.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        trace!("ServerConnection::request");
        util::write_length_prefixed_bincode(&mut self.writer, request)?;
        trace!("ServerConnection::request: sent request");
        self.read_one_response()
    }

    /// Read a single `Response` from the server.
    pub fn read_one_response(&mut self) -> Result<Response> {
        trace!("ServerConnection::read_one_response");
        let mut bytes = [0; 4];
        self.reader.read_exact(&mut bytes).chain_err(|| "Failed to read response header")?;
        let len = BigEndian::read_u32(&bytes);
        trace!("Should read {} more bytes", len);
        let mut data = vec![0; len as usize];
        self.reader.read_exact(&mut data)?;
        trace!("Done reading");
        Ok(bincode::deserialize(&data)?)
    }
}

/// Establish a TCP connection to an sccache server listening on `port`.
pub fn connect_to_server(port: u16) -> io::Result<ServerConnection> {
    trace!("connect_to_server({})", port);
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    ServerConnection::new(stream)
}

/// Attempt to establish a TCP connection to an sccache server listening on `port`.
///
/// If the connection fails, retry a few times.
pub fn connect_with_retry(port: u16) -> io::Result<ServerConnection> {
    trace!("connect_with_retry({})", port);
    // TODOs:
    // * Pass the server Child in here, so we can stop retrying
    //   if the process exited.
    // * Send a pipe handle to the server process so it can notify
    //   us once it starts the server instead of us polling.
    match retry(10, 500, || connect_to_server(port), |res| res.is_ok()) {
        Ok(Ok(conn)) => Ok(conn),
        _ => Err(io::Error::new(io::ErrorKind::TimedOut,
                                "Connection to server timed out")),
    }
}
