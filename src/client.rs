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

use crate::errors::*;
use crate::net::Connection;
use crate::protocol::{Request, Response};
use crate::util;
use byteorder::{BigEndian, ByteOrder};
use retry::{delay::Fixed, retry};
use std::io::{self, BufReader, BufWriter, Read};

/// A connection to an sccache server.
pub struct ServerConnection {
    /// A reader for the socket connected to the server.
    reader: BufReader<Box<dyn Connection>>,
    /// A writer for the socket connected to the server.
    writer: BufWriter<Box<dyn Connection>>,
}

impl ServerConnection {
    /// Create a new connection using `stream`.
    pub fn new(conn: Box<dyn Connection>) -> io::Result<ServerConnection> {
        let write_conn = conn.try_clone()?;
        Ok(ServerConnection {
            reader: BufReader::new(conn),
            writer: BufWriter::new(write_conn),
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
        self.reader
            .read_exact(&mut bytes)
            .context("Failed to read response header")?;
        let len = BigEndian::read_u32(&bytes);
        trace!("Should read {} more bytes", len);
        let mut data = vec![0; len as usize];
        self.reader.read_exact(&mut data)?;
        trace!("Done reading");
        Ok(bincode::deserialize(&data)?)
    }
}

/// Establish a TCP connection to an sccache server listening on `addr`.
pub fn connect_to_server(addr: &crate::net::SocketAddr) -> io::Result<ServerConnection> {
    trace!("connect_to_server({addr})");
    let conn = crate::net::connect(addr)?;
    ServerConnection::new(conn)
}

/// Attempt to establish a TCP connection to an sccache server listening on `addr`.
///
/// If the connection fails, retry a few times.
pub fn connect_with_retry(addr: &crate::net::SocketAddr) -> io::Result<ServerConnection> {
    trace!("connect_with_retry({addr})");
    // TODOs:
    // * Pass the server Child in here, so we can stop retrying
    //   if the process exited.
    // * Send a pipe handle to the server process so it can notify
    //   us once it starts the server instead of us polling.
    match retry(Fixed::from_millis(500).take(10), || connect_to_server(addr)) {
        Ok(conn) => Ok(conn),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Connection to server timed out: {:?}", e),
        )),
    }
}
