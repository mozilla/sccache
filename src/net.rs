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

//! The module is used to provide abstraction over TCP socket and UDS.

use std::fmt;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::linux::net::SocketAddrExt;

use futures::{Future, TryFutureExt};
use tokio::io::{AsyncRead, AsyncWrite};

// A unify version of `std::net::SocketAddr` and Unix domain socket.
#[derive(Debug)]
pub enum SocketAddr {
    Net(std::net::SocketAddr),
    // This could work on Windows in the future. See also rust-lang/rust#56533.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    UnixAbstract(Vec<u8>),
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::Net(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            SocketAddr::Unix(p) => write!(f, "{}", p.display()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            SocketAddr::UnixAbstract(p) => write!(f, "\\x00{}", p.escape_ascii()),
        }
    }
}

impl SocketAddr {
    /// Get a Net address that with IP part set to "127.0.0.1".
    #[inline]
    pub fn with_port(port: u16) -> Self {
        SocketAddr::Net(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    }

    #[inline]
    pub fn as_net(&self) -> Option<&std::net::SocketAddr> {
        match self {
            SocketAddr::Net(addr) => Some(addr),
            #[cfg(unix)]
            _ => None,
        }
    }

    /// Parse a string as a unix domain socket.
    ///
    /// The string should follow the format of `self.to_string()`.
    #[cfg(unix)]
    pub fn parse_uds(s: &str) -> std::io::Result<Self> {
        // Parse abstract socket address first as it can contain any chars.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if s.starts_with("\\x00") {
                // Rust abstract path expects no prepand '\x00'.
                let data = crate::util::ascii_unescape_default(&s.as_bytes()[4..])?;
                return Ok(SocketAddr::UnixAbstract(data));
            }
        }
        let path = std::path::PathBuf::from(s);
        Ok(SocketAddr::Unix(path))
    }

    #[cfg(unix)]
    pub fn is_unix_path(&self) -> bool {
        matches!(self, SocketAddr::Unix(_))
    }

    #[cfg(not(unix))]
    pub fn is_unix_path(&self) -> bool {
        false
    }
}

// A helper trait to unify the behavior of TCP and UDS listener.
pub trait Acceptor {
    type Socket: AsyncRead + AsyncWrite + Unpin + Send;

    fn accept(&self) -> impl Future<Output = tokio::io::Result<Self::Socket>> + Send;
    fn local_addr(&self) -> tokio::io::Result<Option<SocketAddr>>;
}

impl Acceptor for tokio::net::TcpListener {
    type Socket = tokio::net::TcpStream;

    #[inline]
    fn accept(&self) -> impl Future<Output = tokio::io::Result<Self::Socket>> + Send {
        tokio::net::TcpListener::accept(self).and_then(|(s, _)| futures::future::ok(s))
    }

    #[inline]
    fn local_addr(&self) -> tokio::io::Result<Option<SocketAddr>> {
        tokio::net::TcpListener::local_addr(self).map(|a| Some(SocketAddr::Net(a)))
    }
}

// A helper trait to unify the behavior of TCP and UDS stream.
pub trait Connection: std::io::Read + std::io::Write {
    fn try_clone(&self) -> std::io::Result<Box<dyn Connection>>;
}

impl Connection for std::net::TcpStream {
    #[inline]
    fn try_clone(&self) -> std::io::Result<Box<dyn Connection>> {
        let stream = std::net::TcpStream::try_clone(self)?;
        Ok(Box::new(stream))
    }
}

// Helper function to create a stream. Uses dynamic dispatch to make code more
// readable.
pub fn connect(addr: &SocketAddr) -> std::io::Result<Box<dyn Connection>> {
    match addr {
        SocketAddr::Net(addr) => {
            std::net::TcpStream::connect(addr).map(|s| Box::new(s) as Box<dyn Connection>)
        }
        #[cfg(unix)]
        SocketAddr::Unix(p) => {
            std::os::unix::net::UnixStream::connect(p).map(|s| Box::new(s) as Box<dyn Connection>)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        SocketAddr::UnixAbstract(p) => {
            let sock = std::os::unix::net::SocketAddr::from_abstract_name(p)?;
            std::os::unix::net::UnixStream::connect_addr(&sock)
                .map(|s| Box::new(s) as Box<dyn Connection>)
        }
    }
}

#[cfg(unix)]
mod unix_imp {
    use futures::TryFutureExt;

    use super::*;

    impl Acceptor for tokio::net::UnixListener {
        type Socket = tokio::net::UnixStream;

        #[inline]
        fn accept(&self) -> impl Future<Output = tokio::io::Result<Self::Socket>> + Send {
            tokio::net::UnixListener::accept(self).and_then(|(s, _)| futures::future::ok(s))
        }

        #[inline]
        fn local_addr(&self) -> tokio::io::Result<Option<SocketAddr>> {
            let addr = tokio::net::UnixListener::local_addr(self)?;
            if let Some(p) = addr.as_pathname() {
                return Ok(Some(SocketAddr::Unix(p.to_path_buf())));
            }
            // TODO: support get addr from abstract socket.
            // tokio::net::SocketAddr needs to support `as_abstract_name`.
            // #[cfg(any(target_os = "linux", target_os = "android"))]
            // if let Some(p) = addr.0.as_abstract_name() {
            //     return Ok(SocketAddr::UnixAbstract(p.to_vec()));
            // }
            Ok(None)
        }
    }

    impl Connection for std::os::unix::net::UnixStream {
        #[inline]
        fn try_clone(&self) -> std::io::Result<Box<dyn Connection>> {
            let stream = std::os::unix::net::UnixStream::try_clone(self)?;
            Ok(Box::new(stream))
        }
    }
}
