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
    Unix(std::path::PathBuf),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    UnixAbstract(Vec<u8>),
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::Net(addr) => write!(f, "{}", addr),
            SocketAddr::Unix(p) => write!(f, "{}", p.display()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            SocketAddr::UnixAbstract(p) => write!(f, "{}", p.escape_ascii()),
        }
    }
}

impl SocketAddr {
    /// Parse a string as a unix domain socket.
    ///
    /// The string should follow the format of `self.to_string()`.
    pub fn parse_uds(s: &str) -> std::io::Result<Self> {
        // Parse abstract socket address first as it can contain any chars.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if s.starts_with('\x00') {
                let data = crate::util::ascii_unescape_default(s.as_bytes())?;
                return SocketAddr::UnixAbstract(data);
            }
        }
        let path = std::path::PathBuf::from(s);
        Ok(SocketAddr::Unix(path))
    }
}

// A helper trait to unify the behavior of TCP and UDS listener.
pub trait Acceptor {
    type Socket: AsyncRead + AsyncWrite + Unpin + Send;

    fn accept(&self) -> impl Future<Output=tokio::io::Result<Self::Socket>> + Send;
    fn local_addr(&self) -> tokio::io::Result<SocketAddr>;
}

impl Acceptor for tokio::net::TcpListener {
    type Socket = tokio::net::TcpStream;

    #[inline]
    fn accept(&self) -> impl Future<Output=tokio::io::Result<Self::Socket>> + Send {
        tokio::net::TcpListener::accept(self).and_then(|(s, _)| futures::future::ok(s))
    }

    #[inline]
    fn local_addr(&self) -> tokio::io::Result<SocketAddr> {
        tokio::net::TcpListener::local_addr(&self).map(SocketAddr::Net)
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
        SocketAddr::Net(addr) => std::net::TcpStream::connect(addr).map(|s| Box::new(s) as Box<dyn Connection>),
        #[cfg(unix)]
        SocketAddr::Unix(p) => std::os::unix::net::UnixStream::connect(p).map(|s| Box::new(s) as Box<dyn Connection>),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        SocketAddr::UnixAbstract(p) => {
            let sock = std::os::unix::net::SocketAddr::from_abstract_name(p);
            std::os::unix::net::UnixStream::connect_addr(sock).map(|s| Box::new(s) as Box<dyn Connection>)
        }
    }
}

#[cfg(unix)]
mod unix_imp {
    use std::path::PathBuf;

    use futures::TryFutureExt;

    use super::*;

    impl Acceptor for tokio::net::UnixListener {
        type Socket = tokio::net::UnixStream;

        #[inline]
        fn accept(&self) -> impl Future<Output=tokio::io::Result<Self::Socket>> + Send {
            tokio::net::UnixListener::accept(self).and_then(|(s, _)| futures::future::ok(s))
        }

        #[inline]
        fn local_addr(&self) -> tokio::io::Result<SocketAddr> {
            let addr = tokio::net::UnixListener::local_addr(self)?;
            if let Some(p) = addr.as_pathname() {
                return Ok(SocketAddr::Unix(p.to_path_buf()));
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if let Some(p) = addr.as_abstract_name() {
                return Ok(SocketAddr::UnixAbstract(p.to_vec()));
            }
            Ok(SocketAddr::Unix(PathBuf::new()))
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
