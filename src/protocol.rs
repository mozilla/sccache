use crate::compiler::{ColorMode, PreprocessorCacheEntry};
use crate::server::{DistInfo, ServerInfo};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

/// Protocol version for backward compatibility tracking.
///
/// Version 1: Original protocol with Compile request (server-side compilation)
/// Version 2: Extended protocol with CacheGet/CachePut (client-side compilation)
///
/// The protocol is backward compatible through enum variants:
/// - Old clients (v1) send only: ZeroStats, GetStats, DistStatus, Shutdown, Compile
/// - New clients (v2) can send all requests including: CacheGet, CachePut, etc.
/// - Old servers (v1) handle: ZeroStats, GetStats, DistStatus, Shutdown, Compile
/// - New servers (v2) handle all requests
///
/// Compatibility matrix:
/// - Old client + Old server: Works (v1 protocol)
/// - Old client + New server: Works (server supports v1 requests)
/// - New client + Old server: Client must fall back to Compile for cache operations
/// - New client + New server: Works optimally (v2 protocol with client-side compilation)
#[allow(dead_code)]
pub const PROTOCOL_VERSION: u32 = 2;

/// Legacy protocol version (server-side compilation only)
#[allow(dead_code)]
pub const PROTOCOL_VERSION_1: u32 = 1;

/// A client request.
#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    /// Zero the server's statistics.
    ZeroStats,
    /// Get server statistics.
    GetStats,
    /// Get dist status.
    DistStatus,
    /// Shut the server down gracefully.
    Shutdown,
    /// Execute a compile or fetch a cached compilation result.
    Compile(Compile),
    /// Get a cache entry by key.
    CacheGet(CacheGetRequest),
    /// Store a cache entry by key.
    CachePut(CachePutRequest),
    /// Get a preprocessor cache entry.
    PreprocessorCacheGet(String),
    /// Store a preprocessor cache entry.
    PreprocessorCachePut(PreprocessorCachePutRequest),
}

/// A server response.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    /// Response for `Request::Compile`.
    Compile(CompileResponse),
    /// Response for `Request::ZeroStats`.
    ZeroStats,
    /// Response for `Request::GetStats`, containing server statistics.
    Stats(Box<ServerInfo>),
    /// Response for `Request::DistStatus`, containing client info.
    DistStatus(DistInfo),
    /// Response for `Request::Shutdown`, containing server statistics.
    ShuttingDown(Box<ServerInfo>),
    /// Second response for `Request::Compile`, containing the results of the compilation.
    CompileFinished(CompileFinished),
    /// Response for `Request::CacheGet`.
    CacheGet(CacheGetResponse),
    /// Response for `Request::CachePut`, containing the duration of the put operation.
    CachePut(std::time::Duration),
    /// Response for `Request::PreprocessorCacheGet`.
    PreprocessorCacheGet(Option<PreprocessorCacheEntry>),
    /// Response for `Request::PreprocessorCachePut`.
    PreprocessorCachePut,
}

/// Possible responses from the server for a `Compile` request.
#[derive(Serialize, Deserialize, Debug)]
pub enum CompileResponse {
    /// The compilation was started.
    CompileStarted,
    /// The server could not handle this compilation request.
    UnhandledCompile,
    /// The compiler was not supported.
    UnsupportedCompiler(OsString),
}

/// Information about a finished compile, either from cache or executed locally.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CompileFinished {
    /// The return code of the compile process, if available.
    pub retcode: Option<i32>,
    /// The signal that terminated the compile process, if available.
    pub signal: Option<i32>,
    /// The compiler's stdout.
    pub stdout: Vec<u8>,
    /// The compiler's stderr.
    pub stderr: Vec<u8>,
    /// The state of any compiler options passed to control color output.
    pub color_mode: ColorMode,
}

/// The contents of a compile request from a client.
#[derive(Serialize, Deserialize, Debug)]
pub struct Compile {
    /// The full path to the compiler executable.
    pub exe: OsString,
    /// The current working directory in which to execute the compile.
    pub cwd: OsString,
    /// The commandline arguments passed to the compiler.
    pub args: Vec<OsString>,
    /// The environment variables present when the compiler was executed, as (var, val).
    pub env_vars: Vec<(OsString, OsString)>,
}

/// Request to get a cache entry by key.
#[derive(Serialize, Deserialize, Debug)]
pub struct CacheGetRequest {
    /// The cache key to look up.
    pub key: String,
}

/// Request to store a cache entry.
#[derive(Serialize, Deserialize, Debug)]
pub struct CachePutRequest {
    /// The cache key to store under.
    pub key: String,
    /// The cache entry data (serialized zip format).
    pub entry: Vec<u8>,
}

/// Request to store a preprocessor cache entry.
#[derive(Serialize, Deserialize, Debug)]
pub struct PreprocessorCachePutRequest {
    /// The preprocessor cache key.
    pub key: String,
    /// The preprocessor cache entry to store.
    pub entry: PreprocessorCacheEntry,
}

/// Response for a cache get request.
#[derive(Serialize, Deserialize, Debug)]
pub enum CacheGetResponse {
    /// Cache hit with the entry data (serialized zip format).
    Hit(Vec<u8>),
    /// Cache miss - entry not found.
    Miss,
    /// Error occurred during cache lookup.
    Error(String),
}

/// Protocol capability detection helpers.
impl Request {
    /// Check if this request requires protocol v2 features.
    ///
    /// Returns true for CacheGet, CachePut, and preprocessor cache requests
    /// which are only available in v2 servers.
    pub fn requires_v2(&self) -> bool {
        matches!(
            self,
            Request::CacheGet(_)
                | Request::CachePut(_)
                | Request::PreprocessorCacheGet(_)
                | Request::PreprocessorCachePut(_)
        )
    }

    /// Check if this request is compatible with protocol v1.
    ///
    /// Returns true for legacy requests that work with both old and new servers.
    pub fn is_v1_compatible(&self) -> bool {
        matches!(
            self,
            Request::ZeroStats
                | Request::GetStats
                | Request::DistStatus
                | Request::Shutdown
                | Request::Compile(_)
        )
    }
}
