use crate::compiler::{ColorMode, PreprocessorCacheEntry};
use crate::server::{DistInfo, ServerInfo};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

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
