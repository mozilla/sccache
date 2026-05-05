use crate::cache::FileObjectSource;
use crate::compiler::ColorMode;
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
    /// Response for `Request::CachePut`.
    CachePut(CachePutResponse),
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
///
/// The server extracts output artifacts directly to `output_paths` on a hit,
/// so no large data ever crosses the IPC channel.
#[derive(Serialize, Deserialize, Debug)]
pub struct CacheGetRequest {
    /// The cache key to look up.
    pub key: String,
    /// Where to extract output artifacts on a cache hit.
    pub output_paths: Vec<FileObjectSource>,
}

/// Request to store a cache entry.
///
/// The server reads the output artifacts from `output_paths` directly from
/// disk (client and server share the same filesystem). Only stdout/stderr
/// (typically small) are sent over the IPC channel.
#[derive(Serialize, Deserialize, Debug)]
pub struct CachePutRequest {
    /// The cache key to store under.
    pub key: String,
    /// Paths to the output artifacts the server should pack into the entry.
    pub output_paths: Vec<FileObjectSource>,
    /// The compiler's stdout.
    pub stdout: Vec<u8>,
    /// The compiler's stderr.
    pub stderr: Vec<u8>,
}

/// Response for a cache get request.
///
/// On a hit the server has already extracted the artifacts to the paths
/// supplied in the request; the response carries only stdout/stderr.
#[derive(Serialize, Deserialize, Debug)]
pub enum CacheGetResponse {
    /// Cache hit – artifacts extracted to the requested paths.
    Hit { stdout: Vec<u8>, stderr: Vec<u8> },
    /// Cache miss – entry not found.
    Miss,
    /// Error occurred during cache lookup.
    Error(String),
}

/// Response for a cache put request.
#[derive(Serialize, Deserialize, Debug)]
pub enum CachePutResponse {
    /// Cache entry stored successfully.
    Success,
    /// Error occurred during cache storage (best-effort, not fatal).
    Error(String),
}
