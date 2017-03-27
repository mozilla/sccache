use std::ffi::OsString;

/// A client request.
#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    /// Zero the server's statistics.
    ZeroStats,
    /// Get server statistics.
    GetStats,
    /// Shut the server down gracefully.
    Shutdown,
    /// Execute a compile or fetch a cached compilation result.
    Compile(Compile),
}

/// A server response.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    /// Response for `Request::Compile`.
    Compile(CompileResponse),
    /// Response for `Request::GetStats`, containing server statistics.
    Stats(CacheStats),
    /// Response for `Request::Shutdown`, containing server statistics.
    ShuttingDown(CacheStats),
    /// Second response for `Request::Compile`, containing the results of the compilation.
    CompileFinished(CompileFinished),
}

/// Possible responses from the server for a `Compile` request.
#[derive(Serialize, Deserialize, Debug)]
pub enum CompileResponse {
    /// The compilation was started.
    CompileStarted,
    /// The server could not handle this compilation request.
    UnhandledCompile,
}

/// Server statistics.
#[derive(Serialize, Deserialize, Debug)]
pub struct CacheStats {
    /// A `Vec` of individual statistics.
    pub stats: Vec<CacheStatistic>,
}

/// A single server statistic.
#[derive(Serialize, Deserialize, Debug)]
pub struct CacheStatistic {
    /// Stat name.
    pub name: String,
    /// Stat value.
    pub value: CacheStat,
}

/// A statistic value.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum CacheStat {
    /// A count of occurrences.
    Count(u64),
    /// An opaque string, such as a name.
    String(String),
    /// A size in bytes.
    Size(u64),
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
}

/// The contents of a compile request from a client.
#[derive(Serialize, Deserialize, Debug)]
pub struct Compile {
    /// The full path to the compiler executable.
    pub exe: String,
    /// The current working directory in which to execute the compile.
    pub cwd: String,
    /// The commandline arguments passed to the compiler.
    pub args: Vec<String>,
    /// The environment variables present when the compiler was executed, as (var, val).
    pub env_vars: Vec<(OsString, OsString)>,
}
