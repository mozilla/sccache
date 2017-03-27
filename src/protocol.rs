#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    ZeroStats,
    GetStats,
    Shutdown,
    Compile(Compile),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Compile(CompileResponse),
    Stats(CacheStats),
    ShuttingDown(CacheStats),
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

#[derive(Serialize, Deserialize, Debug)]
pub struct CacheStats {
    pub stats: Vec<CacheStatistic>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CacheStatistic {
    pub name: String,
    pub value: CacheStat,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum CacheStat {
    Count(u64),
    String(String),
    Size(u64),
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CompileFinished {
    pub retcode: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Compile {
    pub exe: String,
    pub cwd: String,
    pub args: Vec<String>,
}
