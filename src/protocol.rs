use crate::cache::{CacheMode, GetPathResult};
use crate::compiler::ColorMode;
use crate::config::PreprocessorCacheModeConfig;
use crate::server::{DistInfo, ServerInfo, ServerStats};
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

    // --- Storage RPCs (client-side mode) ---
    /// One-shot handshake: client requests cache metadata from the daemon.
    StorageHandshake,
    /// Fetch the filesystem path of the cached entry for `key`.
    /// Reports a missing key, unsupported direct file access, or a lookup error.
    StorageGetPath { key: String },
    /// Fetch raw (zip) bytes for `key`; returns `None` on a miss.
    StorageGetRaw { key: String },
    /// Store raw (zip) bytes under `key`.
    StoragePutRaw { key: String, data: Vec<u8> },
    /// Retrieve the preprocessor cache entry for `key`.
    StorageGetPreprocessorEntry { key: String },
    /// Store or overwrite the preprocessor cache entry for `key`.
    StoragePutPreprocessorEntry { key: String, entry_bytes: Vec<u8> },
    /// Merge per-invocation stats into the daemon's running totals.
    RecordStats(Box<ServerStats>),
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

    // --- Storage RPC responses (client-side mode) ---
    /// Response for `Request::StorageHandshake`.
    StorageHandshake(StorageHandshakeInfo),
    /// Response for `Request::StorageGetPath`.
    StorageGetPath(GetPathResult),
    /// Response for `Request::StorageGetRaw`: zip bytes on hit, `None` on miss.
    StorageGetRaw(Option<Vec<u8>>),
    /// Response for `Request::StoragePutRaw`.
    StoragePutRaw(Result<(), String>),
    /// Response for `Request::StorageGetPreprocessorEntry`.
    StorageGetPreprocessorEntry(Result<Option<Vec<u8>>, String>),
    /// Response for `Request::StoragePutPreprocessorEntry`.
    StoragePutPreprocessorEntry(Result<(), String>),
    /// Response for `Request::RecordStats`.
    RecordStats,

    /// A rustc artifact notification delivered while the compiler is still running.
    ///
    /// The line also stays in [`CompileFinished::stderr`].
    /// The client that has forwarded the notification must drop that copy.
    ///
    /// Currently only `.rmeta` notifications are sent (for Cargo pipelining).
    ArtifactNotification(Vec<u8>),

    // Append new variants to preserve bincode's existing response discriminants.
    /// A failed `StorageGetPath` or `StorageGetRaw` lookup.
    StorageReadError(String),
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

/// Cache metadata returned by the daemon on `StorageHandshake`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageHandshakeInfo {
    pub location: String,
    pub cache_type_name: String,
    pub basedirs: Vec<Vec<u8>>,
    pub preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
    pub cache_mode: CacheMode,
    pub max_size: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Freeze the schema before StorageReadError to exercise mixed-build replies.
    #[derive(Serialize, Deserialize, Debug)]
    enum LegacyResponse {
        Compile(CompileResponse),
        ZeroStats,
        Stats(Box<ServerInfo>),
        DistStatus(DistInfo),
        ShuttingDown(Box<ServerInfo>),
        CompileFinished(CompileFinished),
        StorageHandshake(StorageHandshakeInfo),
        StorageGetPath(GetPathResult),
        StorageGetRaw(Option<Vec<u8>>),
        StoragePutRaw(Result<(), String>),
        StorageGetPreprocessorEntry(Result<Option<Vec<u8>>, String>),
        StoragePutPreprocessorEntry(Result<(), String>),
        RecordStats,
        ArtifactNotification(Vec<u8>),
    }

    #[test]
    fn storage_raw_replies_preserve_legacy_hits_and_misses() {
        for expected in [None, Some(vec![1, 2, 3])] {
            let old = bincode::serialize(&LegacyResponse::StorageGetRaw(expected.clone())).unwrap();
            let new = bincode::serialize(&Response::StorageGetRaw(expected.clone())).unwrap();
            assert_eq!(old, new);

            let LegacyResponse::StorageGetRaw(actual) = bincode::deserialize(&new).unwrap() else {
                panic!("expected a legacy raw lookup reply");
            };
            assert_eq!(actual, expected);
            let Response::StorageGetRaw(actual) = bincode::deserialize(&old).unwrap() else {
                panic!("expected a raw lookup reply");
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn storage_path_replies_preserve_legacy_outcomes() {
        for expected in [
            GetPathResult::Found("cache.zip".into()),
            GetPathResult::Miss,
            GetPathResult::Unsupported,
        ] {
            let old =
                bincode::serialize(&LegacyResponse::StorageGetPath(expected.clone())).unwrap();
            let new = bincode::serialize(&Response::StorageGetPath(expected.clone())).unwrap();
            assert_eq!(old, new);

            let LegacyResponse::StorageGetPath(old_client) = bincode::deserialize(&new).unwrap()
            else {
                panic!("expected a legacy path lookup reply");
            };
            let Response::StorageGetPath(new_client) = bincode::deserialize(&old).unwrap() else {
                panic!("expected a path lookup reply");
            };
            for actual in [old_client, new_client] {
                match (&expected, actual) {
                    (GetPathResult::Found(expected), GetPathResult::Found(actual)) => {
                        assert_eq!(*expected, actual);
                    }
                    (GetPathResult::Miss, GetPathResult::Miss)
                    | (GetPathResult::Unsupported, GetPathResult::Unsupported) => {}
                    (_, actual) => panic!("expected {expected:?}, got {actual:?}"),
                }
            }
        }
    }

    #[test]
    fn storage_read_errors_are_not_legacy_misses() {
        let bytes =
            bincode::serialize(&Response::StorageReadError("backend read failed".into())).unwrap();
        assert!(bincode::deserialize::<LegacyResponse>(&bytes).is_err());
        let Response::StorageReadError(error) = bincode::deserialize(&bytes).unwrap() else {
            panic!("expected a storage read error");
        };
        assert_eq!(error, "backend read failed");
    }
}
