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

use crate::cache::CacheMode;
use crate::cache::GetPathResult;
use crate::cache::cache::Storage;
use crate::cache::cache_io::{Cache, CacheRead, CacheWrite};
use crate::client::ServerConnection;
use crate::compiler::PreprocessorCacheEntry;
use crate::config::PreprocessorCacheModeConfig;
use crate::errors::*;
use crate::protocol::{Request, Response, StorageHandshakeInfo};
use async_trait::async_trait;
use bytes::Bytes;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `Storage` implementation that forwards all cache operations to the sccache
/// daemon over the existing IPC connection.  Used by CLI processes in
/// client-side mode.
///
/// `ServerConnection` is synchronous and non-`Clone`, so it lives behind a
/// `Mutex` and every RPC dispatches via `tokio::task::spawn_blocking`.  The
/// lock is held only for the duration of a single blocking call, never across
/// an `.await` point.
pub struct IpcStorage {
    conn: Arc<Mutex<ServerConnection>>,
    handshake: StorageHandshakeInfo,
}

impl IpcStorage {
    /// Connect to the daemon and perform the `StorageHandshake` RPC.
    /// Returns an `IpcStorage` that can be used as an `Arc<dyn Storage>`.
    pub fn connect(mut conn: ServerConnection) -> Result<Self> {
        let resp = conn.request(Request::StorageHandshake)?;
        let handshake = match resp {
            Response::StorageHandshake(info) => info,
            other => bail!("IpcStorage: unexpected handshake response: {other:?}"),
        };
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            handshake,
        })
    }

    /// Return a clone of the underlying connection handle so callers can send
    /// additional RPCs (e.g., `RecordStats`) after the storage is no longer
    /// needed.
    pub fn conn(&self) -> Arc<Mutex<ServerConnection>> {
        Arc::clone(&self.conn)
    }

    async fn rpc(&self, req: Request) -> Result<Response> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || conn.lock().unwrap().request(req))
            .await
            .context("spawn_blocking panicked")?
    }
}

#[async_trait]
impl Storage for IpcStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        match self.get_path(key).await {
            GetPathResult::Found(path) => {
                let file = std::fs::File::open(&path)
                    .with_context(|| format!("IpcStorage::get: open {}", path.display()))?;
                match CacheRead::from(file) {
                    Ok(entry) => Ok(Cache::Hit(entry)),
                    Err(_) => Ok(Cache::Miss),
                }
            }
            GetPathResult::Miss => Ok(Cache::Miss),
            // Backend doesn't support paths (S3, Redis, …); fall back to bytes over IPC.
            GetPathResult::Unsupported => match self.get_raw(key).await? {
                Some(bytes) => match CacheRead::from(Cursor::new(bytes)) {
                    Ok(entry) => Ok(Cache::Hit(entry)),
                    Err(_) => Ok(Cache::Miss),
                },
                None => Ok(Cache::Miss),
            },
        }
    }

    async fn get_path(&self, key: &str) -> GetPathResult {
        match self
            .rpc(Request::StorageGetPath {
                key: key.to_owned(),
            })
            .await
        {
            Ok(Response::StorageGetPath(result)) => result,
            _ => GetPathResult::Unsupported,
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        self.put_raw(key, entry.finish()?.into()).await
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        let resp = self
            .rpc(Request::StorageGetRaw {
                key: key.to_owned(),
            })
            .await?;
        match resp {
            Response::StorageGetRaw(opt) => Ok(opt.map(Bytes::from)),
            other => bail!("IpcStorage::get_raw: unexpected response: {other:?}"),
        }
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        let resp = self
            .rpc(Request::StoragePutRaw {
                key: key.to_owned(),
                data: data.to_vec(),
            })
            .await?;
        match resp {
            Response::StoragePutRaw(Ok(())) => Ok(Duration::ZERO),
            Response::StoragePutRaw(Err(e)) => bail!("IpcStorage::put_raw: daemon error: {e}"),
            other => bail!("IpcStorage::put_raw: unexpected response: {other:?}"),
        }
    }

    async fn check(&self) -> Result<CacheMode> {
        Ok(self.handshake.cache_mode)
    }

    fn location(&self) -> String {
        self.handshake.location.clone()
    }

    fn cache_type_name(&self) -> &'static str {
        "ipc"
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(self.handshake.max_size)
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.handshake.preprocessor_cache_mode_config
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.handshake.basedirs
    }

    async fn get_preprocessor_cache_entry(
        &self,
        key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        let resp = self
            .rpc(Request::StorageGetPreprocessorEntry {
                key: key.to_owned(),
            })
            .await?;
        match resp {
            Response::StorageGetPreprocessorEntry(Ok(None)) => Ok(None),
            Response::StorageGetPreprocessorEntry(Ok(Some(bytes))) => Ok(Some(
                Box::new(Cursor::new(bytes)) as Box<dyn crate::lru_disk_cache::ReadSeek>,
            )),
            Response::StorageGetPreprocessorEntry(Err(e)) => {
                bail!("IpcStorage::get_preprocessor_cache_entry: {e}")
            }
            other => {
                bail!("IpcStorage::get_preprocessor_cache_entry: unexpected response: {other:?}")
            }
        }
    }

    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        let mut buf = vec![];
        entry
            .serialize_to(&mut buf)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let resp = self
            .rpc(Request::StoragePutPreprocessorEntry {
                key: key.to_owned(),
                entry_bytes: buf,
            })
            .await?;
        match resp {
            Response::StoragePutPreprocessorEntry(Ok(())) => Ok(()),
            Response::StoragePutPreprocessorEntry(Err(e)) => {
                bail!("IpcStorage::put_preprocessor_cache_entry: {e}")
            }
            other => {
                bail!("IpcStorage::put_preprocessor_cache_entry: unexpected response: {other:?}")
            }
        }
    }
}
