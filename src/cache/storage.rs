// Copyright 2026 Mozilla Foundation
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

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::cache::cache_io::{Cache, CacheMode, CacheRead, CacheWrite};
use crate::cache::multilevel::MultiLevelStats;
#[cfg(any_cache_remote)]
use crate::cache::utils::normalize_key;
use crate::compiler::PreprocessorCacheEntry;
use crate::config::PreprocessorCacheModeConfig;
use crate::errors::*;

/// Result of [`Storage::get_path`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GetPathResult {
    /// Cache hit: the entry lives at this filesystem path.
    Found(PathBuf),
    /// Cache miss: the key is not in the cache.
    Miss,
    /// This backend does not support direct file access; use `get`/`get_raw` instead.
    Unsupported,
}

/// An interface to cache storage.
#[async_trait]
pub trait CacheStorage: Send + Sync {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    async fn get(&self, key: &str) -> Result<Cache>;

    /// Get a parsed cache entry and, when supported, the same entry's raw bytes.
    ///
    /// Multi-level caches use the raw bytes to backfill faster levels. The
    /// default preserves compatibility with existing backends by retaining
    /// the historical second `get_raw()` call; raw-capable backends can
    /// override this to avoid reading a hit twice.
    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        let cache = self.get(key).await?;
        let raw = if matches!(&cache, Cache::Hit(_)) {
            match self.get_raw(key).await {
                Ok(raw) => raw,
                Err(error) => {
                    debug!("Failed to get raw bytes for cache backfill: {}", error);
                    None
                }
            }
        } else {
            None
        };
        Ok((cache, raw))
    }

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration>;

    /// Get raw serialized cache entry bytes by `key` (for multi-level backfill).
    /// Returns `None` if the entry is not found, or if the implementation doesn't support raw access.
    /// This is used by multi-level caches to backfill faster levels.
    async fn get_raw(&self, _key: &str) -> Result<Option<Bytes>> {
        Ok(None)
    }

    /// Put raw serialized cache entry bytes under `key` (for multi-level backfill).
    /// Returns an error if the implementation doesn't support raw access.
    /// This is used by multi-level caches to backfill faster levels.
    async fn put_raw(&self, _key: &str, _data: Bytes) -> Result<Duration> {
        Err(anyhow!("put_raw not implemented for this storage backend"))
    }

    /// Check the cache capability.
    ///
    /// - `Ok(CacheMode::ReadOnly)` means cache can only be used to `get`
    ///   cache.
    /// - `Ok(CacheMode::ReadWrite)` means cache can do both `get` and `put`.
    /// - `Err(err)` means cache is not setup correctly or not match with
    ///   users input (for example, user try to use `ReadWrite` but cache
    ///   is `ReadOnly`).
    ///
    /// We will provide a default implementation which returns
    /// `Ok(CacheMode::ReadWrite)` for service that doesn't
    /// support check yet.
    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadWrite)
    }

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the cache backend type name (e.g., "disk", "redis", "s3").
    /// Used for statistics and display purposes.
    fn cache_type_name(&self) -> &'static str {
        "unknown"
    }

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;

    /// Get multi-level cache statistics, if this is a multi-level storage.
    fn multilevel_stats(&self) -> Option<MultiLevelStats> {
        None
    }

    /// Return the base directories for path normalization if configured
    fn basedirs(&self) -> &[Vec<u8>] {
        &[]
    }

    /// Return the filesystem path of the cached entry for `key`.
    /// Default impl returns [`GetPathResult::Unsupported`].
    async fn get_path(&self, _key: &str) -> GetPathResult {
        GetPathResult::Unsupported
    }
}

/// An interface for preprocessor cache storage
/// Preprocessor cache will include the source code into the hash.
/// Not all storage supports preprocessor cache, since this requires the underlying file system supports random read/write.
#[async_trait]
pub trait PreprocessorCacheStorage: Send + Sync {
    /// Return the config for preprocessor cache mode if applicable
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        // Enable by default, only in local mode
        PreprocessorCacheModeConfig::default()
    }

    /// Return the preprocessor cache entry for a given preprocessor key,
    /// if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn get_preprocessor_cache_entry(
        &self,
        _key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        Ok(None)
    }
    /// Insert a preprocessor cache entry at the given preprocessor key,
    /// overwriting the entry if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn put_preprocessor_cache_entry(
        &self,
        _key: &str,
        _preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        Ok(())
    }
}

pub trait Storage: CacheStorage + PreprocessorCacheStorage {}

impl<T: CacheStorage + PreprocessorCacheStorage> Storage for T {}

/// Wrapper for opendal::Operator that adds basedirs support
#[cfg(any_cache_remote)]
pub struct RemoteStorage {
    operator: opendal::Operator,
    basedirs: Vec<Vec<u8>>,
    rw_mode: CacheMode,
    skip_cache_check: bool,
}

#[cfg(any_cache_remote)]
impl RemoteStorage {
    pub fn new(operator: opendal::Operator, basedirs: Vec<Vec<u8>>, rw_mode: CacheMode) -> Self {
        Self {
            operator,
            basedirs,
            rw_mode,
            skip_cache_check: false,
        }
    }

    pub fn with_skip_cache_check(mut self, skip_cache_check: bool) -> Self {
        self.skip_cache_check = skip_cache_check;
        self
    }
}

#[cfg(any_cache_remote)]
pub(in crate::cache) fn decode_remote_cache_read(
    result: opendal::Result<opendal::Buffer>,
) -> Result<(Cache, Option<Bytes>)> {
    match result {
        Ok(res) => {
            let data = res.to_bytes();
            let hit = CacheRead::from(std::io::Cursor::new(data.clone()))?;
            Ok((Cache::Hit(hit), Some(data)))
        }
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok((Cache::Miss, None)),
        Err(e) => Err(e).context("failed to read remote cache entry"),
    }
}

/// Implement storage for operator.
#[cfg(any_cache_remote)]
#[async_trait]
impl CacheStorage for RemoteStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        Ok(self.get_with_raw(key).await?.0)
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        decode_remote_cache_read(self.operator.read(&normalize_key(key)).await)
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        trace!("RemoteStorage::put({})", key);
        // Delegate to put_raw after serializing the entry
        let data = entry.finish()?;
        self.put_raw(key, data.into()).await
    }

    async fn check(&self) -> Result<CacheMode> {
        use opendal::ErrorKind;

        if self.skip_cache_check {
            debug!(
                "storage check skipped; using configured cache mode: {:?}",
                self.rw_mode
            );
            return Ok(self.rw_mode);
        }

        let path = ".sccache_check";

        // Read is required, return error directly if we can't read .
        match self.operator.read(path).await {
            Ok(_) => (),
            // Read not exist file with not found is ok.
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            // Tricky Part.
            //
            // We tolerate rate limited here to make sccache keep running.
            // For the worse case, we will miss all the cache.
            //
            // In some super rare cases, user could configure storage in wrong
            // and hitting other services rate limit. There are few things we
            // can do, so we will print our the error here to make users know
            // about it.
            Err(err) if err.kind() == ErrorKind::RateLimited => {
                eprintln!("cache storage read check: {err:?}, but we decide to keep running");
            }
            Err(err) => bail!("cache storage failed to read: {:?}", err),
        }

        // No need to check write if we are in manually-set read-only mode
        if self.rw_mode == CacheMode::ReadOnly {
            let mode = CacheMode::ReadOnly;
            debug!("storage check result: {mode:?} (manually set)");
            return Ok(mode);
        }

        let can_write = match self.operator.write(path, "Hello, World!").await {
            Ok(_) => true,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => true,
            // Tolerate all other write errors because we can do read at least.
            Err(err) => {
                eprintln!("storage write check failed: {err:?}");
                false
            }
        };

        let mode = if can_write {
            CacheMode::ReadWrite
        } else {
            CacheMode::ReadOnly
        };

        debug!("storage check result: {mode:?}");

        Ok(mode)
    }

    fn location(&self) -> String {
        let meta = self.operator.info();
        format!(
            "{}, name: {}, prefix: {}",
            meta.scheme(),
            meta.name(),
            meta.root()
        )
    }

    fn cache_type_name(&self) -> &'static str {
        // Use opendal's scheme as the cache type name
        // This returns "s3", "redis", "azure", "gcs", etc.
        self.operator.info().scheme()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }

    /// Get raw bytes from remote storage for multi-level backfill.
    ///
    /// Unlike `get()` which parses bytes into `CacheRead` (a `ZipArchive<Box<dyn ReadSeek>>`),
    /// this returns the raw bytes without parsing. `CacheRead` is a one-way transformation —
    /// there is no way to extract the original bytes back from the parsed ZIP archive.
    /// For backfill we need the raw bytes to write directly to another cache level.
    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        trace!("opendal::Operator::get_raw({})", key);
        match self.operator.read(&normalize_key(key)).await {
            Ok(res) => {
                let data = res.to_bytes();
                trace!(
                    "opendal::Operator::get_raw({}): Found {} bytes",
                    key,
                    data.len()
                );
                Ok(Some(data))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
                trace!("opendal::Operator::get_raw({}): NotFound", key);
                Ok(None)
            }
            Err(e) => {
                warn!("opendal::Operator::get_raw({}): Error: {:?}", key, e);
                // Return error instead of silently returning None
                Err(anyhow!("Failed to read raw bytes: {:?}", e))
            }
        }
    }

    /// Write raw bytes to remote storage for multi-level backfill.
    ///
    /// Unlike `put()` which takes a `CacheWrite` and serializes it, this writes
    /// pre-serialized bytes directly. Paired with `get_raw()` for efficient
    /// level-to-level data transfer without a deserialize/reserialize round-trip.
    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        trace!("opendal::Operator::put_raw({}, {} bytes)", key, data.len());
        let start = std::time::Instant::now();

        if self.rw_mode == CacheMode::ReadOnly {
            bail!("storage is read-only");
        }

        self.operator.write(&normalize_key(key), data).await?;

        Ok(start.elapsed())
    }
}

#[cfg(any_cache_remote)]
#[async_trait]
impl PreprocessorCacheStorage for RemoteStorage {}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(any_cache_remote)]
    mod remote_storage {
        use super::*;
        use opendal::{Error, ErrorKind};

        #[test]
        fn get_returns_miss_for_not_found() {
            let (cache, raw) =
                decode_remote_cache_read(Err(Error::new(ErrorKind::NotFound, "entry not found")))
                    .unwrap();

            assert!(matches!(cache, Cache::Miss));
            assert!(raw.is_none());
        }

        #[test]
        fn get_propagates_unexpected_backend_errors() {
            let error = decode_remote_cache_read(Err(Error::new(
                ErrorKind::Unexpected,
                "injected read failure",
            )))
            .unwrap_err();

            assert_eq!(
                error.downcast_ref::<Error>().map(Error::kind),
                Some(ErrorKind::Unexpected)
            );
        }
    }
}
