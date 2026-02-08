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

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::cache::build_single_cache;
use crate::cache::disk::DiskCache;
use crate::cache::{Cache, CacheMode, CacheWrite, Storage};
use crate::compiler::PreprocessorCacheEntry;
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::config::CacheType;
use crate::config::{Config, PreprocessorCacheModeConfig, WritePolicy};
use crate::errors::*;

/// A multi-level cache storage that checks multiple storage backends in order.
///
/// This enables hierarchical caching similar to CPU L1/L2/L3 caches:
/// - Fast, small caches (e.g., disk) are checked first (L0)
/// - Slower, larger caches (e.g., S3) are checked on miss
/// - Cache hits trigger automatic async backfill to faster levels
/// - Writes go to all levels in parallel
///
/// Configure via SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3" environment variable.
/// See docs/MultiLevel.md for details.
pub struct MultiLevelStorage {
    levels: Vec<Arc<dyn Storage>>,
    write_policy: WritePolicy,
}

impl MultiLevelStorage {
    /// Create a new multi-level storage from a list of storage backends.
    ///
    /// Levels are checked in order (L0, L1, L2, ...) during reads.
    /// All levels receive writes in parallel.
    pub fn new(levels: Vec<Arc<dyn Storage>>) -> Self {
        MultiLevelStorage {
            levels,
            write_policy: WritePolicy::default(),
        }
    }

    /// Create a new multi-level storage with explicit write policy.
    pub fn with_write_policy(levels: Vec<Arc<dyn Storage>>, write_policy: WritePolicy) -> Self {
        MultiLevelStorage {
            levels,
            write_policy,
        }
    }

    /// Create a multi-level storage from configuration.
    ///
    /// Returns None if no levels are configured (SCCACHE_MULTILEVEL_CHAIN not set).
    /// Returns an error if levels are specified but can't be built.
    ///
    /// Each level specified in config.cache_configs.multilevel.chain must have its
    /// corresponding configuration present (e.g., SCCACHE_DIR for disk,
    /// SCCACHE_REDIS_ENDPOINT for redis, etc).
    pub fn from_config(config: &Config, pool: &tokio::runtime::Handle) -> Result<Option<Self>> {
        let ml_config = match config.cache_configs.multilevel.as_ref() {
            Some(cfg) if !cfg.chain.is_empty() => cfg,
            _ => return Ok(None),
        };

        debug!(
            "Configuring multi-level cache with {} levels",
            ml_config.chain.len()
        );

        let levels = &ml_config.chain;
        let write_policy = ml_config.write_policy;

        let mut storages: Vec<Arc<dyn Storage>> = Vec::new();

        // Build caches in the exact order specified in levels
        for level_name in levels {
            let level_name = level_name.trim();

            if level_name.eq_ignore_ascii_case("disk") {
                // Build disk cache from config
                let disk_config = config.cache_configs.disk.as_ref().ok_or_else(|| {
                    anyhow!("Disk cache specified in levels but not configured (set SCCACHE_DIR)")
                })?;
                let preprocessor_cache_mode_config = disk_config.preprocessor_cache_mode;
                let rw_mode = disk_config.rw_mode.into();
                debug!(
                    "Adding disk cache level with dir {:?}, size {}",
                    disk_config.dir, disk_config.size
                );
                let disk_storage: Arc<dyn Storage> = Arc::new(DiskCache::new(
                    &disk_config.dir,
                    disk_config.size,
                    pool,
                    preprocessor_cache_mode_config,
                    rw_mode,
                    config.basedirs.clone(),
                ));
                storages.push(disk_storage);
                trace!("Added disk cache level");
            } else {
                // Build remote cache - get the appropriate CacheType
                #[cfg(any(
                    feature = "azure",
                    feature = "gcs",
                    feature = "gha",
                    feature = "memcached",
                    feature = "redis",
                    feature = "s3",
                    feature = "webdav",
                    feature = "oss",
                    feature = "cos"
                ))]
                {
                    let cache_type = match level_name.to_lowercase().as_str() {
                        #[cfg(feature = "s3")]
                        "s3" => config.cache_configs.s3.clone().map(CacheType::S3),
                        #[cfg(feature = "redis")]
                        "redis" => config.cache_configs.redis.clone().map(CacheType::Redis),
                        #[cfg(feature = "memcached")]
                        "memcached" => config
                            .cache_configs
                            .memcached
                            .clone()
                            .map(CacheType::Memcached),
                        #[cfg(feature = "gcs")]
                        "gcs" => config.cache_configs.gcs.clone().map(CacheType::GCS),
                        #[cfg(feature = "gha")]
                        "gha" => config.cache_configs.gha.clone().map(CacheType::GHA),
                        #[cfg(feature = "azure")]
                        "azure" => config.cache_configs.azure.clone().map(CacheType::Azure),
                        #[cfg(feature = "webdav")]
                        "webdav" => config.cache_configs.webdav.clone().map(CacheType::Webdav),
                        #[cfg(feature = "oss")]
                        "oss" => config.cache_configs.oss.clone().map(CacheType::OSS),
                        #[cfg(feature = "cos")]
                        "cos" => config.cache_configs.cos.clone().map(CacheType::COS),
                        _ => {
                            return Err(anyhow!("Unknown cache level: '{}'", level_name));
                        }
                    };

                    if let Some(cache_type) = cache_type {
                        let storage = build_single_cache(&cache_type, &config.basedirs, pool)
                            .with_context(|| {
                                format!("Failed to build cache for level '{}'", level_name)
                            })?;
                        storages.push(storage);
                        trace!("Added cache level: {}", level_name);
                    } else {
                        return Err(anyhow!(
                            "Cache level '{}' specified in SCCACHE_MULTILEVEL_CHAIN but not configured (missing environment variables)",
                            level_name
                        ));
                    }
                }
                #[cfg(not(any(
                    feature = "azure",
                    feature = "gcs",
                    feature = "gha",
                    feature = "memcached",
                    feature = "redis",
                    feature = "s3",
                    feature = "webdav",
                    feature = "oss",
                    feature = "cos"
                )))]
                {
                    return Err(anyhow!(
                        "Cache level '{}' requires a backend feature to be enabled (e.g., --features redis,s3)",
                        level_name
                    ));
                }
            }
        }

        if storages.is_empty() {
            return Err(anyhow!(
                "Multi-level cache configured with {} levels but none could be built",
                levels.len()
            ));
        }

        debug!(
            "Initialized multi-level storage with {} total levels",
            storages.len()
        );

        Ok(Some(MultiLevelStorage::with_write_policy(
            storages,
            write_policy,
        )))
    }

    /// Helper to write cache entry from raw bytes.
    ///
    /// Used during backfill operations to efficiently copy data between levels.
    async fn write_entry_from_bytes(
        level: &Arc<dyn Storage>,
        key: &str,
        data: &Arc<Vec<u8>>,
    ) -> Result<()> {
        // Try to use put_raw for direct bytes write (most efficient)
        level.put_raw(key, (**data).clone()).await?;
        Ok(())
    }

    /// Write to levels starting from `start_idx` asynchronously
    async fn write_remaining_levels_async(&self, key: &str, data: &Arc<Vec<u8>>, start_idx: usize) {
        for (idx, level) in self.levels.iter().enumerate().skip(start_idx) {
            // Check if level is read-only before spawning task
            if matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                debug!("Level {} is read-only, skipping write", idx);
                continue;
            }

            let data = Arc::clone(data);
            let key = key.to_string();
            let level = Arc::clone(level);

            tokio::spawn(async move {
                match Self::write_entry_from_bytes(&level, &key, &data).await {
                    Ok(_) => trace!("Backfilled cache level {} on write", idx),
                    Err(e) => debug!("Background write to level {} failed: {}", idx, e),
                }
            });
        }
    }
}

#[async_trait]
impl Storage for MultiLevelStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        for (idx, level) in self.levels.iter().enumerate() {
            match level.get(key).await {
                Ok(Cache::Hit(entry)) => {
                    debug!("Cache hit at level {}", idx);

                    // If hit at level > 0, backfill to faster levels (L0 to L(idx-1))
                    if idx > 0 {
                        let key_str = key.to_string();
                        let hit_level = idx;

                        // Try to get raw bytes for backfilling
                        match level.get_raw(key).await {
                            Ok(Some(raw_bytes)) => {
                                let raw_bytes = Arc::new(raw_bytes);

                                // Spawn background backfill tasks for each faster level
                                // Iterate slice directly instead of creating Vec
                                for backfill_idx in 0..idx {
                                    let key_bf = key_str.clone();
                                    let bytes_bf = Arc::clone(&raw_bytes);
                                    let level_bf = Arc::clone(&self.levels[backfill_idx]);

                                    tokio::spawn(async move {
                                        match Self::write_entry_from_bytes(
                                            &level_bf, &key_bf, &bytes_bf,
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                trace!(
                                                    "Backfilled cache level {} from level {}",
                                                    backfill_idx, hit_level
                                                );
                                            }
                                            Err(e) => {
                                                debug!(
                                                    "Background backfill from level {} to level {} failed: {}",
                                                    hit_level, backfill_idx, e
                                                );
                                            }
                                        }
                                    });
                                }
                            }
                            Ok(None) => {
                                debug!(
                                    "Cache backend at level {} does not support get_raw(), skipping backfill",
                                    hit_level
                                );
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to get raw bytes from level {} for backfill: {}",
                                    hit_level, e
                                );
                            }
                        }
                    }

                    return Ok(Cache::Hit(entry));
                }
                Ok(Cache::Miss) => {
                    trace!("Cache miss at level {}, trying next level", idx);
                    continue;
                }
                Ok(other) => {
                    return Ok(other);
                }
                Err(e) => {
                    warn!(
                        "Error checking cache level {}: {}, trying next level",
                        idx, e
                    );
                    continue;
                }
            }
        }
        debug!("Cache miss at all levels");
        Ok(Cache::Miss)
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        if self.levels.is_empty() {
            return Err(anyhow!("No cache levels configured"));
        }

        // Serialize cache entry once
        let data = Arc::new(entry.finish()?);
        let key_str = key.to_string();

        match self.write_policy {
            WritePolicy::Ignore => {
                // Never fail, log warnings only
                self.write_remaining_levels_async(&key_str, &data, 0).await;
                Ok(Duration::ZERO)
            }

            WritePolicy::L0 => {
                // Fail only if L0 write fails (unless L0 is read-only)
                if let Some(l0) = self.levels.first() {
                    // Check if L0 is read-only before attempting write
                    if matches!(l0.check().await, Ok(CacheMode::ReadOnly)) {
                        debug!("Level 0 is read-only, skipping L0 write");
                    } else {
                        // Attempt write and propagate errors
                        Self::write_entry_from_bytes(l0, &key_str, &data).await?;
                        trace!("Stored in cache level 0");
                    }

                    // Background writes for L1+ (best-effort)
                    self.write_remaining_levels_async(&key_str, &data, 1).await;
                }
                Ok(Duration::ZERO)
            }

            WritePolicy::All => {
                // Fail if any RW level fails
                use tokio::sync::mpsc;
                let (tx, mut rx) = mpsc::channel(self.levels.len());

                for (idx, level) in self.levels.iter().enumerate() {
                    let data = Arc::clone(&data);
                    let key_str = key_str.clone();
                    let level = Arc::clone(level);
                    let tx = tx.clone();

                    let write_task = async move {
                        let result = Self::write_entry_from_bytes(&level, &key_str, &data).await;
                        (idx, result, level)
                    };

                    if idx == 0 {
                        // L0 synchronous
                        let (idx, result, level) = write_task.await;
                        if let Err(e) = result {
                            // Check if read-only before failing
                            if !matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                                return Err(anyhow!(
                                    "Failed to write to cache level {}: {}",
                                    idx,
                                    e
                                ));
                            }
                        }
                    } else {
                        // L1+ async
                        tokio::spawn(async move {
                            let result = write_task.await;
                            let _ = tx.send(result).await;
                        });
                    }
                }
                drop(tx);

                // Check async results
                while let Some((idx, result, level)) = rx.recv().await {
                    if let Err(e) = result {
                        // Check if read-only before failing
                        if !matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                            return Err(anyhow!("Failed to write to cache level {}: {}", idx, e));
                        }
                    }
                }

                Ok(Duration::ZERO)
            }
        }
    }

    async fn check(&self) -> Result<CacheMode> {
        let mut result = CacheMode::ReadWrite;
        for (idx, level) in self.levels.iter().enumerate() {
            match level.check().await {
                Ok(CacheMode::ReadOnly) => {
                    result = CacheMode::ReadOnly;
                    debug!("Cache level {} is read-only", idx);
                }
                Ok(CacheMode::ReadWrite) => {
                    trace!("Cache level {} is read-write", idx);
                }
                Err(e) => {
                    warn!("Error checking cache level {}: {}", idx, e);
                    return Err(e);
                }
            }
        }
        Ok(result)
    }

    fn location(&self) -> String {
        format!(
            "Multi-level ({} levels): {}",
            self.levels.len(),
            self.levels
                .iter()
                .enumerate()
                .map(|(idx, level)| format!("L{}: {}", idx, level.location()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        let mut total = 0u64;
        for level in &self.levels {
            if let Some(size) = level.current_size().await? {
                total += size;
            }
        }
        if total > 0 { Ok(Some(total)) } else { Ok(None) }
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        let mut total = 0u64;
        for level in &self.levels {
            if let Some(size) = level.max_size().await? {
                total += size;
            }
        }
        if total > 0 { Ok(Some(total)) } else { Ok(None) }
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.levels
            .first()
            .map(|level| level.preprocessor_cache_mode_config())
            .unwrap_or_default()
    }

    async fn get_preprocessor_cache_entry(
        &self,
        key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        for level in &self.levels {
            if let Some(entry) = level.get_preprocessor_cache_entry(key).await? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        for (idx, level) in self.levels.iter().enumerate() {
            if let Err(e) = level
                .put_preprocessor_cache_entry(key, preprocessor_cache_entry.clone())
                .await
            {
                warn!(
                    "Failed to write preprocessor cache entry to level {}: {}",
                    idx, e
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::CacheRead;
    use crate::cache::disk::DiskCache;
    use crate::cache::readonly::ReadOnlyStorage;
    use crate::config::Config;
    use crate::config::PreprocessorCacheModeConfig;
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::Builder as TempBuilder;
    use tokio::runtime::Builder as RuntimeBuilder;
    use tokio::sync::Mutex;
    use tokio::time::sleep;

    #[test]
    fn test_multi_level_storage_get() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let tempdir1 = TempBuilder::new()
            .prefix("sccache_test_l1_")
            .tempdir()
            .unwrap();
        let cache_dir1 = tempdir1.path().join("cache");
        fs::create_dir(&cache_dir1).unwrap();

        let tempdir2 = TempBuilder::new()
            .prefix("sccache_test_l2_")
            .tempdir()
            .unwrap();
        let cache_dir2 = tempdir2.path().join("cache");
        fs::create_dir(&cache_dir2).unwrap();

        let cache1 = DiskCache::new(
            &cache_dir1,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );
        let cache2 = DiskCache::new(
            &cache_dir2,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        let cache1_storage: Arc<dyn Storage> = Arc::new(cache1);
        let cache2_storage: Arc<dyn Storage> = Arc::new(cache2);

        let storage = MultiLevelStorage::new(vec![
            Arc::clone(&cache1_storage),
            Arc::clone(&cache2_storage),
        ]);

        runtime.block_on(async {
            // Write directly to level 2 (level 1 is empty)
            {
                let entry = CacheWrite::default();
                cache2_storage.put("test_key", entry).await.unwrap();
            }

            // Now try to read through multi-level storage
            match storage.get("test_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - found at level 2
                }
                _ => panic!("Expected cache hit at level 2"),
            }

            // Try non-existent key
            match storage.get("nonexistent").await.unwrap() {
                Cache::Miss => {
                    // Expected
                }
                _ => panic!("Expected cache miss"),
            }
        });
    }

    #[test]
    fn test_multi_level_storage_backfill_on_hit() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let tempdir1 = TempBuilder::new()
            .prefix("sccache_test_bf_l1_")
            .tempdir()
            .unwrap();
        let cache_dir1 = tempdir1.path().join("cache");
        fs::create_dir(&cache_dir1).unwrap();

        let tempdir2 = TempBuilder::new()
            .prefix("sccache_test_bf_l2_")
            .tempdir()
            .unwrap();
        let cache_dir2 = tempdir2.path().join("cache");
        fs::create_dir(&cache_dir2).unwrap();

        let cache1 = DiskCache::new(
            &cache_dir1,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );
        let cache2 = DiskCache::new(
            &cache_dir2,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        let cache1_storage: Arc<dyn Storage> = Arc::new(cache1);
        let cache2_storage: Arc<dyn Storage> = Arc::new(cache2);

        let storage = MultiLevelStorage::new(vec![
            Arc::clone(&cache1_storage),
            Arc::clone(&cache2_storage),
        ]);

        runtime.block_on(async {
            // Write directly to level 2 (level 1 is empty)
            {
                let entry = CacheWrite::default();
                cache2_storage.put("backfill_key", entry).await.unwrap();
            }

            // Verify level 1 doesn't have it yet
            match cache1_storage.get("backfill_key").await.unwrap() {
                Cache::Miss => {
                    // Expected - level 1 is empty
                }
                _ => panic!("Level 1 should be empty"),
            }

            // Now read through multi-level storage - should hit level 2 and backfill to level 1
            match storage.get("backfill_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - found at level 2
                }
                _ => panic!("Expected cache hit at level 2"),
            }

            // Give background backfill task time to complete
            sleep(Duration::from_millis(200)).await;

            // Now level 1 should have the data (backfilled)
            match cache1_storage.get("backfill_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - backfilled from level 2
                }
                _ => panic!("Level 1 should now have the data (backfilled)"),
            }
        });
    }

    /// In-memory storage mock for testing multi-level backfill with remote-like backends.
    ///
    /// This is used to test multi-level cache backfill logic without requiring:
    /// - Network access to real remote services (S3, Redis, etc.)
    /// - Complex mock infrastructure (channels, queues, etc.)
    /// - Disk I/O operations
    ///
    /// The mock implements both Storage trait and get_raw() to simulate real backend
    /// behavior where remote caches support raw byte retrieval for efficient backfilling.
    struct InMemoryStorage {
        data: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        access_log: Arc<Mutex<Vec<String>>>,
    }

    impl InMemoryStorage {
        fn new() -> Self {
            Self {
                data: Arc::new(Mutex::new(HashMap::new())),
                access_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn get_access_log(&self) -> Arc<Mutex<Vec<String>>> {
            Arc::clone(&self.access_log)
        }
    }

    #[async_trait]
    impl Storage for InMemoryStorage {
        async fn get(&self, key: &str) -> Result<Cache> {
            self.access_log.lock().await.push(format!("get:{}", key));

            let data = self.data.lock().await;
            match data.get(key) {
                Some(bytes) => {
                    let cursor = Cursor::new(bytes.clone());
                    match CacheRead::from(cursor) {
                        Ok(hit) => Ok(Cache::Hit(hit)),
                        Err(_) => Ok(Cache::Miss),
                    }
                }
                None => Ok(Cache::Miss),
            }
        }

        async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
            self.access_log.lock().await.push(format!("put:{}", key));

            let data = entry.finish()?;
            self.data.lock().await.insert(key.to_string(), data);
            Ok(Duration::ZERO)
        }

        async fn check(&self) -> Result<CacheMode> {
            Ok(CacheMode::ReadWrite)
        }

        fn location(&self) -> String {
            "InMemory".to_string()
        }

        async fn current_size(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        async fn max_size(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        /// Implement get_raw() to enable backfill testing with remote-like backends.
        /// This simulates the behavior of real remote backends (S3, Redis, etc.) that
        /// can efficiently return raw serialized cache entries for backfilling.
        async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.data.lock().await.get(key).cloned())
        }

        /// Implement put_raw() to enable backfill writes during testing.
        async fn put_raw(&self, key: &str, data: Vec<u8>) -> Result<Duration> {
            self.data.lock().await.insert(key.to_string(), data);
            Ok(Duration::ZERO)
        }
    }

    #[test]
    fn test_disk_plus_remote_to_remote_backfill() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Create multi-level cache: Disk (L0) + Memcached (L1) + Redis (L2) + S3 (L3)
        // This simulates a real-world setup with local disk cache and multiple remote caches
        let tempdir = TempBuilder::new()
            .prefix("sccache_test_multilevel_")
            .tempdir()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        let disk_cache = Arc::new(DiskCache::new(
            &cache_dir,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        ));

        let remote_l1 = Arc::new(InMemoryStorage::new()); // Memcached-like
        let remote_l2 = Arc::new(InMemoryStorage::new()); // Redis-like
        let remote_l3 = Arc::new(InMemoryStorage::new()); // S3-like

        let storage = MultiLevelStorage::new(vec![
            disk_cache.clone() as Arc<dyn Storage>,
            remote_l1.clone() as Arc<dyn Storage>,
            remote_l2.clone() as Arc<dyn Storage>,
            remote_l3.clone() as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            // Scenario: Data only in S3 (L3), need to backfill all the way to local disk (L0)
            {
                let entry = CacheWrite::default();
                remote_l3.put("global_key", entry).await.unwrap();
            }

            // Verify only L3 has it
            assert!(matches!(
                disk_cache.get("global_key").await.unwrap(),
                Cache::Miss
            ));
            assert!(matches!(
                remote_l1.get("global_key").await.unwrap(),
                Cache::Miss
            ));
            assert!(matches!(
                remote_l2.get("global_key").await.unwrap(),
                Cache::Miss
            ));

            // Read through multi-level storage - should hit L3 and backfill everywhere
            match storage.get("global_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - found at L3
                }
                _ => panic!("Expected cache hit at L3"),
            }

            // Give all background backfill tasks time to complete
            // We have 3 backfill tasks (L3 -> L2, L3 -> L1, L3 -> L0)
            sleep(Duration::from_millis(400)).await;

            // Verify local disk was backfilled (closest to CPU)
            match disk_cache.get("global_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - backfilled from L3 to disk cache
                }
                _ => panic!("Disk cache should be backfilled from L3"),
            }

            // Verify remote L1 was backfilled
            match remote_l1.get("global_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected
                }
                _ => panic!("Remote L1 should be backfilled from L3"),
            }

            // Verify remote L2 was backfilled
            match remote_l2.get("global_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected
                }
                _ => panic!("Remote L2 should be backfilled from L3"),
            }

            // Now reading should hit at L0 (disk) - fastest
            match storage.get("global_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - immediate local disk hit
                }
                _ => panic!("Should hit at disk cache (L0)"),
            }
        });
    }

    #[test]
    fn test_disk_plus_remotes_write_to_all() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Test write path: ensure data is written to all levels
        let tempdir = TempBuilder::new()
            .prefix("sccache_test_write_all_")
            .tempdir()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        let disk_cache = Arc::new(DiskCache::new(
            &cache_dir,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        ));

        let remote_l1 = Arc::new(InMemoryStorage::new());
        let remote_l2 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::new(vec![
            disk_cache.clone() as Arc<dyn Storage>,
            remote_l1.clone() as Arc<dyn Storage>,
            remote_l2.clone() as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            // Write through multi-level should go to all levels
            {
                let entry = CacheWrite::default();
                storage.put("write_test_key", entry).await.unwrap();
            }

            // Give async writes time to complete
            sleep(Duration::from_millis(200)).await;

            // Verify disk cache has it
            match disk_cache.get("write_test_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - written to disk synchronously
                }
                _ => panic!("Disk cache should have data after put"),
            }

            // Verify both remote caches have it
            match remote_l1.get("write_test_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - written to L1 asynchronously
                }
                _ => panic!("Remote L1 should have data after put"),
            }

            match remote_l2.get("write_test_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - written to L2 asynchronously
                }
                _ => panic!("Remote L2 should have data after put"),
            }
        });
    }

    #[test]
    fn test_remote_to_remote_backfill() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Create three in-memory "remote" caches to simulate:
        // L0: Memcached (fast, small)
        // L1: Redis (medium, medium)
        // L2: S3 (slow, large)
        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(InMemoryStorage::new());
        let cache_l2 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::new(vec![
            cache_l0.clone() as Arc<dyn Storage>,
            cache_l1.clone() as Arc<dyn Storage>,
            cache_l2.clone() as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            // Simulate cache miss at L0 and L1, hit at L2 (typical scenario)
            {
                let entry = CacheWrite::default();
                cache_l2.put("remote_key", entry).await.unwrap();
            }

            // Verify L0 and L1 are empty (cache misses at those levels)
            match cache_l0.get("remote_key").await.unwrap() {
                Cache::Miss => {}
                _ => panic!("L0 should be empty initially"),
            }
            match cache_l1.get("remote_key").await.unwrap() {
                Cache::Miss => {}
                _ => panic!("L1 should be empty initially"),
            }

            // Read through multi-level storage - should hit L2 and backfill to L0 and L1
            match storage.get("remote_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - found at L2
                }
                _ => panic!("Expected cache hit at L2"),
            }

            // Give background backfill tasks time to complete
            // Multiple levels means multiple concurrent spawn tasks
            sleep(Duration::from_millis(300)).await;

            // Verify L0 was backfilled from L2 (through L1)
            match cache_l0.get("remote_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - backfilled from L2 via L1
                }
                _ => panic!("L0 should be backfilled from L2"),
            }

            // Verify L1 was backfilled from L2
            match cache_l1.get("remote_key").await.unwrap() {
                Cache::Hit(_) => {
                    // Expected - backfilled from L2
                }
                _ => panic!("L1 should be backfilled from L2"),
            }
        });
    }

    #[test]
    #[serial_test::serial(multilevel_env)]
    fn test_config_validation_invalid_level_name() {
        // Test that invalid level names are rejected
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Set invalid level name
        unsafe {
            env::set_var("SCCACHE_MULTILEVEL_CHAIN", "disk,invalid_backend,s3");
            env::set_var("SCCACHE_DIR", "/tmp/test-cache");
        }

        let config = Config::load().unwrap();
        let result = MultiLevelStorage::from_config(&config, runtime.handle());

        // Should error with unknown cache level
        assert!(result.is_err());
        if let Err(e) = result {
            let err_msg = format!("{}", e);
            assert!(err_msg.contains("Unknown cache level") || err_msg.contains("invalid_backend"));
        }

        unsafe {
            env::remove_var("SCCACHE_MULTILEVEL_CHAIN");
            env::remove_var("SCCACHE_DIR");
        }
    }

    #[test]
    fn test_config_validation_empty_levels() {
        // Test that empty levels list is handled
        let storage = MultiLevelStorage::new(vec![]);

        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Get should return miss (no levels to check)
            match storage.get("test_key").await.unwrap() {
                Cache::Miss => {} // Expected
                _ => panic!("Empty levels should always miss"),
            }
        });
    }

    #[test]
    fn test_config_validation_single_level() {
        // Test that single level works (passthrough mode)
        let cache = Arc::new(InMemoryStorage::new());
        let storage = MultiLevelStorage::new(vec![cache.clone() as Arc<dyn Storage>]);

        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        runtime.block_on(async {
            let entry = CacheWrite::default();
            storage.put("single_key", entry).await.unwrap();

            match storage.get("single_key").await.unwrap() {
                Cache::Hit(_) => {} // Expected
                _ => panic!("Single level should work as passthrough"),
            }

            // Should not backfill since only one level
            match cache.get("single_key").await.unwrap() {
                Cache::Hit(_) => {} // Expected - data is there
                _ => panic!("Data should be in the single level"),
            }
        });
    }

    #[test]
    #[serial_test::serial(multilevel_env)]
    fn test_config_level_not_configured() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Set level without configuration
        unsafe {
            env::set_var("SCCACHE_MULTILEVEL_CHAIN", "redis");
            // Don't set SCCACHE_REDIS_ENDPOINT
            env::remove_var("SCCACHE_REDIS");
            env::remove_var("SCCACHE_REDIS_ENDPOINT");
        }

        let config = Config::load().unwrap();
        let result = MultiLevelStorage::from_config(&config, runtime.handle());

        // Should error with "not configured" or "requires" (when feature disabled)
        assert!(result.is_err());
        if let Err(e) = result {
            let err_msg = format!("{}", e);
            assert!(
                err_msg.contains("not configured")
                    || err_msg.contains("missing")
                    || err_msg.contains("requires"),
                "Expected error about missing config or feature, got: {}",
                err_msg
            );
        }

        unsafe {
            env::remove_var("SCCACHE_MULTILEVEL_CHAIN");
        }
    }

    #[test]
    fn test_concurrent_reads() {
        // Test multiple simultaneous reads to different levels
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()
            .unwrap();

        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(InMemoryStorage::new());
        let cache_l2 = Arc::new(InMemoryStorage::new());

        let storage = Arc::new(MultiLevelStorage::new(vec![
            cache_l0.clone() as Arc<dyn Storage>,
            cache_l1.clone() as Arc<dyn Storage>,
            cache_l2.clone() as Arc<dyn Storage>,
        ]));

        runtime.block_on(async {
            // Populate different keys at different levels
            cache_l0.put("key_l0", CacheWrite::default()).await.unwrap();
            cache_l1.put("key_l1", CacheWrite::default()).await.unwrap();
            cache_l2.put("key_l2", CacheWrite::default()).await.unwrap();

            // Concurrent reads
            let storage1 = Arc::clone(&storage);
            let storage2 = Arc::clone(&storage);
            let storage3 = Arc::clone(&storage);

            let (r1, r2, r3) = tokio::join!(
                async move { storage1.get("key_l0").await },
                async move { storage2.get("key_l1").await },
                async move { storage3.get("key_l2").await },
            );

            // All should hit
            assert!(matches!(r1.unwrap(), Cache::Hit(_)));
            assert!(matches!(r2.unwrap(), Cache::Hit(_)));
            assert!(matches!(r3.unwrap(), Cache::Hit(_)));
        });
    }

    #[test]
    fn test_concurrent_write_and_read() {
        // Test concurrent writes and reads to same key
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()
            .unwrap();

        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(InMemoryStorage::new());

        let storage = Arc::new(MultiLevelStorage::new(vec![
            cache_l0.clone() as Arc<dyn Storage>,
            cache_l1.clone() as Arc<dyn Storage>,
        ]));

        runtime.block_on(async {
            let storage_write = Arc::clone(&storage);
            let storage_read = Arc::clone(&storage);

            // Concurrent write and read
            let write_task = tokio::spawn(async move {
                storage_write
                    .put("concurrent_key", CacheWrite::default())
                    .await
            });

            let read_task = tokio::spawn(async move {
                sleep(Duration::from_millis(10)).await;
                storage_read.get("concurrent_key").await
            });

            let (write_result, read_result) = tokio::join!(write_task, read_task);

            // Write should succeed
            write_result.unwrap().unwrap();

            // Read might miss or hit depending on timing (both are valid)
            match read_result.unwrap().unwrap() {
                Cache::Hit(_) | Cache::Miss => {} // Both valid
                _ => panic!("Unexpected cache result"),
            }
        });
    }

    #[test]
    fn test_large_data_handling() {
        // Test with large cache entries
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::new(vec![
            cache_l0.clone() as Arc<dyn Storage>,
            cache_l1.clone() as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            // Create large entry (1MB of data)
            let mut entry = CacheWrite::new();
            let large_data = vec![0xAB; 1024 * 1024]; // 1MB of data
            entry.put_stdout(&large_data).unwrap();
            cache_l1.put("large_key", entry).await.unwrap();

            // Read through multi-level - should hit at L1
            match storage.get("large_key").await.unwrap() {
                Cache::Hit(_) => {}
                _ => panic!("Should hit at L1"),
            }

            // Wait for backfill
            sleep(Duration::from_millis(200)).await;

            // Verify L0 was backfilled
            match cache_l0.get("large_key").await.unwrap() {
                Cache::Hit(_) => {} // Expected
                _ => panic!("L0 should have backfilled data from L1"),
            }
        });
    }

    #[test]
    fn test_storage_trait_methods() {
        // Test Storage trait methods: check(), location(), current_size(), max_size()
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::new(vec![
            cache_l0 as Arc<dyn Storage>,
            cache_l1 as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            // Test check() - should return ReadWrite
            match storage.check().await.unwrap() {
                CacheMode::ReadWrite => {} // Expected
                _ => panic!("Expected ReadWrite mode"),
            }

            // Test location() - should return multi-level description
            let location = storage.location();
            assert!(
                location.contains("Multi-level"),
                "Location should mention Multi-level: {}",
                location
            );

            // Test current_size() - should return None or Some
            let _ = storage.current_size().await.unwrap();

            // Test max_size() - should return None or Some
            let _ = storage.max_size().await.unwrap();
        });
    }

    #[test]
    fn test_all_levels_fail_on_put() {
        // Test behavior when all storage levels fail on write
        // In multi-level design, put() succeeds if ANY level succeeds
        // Even if all fail, it should not panic
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Create ReadOnly storages that will reject writes
        let cache_l0 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
        let cache_l1 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));

        let storage = MultiLevelStorage::new(vec![
            cache_l0 as Arc<dyn Storage>,
            cache_l1 as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            let entry = CacheWrite::new();

            // put() should complete without panic even when all levels fail
            // (writes to L0 are synchronous, L1+ are async background)
            let result = storage.put("fail_key", entry).await;

            assert!(result.is_ok(), "Put should succeed with read-only levels");
        });
    }

    #[test]
    fn test_preprocessor_cache_mode() {
        // Test preprocessor_cache_mode_config() returns first level's config
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let tempdir = TempBuilder::new()
            .prefix("sccache_test_preprocessor_")
            .tempdir()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        let preprocessor_config = PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: true,
            ..Default::default()
        };

        let disk_cache = Arc::new(DiskCache::new(
            &cache_dir,
            1024 * 1024 * 100,
            runtime.handle(),
            preprocessor_config,
            CacheMode::ReadWrite,
            vec![],
        ));

        let cache_l1 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::new(vec![
            disk_cache as Arc<dyn Storage>,
            cache_l1 as Arc<dyn Storage>,
        ]);

        // Should return first level's config
        let config = storage.preprocessor_cache_mode_config();
        assert!(config.use_preprocessor_cache_mode);
    }

    #[test]
    fn test_empty_levels_new() {
        // Edge case: creating MultiLevelStorage with empty vec
        // This is allowed but from_config prevents it
        let storage = MultiLevelStorage::new(vec![]);

        // Should have zero levels
        assert_eq!(storage.levels.len(), 0);

        // location() should still work
        let location = storage.location();
        assert!(location.contains("0"));
    }

    #[test]
    fn test_preprocessor_cache_methods() {
        // Test get_preprocessor_cache_entry and put_preprocessor_cache_entry
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let tempdir = TempBuilder::new()
            .prefix("sccache_test_prep_")
            .tempdir()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        let disk_cache = Arc::new(DiskCache::new(
            &cache_dir,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        ));

        let storage = MultiLevelStorage::new(vec![disk_cache as Arc<dyn Storage>]);

        runtime.block_on(async {
            // Test get_preprocessor_cache_entry - should return None for non-existent key
            let result = storage.get_preprocessor_cache_entry("test_key").await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());

            // Test put_preprocessor_cache_entry
            let entry = PreprocessorCacheEntry::default();
            let result = storage
                .put_preprocessor_cache_entry("test_key", entry)
                .await;
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_readonly_level_in_check() {
        // Test that check() properly detects read-only levels
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let tempdir = TempBuilder::new()
            .prefix("sccache_test_ro_")
            .tempdir()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        let disk_cache = DiskCache::new(
            &cache_dir,
            1024 * 1024 * 100,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        // Wrap in ReadOnly
        let ro_cache = Arc::new(ReadOnlyStorage(Arc::new(disk_cache)));

        let storage = MultiLevelStorage::new(vec![ro_cache as Arc<dyn Storage>]);

        runtime.block_on(async {
            // check() should detect read-only mode
            match storage.check().await.unwrap() {
                CacheMode::ReadOnly => {} // Expected
                _ => panic!("Should detect read-only mode"),
            }
        });
    }

    #[test]
    fn test_sequential_read_order() {
        // Test that reads happen sequentially (L0, L1, L2, ...), not in parallel
        // This verifies the documented behavior: "check multiple storage backends in sequence"
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Create three storage levels with access tracking
        let l0 = Arc::new(InMemoryStorage::new());
        let l1 = Arc::new(InMemoryStorage::new());
        let l2 = Arc::new(InMemoryStorage::new());

        let l0_log = l0.get_access_log();
        let l1_log = l1.get_access_log();
        let l2_log = l2.get_access_log();

        // Put data only in L2 (slowest level)
        let key = "test_key_12345678901234567890";
        runtime.block_on(async {
            let mut entry = CacheWrite::default();
            entry.put_stdout(b"test data").unwrap();
            l2.put(key, entry).await.unwrap();
        });

        let storage = MultiLevelStorage::new(vec![
            l0 as Arc<dyn Storage>,
            l1 as Arc<dyn Storage>,
            l2 as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            let result = storage.get(key).await.unwrap();

            assert!(matches!(result, Cache::Hit(_)));

            // Check that all three levels were accessed in order
            let l0_accesses = l0_log.lock().await;
            let l1_accesses = l1_log.lock().await;
            let l2_accesses = l2_log.lock().await;

            // Each level should have been accessed exactly once for get
            assert_eq!(l0_accesses.len(), 1, "L0 should be checked first");
            assert_eq!(l1_accesses.len(), 1, "L1 should be checked second");
            assert_eq!(l2_accesses.len(), 2, "L2: put (setup) + get (check)");

            assert_eq!(l0_accesses[0], format!("get:{}", key));
            assert_eq!(l1_accesses[0], format!("get:{}", key));
            assert_eq!(l2_accesses[0], format!("put:{}", key)); // from setup
            assert_eq!(l2_accesses[1], format!("get:{}", key)); // from sequential check
        });
    }

    #[test]
    fn test_read_stops_at_first_hit_not_parallel() {
        // Test that when L1 has data, L2 is NEVER accessed (proving sequential not parallel)
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let l0 = Arc::new(InMemoryStorage::new());
        let l1 = Arc::new(InMemoryStorage::new());
        let l2 = Arc::new(InMemoryStorage::new());

        let l0_log = l0.get_access_log();
        let l1_log = l1.get_access_log();
        let l2_log = l2.get_access_log();

        let key = "test_key_early_hit_1234567890ab";

        // Put data in L1
        runtime.block_on(async {
            let mut entry = CacheWrite::default();
            entry.put_stdout(b"L1 data").unwrap();
            l1.put(key, entry).await.unwrap();
        });

        let storage = MultiLevelStorage::new(vec![
            l0 as Arc<dyn Storage>,
            l1 as Arc<dyn Storage>,
            l2 as Arc<dyn Storage>,
        ]);

        runtime.block_on(async {
            let result = storage.get(key).await.unwrap();

            assert!(matches!(result, Cache::Hit(_)));

            // Verify L0 and L1 were accessed, but L2 was NOT
            let l0_accesses = l0_log.lock().await;
            let l1_accesses = l1_log.lock().await;
            let l2_accesses = l2_log.lock().await;

            assert_eq!(l0_accesses.len(), 1, "L0 should be checked first");
            assert_eq!(l1_accesses.len(), 2, "L1: put (setup) + get (check)");
            assert_eq!(
                l2_accesses.len(),
                0,
                "L2 should NOT be checked (sequential read stops at first hit)"
            );
        });
    }

    /// Storage mock that always fails on write (for testing error handling).
    ///
    /// Unlike ReadOnlyStorage (which is a valid mode), this returns actual errors
    /// to simulate real failure scenarios like disk full, network errors, etc.
    struct FailingStorage;

    #[async_trait]
    impl Storage for FailingStorage {
        async fn get(&self, _key: &str) -> Result<Cache> {
            Ok(Cache::Miss)
        }

        async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
            Err(anyhow!("Intentional failure for testing"))
        }

        async fn put_raw(&self, _key: &str, _entry: Vec<u8>) -> Result<Duration> {
            Err(anyhow!("Intentional failure for testing"))
        }

        async fn check(&self) -> Result<CacheMode> {
            Ok(CacheMode::ReadWrite) // It's RW but fails on put
        }

        fn location(&self) -> String {
            "FailingStorage".to_string()
        }

        async fn current_size(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        async fn max_size(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
            PreprocessorCacheModeConfig::default()
        }

        async fn get_preprocessor_cache_entry(
            &self,
            _key: &str,
        ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
            Err(anyhow!("Intentional failure for testing"))
        }

        async fn put_preprocessor_cache_entry(
            &self,
            _key: &str,
            _entry: PreprocessorCacheEntry,
        ) -> Result<()> {
            Err(anyhow!("Intentional failure for testing"))
        }
    }

    #[test]
    fn test_put_mode_ignore() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // All levels fail with actual errors
        let cache_l0 = Arc::new(FailingStorage);
        let cache_l1 = Arc::new(FailingStorage);

        let storage = MultiLevelStorage::with_write_policy(
            vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
            WritePolicy::Ignore,
        );

        runtime.block_on(async {
            let entry = CacheWrite::new();
            let result = storage.put("test_key", entry).await;

            assert!(
                result.is_ok(),
                "WritePolicy::Ignore should never fail, even when all levels error"
            );
        });
    }

    #[test]
    fn test_put_mode_l0_fails_on_error() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // L0 fails with actual error, L1 succeeds
        let cache_l0 = Arc::new(FailingStorage);
        let cache_l1 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::with_write_policy(
            vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
            WritePolicy::L0,
        );

        runtime.block_on(async {
            let entry = CacheWrite::new();
            let result = storage.put("test_key", entry).await;

            assert!(
                result.is_err(),
                "WritePolicy::L0 should fail when L0 write fails"
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Intentional") || err_msg.contains("put_raw not implemented"),
                "Expected failure message, got: {}",
                err_msg
            );
        });
    }

    #[test]
    fn test_put_mode_l0_succeeds_if_l0_ok() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // L0 succeeds, L1 fails (shouldn't matter in L0 mode)
        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(FailingStorage);

        let storage = MultiLevelStorage::with_write_policy(
            vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
            WritePolicy::L0,
        );

        runtime.block_on(async {
            let entry = CacheWrite::new();
            let result = storage.put("test_key", entry).await;

            assert!(
                result.is_ok(),
                "WritePolicy::L0 should succeed when L0 succeeds, even if L1+ fails"
            );
        });
    }

    #[test]
    fn test_put_mode_all_fails_on_any_error() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // L0 succeeds, L1 fails
        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(FailingStorage);

        let storage = MultiLevelStorage::with_write_policy(
            vec![cache_l0 as Arc<dyn Storage>, cache_l1 as Arc<dyn Storage>],
            WritePolicy::All,
        );

        runtime.block_on(async {
            let entry = CacheWrite::new();
            let result = storage.put("test_key", entry).await;

            // Give background L1 task time to complete and report failure
            sleep(Duration::from_millis(100)).await;

            assert!(
                result.is_err(),
                "WritePolicy::All should fail when any RW level fails"
            );
        });
    }

    #[test]
    fn test_put_mode_all_succeeds_when_all_ok() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Both levels succeed
        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::with_write_policy(
            vec![
                cache_l0.clone() as Arc<dyn Storage>,
                cache_l1.clone() as Arc<dyn Storage>,
            ],
            WritePolicy::All,
        );

        runtime.block_on(async {
            let entry = CacheWrite::new();
            let result = storage.put("test_key", entry).await;

            // Give background tasks time to complete
            sleep(Duration::from_millis(100)).await;

            assert!(
                result.is_ok(),
                "WritePolicy::All should succeed when all levels succeed"
            );

            // Verify both levels have the data
            assert!(matches!(
                cache_l0.get("test_key").await.unwrap(),
                Cache::Hit(_)
            ));
            assert!(matches!(
                cache_l1.get("test_key").await.unwrap(),
                Cache::Hit(_)
            ));
        });
    }

    #[test]
    fn test_put_mode_all_skips_readonly() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // L0 writable, L1 read-only (should be skipped), L2 writable
        let cache_l0 = Arc::new(InMemoryStorage::new());
        let cache_l1 = Arc::new(ReadOnlyStorage(Arc::new(InMemoryStorage::new())));
        let cache_l2 = Arc::new(InMemoryStorage::new());

        let storage = MultiLevelStorage::with_write_policy(
            vec![
                cache_l0.clone() as Arc<dyn Storage>,
                cache_l1 as Arc<dyn Storage>,
                cache_l2.clone() as Arc<dyn Storage>,
            ],
            WritePolicy::All,
        );

        runtime.block_on(async {
            let entry = CacheWrite::new();
            let result = storage.put("test_key", entry).await;

            // Give background tasks time to complete
            sleep(Duration::from_millis(100)).await;

            assert!(
                result.is_ok(),
                "WritePolicy::All should succeed when read-only levels are skipped"
            );

            // Verify writable levels have the data
            assert!(matches!(
                cache_l0.get("test_key").await.unwrap(),
                Cache::Hit(_)
            ));
            assert!(matches!(
                cache_l2.get("test_key").await.unwrap(),
                Cache::Hit(_)
            ));
        });
    }
}
