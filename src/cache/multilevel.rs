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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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

/// Lock-free atomic counters for multi-level cache statistics.
/// Stored directly in MultiLevelStorage to avoid mutex contention.
struct AtomicLevelStats {
    name: String,
    hits: AtomicU64,
    misses: AtomicU64,
    writes: AtomicU64,
    write_failures: AtomicU64,
    backfills_from: AtomicU64,
    backfills_to: AtomicU64,
    hit_duration_nanos: AtomicU64,
    write_duration_nanos: AtomicU64,
}

impl AtomicLevelStats {
    fn new(name: String) -> Self {
        Self {
            name,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
            backfills_from: AtomicU64::new(0),
            backfills_to: AtomicU64::new(0),
            hit_duration_nanos: AtomicU64::new(0),
            write_duration_nanos: AtomicU64::new(0),
        }
    }

    /// Create atomic stats for a specific cache level with formatted name
    fn for_level(idx: usize, storage: &Arc<dyn Storage>) -> Self {
        Self::new(format!("L{} ({})", idx, storage.cache_type_name()))
    }

    /// Create a Vec of atomic stats from a slice of storage backends
    fn from_levels(levels: &[Arc<dyn Storage>]) -> Vec<Arc<Self>> {
        levels
            .iter()
            .enumerate()
            .map(|(idx, level)| Arc::new(Self::for_level(idx, level)))
            .collect()
    }

    /// Take a consistent snapshot of all stats
    fn snapshot(&self) -> LevelStats {
        LevelStats {
            name: self.name.clone(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            write_failures: self.write_failures.load(Ordering::Relaxed),
            backfills_from: self.backfills_from.load(Ordering::Relaxed),
            backfills_to: self.backfills_to.load(Ordering::Relaxed),
            hit_duration: Duration::from_nanos(self.hit_duration_nanos.load(Ordering::Relaxed)),
            write_duration: Duration::from_nanos(self.write_duration_nanos.load(Ordering::Relaxed)),
        }
    }
}

/// Statistics for a single cache level (snapshot for display/serialization).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LevelStats {
    /// Human-readable name of this level (e.g., "L0 (disk)")
    pub name: String,
    /// Number of cache hits at this level
    pub hits: u64,
    /// Number of cache misses (checked but not found) at this level
    pub misses: u64,
    /// Number of successful writes to this level
    pub writes: u64,
    /// Number of failed writes to this level
    pub write_failures: u64,
    /// Number of times data from this level was backfilled to faster levels
    pub backfills_from: u64,
    /// Number of times data from slower levels was backfilled to this level
    pub backfills_to: u64,
    /// Total time spent reading hits from this level
    pub hit_duration: Duration,
    /// Total time spent writing to this level
    pub write_duration: Duration,
}

/// Statistics for multi-level cache operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MultiLevelStats {
    /// Per-level statistics
    pub levels: Vec<LevelStats>,
}

impl LevelStats {
    /// Calculate hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total > 0 {
            (self.hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Calculate average hit latency in milliseconds
    pub fn avg_hit_latency_ms(&self) -> f64 {
        if self.hits > 0 {
            self.hit_duration.as_secs_f64() * 1000.0 / self.hits as f64
        } else {
            0.0
        }
    }

    /// Calculate average write latency in milliseconds
    pub fn avg_write_latency_ms(&self) -> f64 {
        if self.writes > 0 {
            self.write_duration.as_secs_f64() * 1000.0 / self.writes as f64
        } else {
            0.0
        }
    }

    /// Format stats for human-readable display
    /// Returns a vector of (label, value_with_suffix, suffix_length) tuples
    /// suffix_length is used for width calculations in formatting
    /// Order: hits, misses, rate, writes, failures, backfills, write timing, read timing
    pub fn format_stats(&self) -> Vec<(String, String, usize)> {
        let mut stats = vec![];

        // 1. Hits/Misses/Rate
        stats.push((format!("  {} hits", self.name), self.hits.to_string(), 0));
        stats.push((
            format!("  {} misses", self.name),
            self.misses.to_string(),
            0,
        ));

        let total_checks = self.hits + self.misses;
        if total_checks > 0 {
            stats.push((
                format!("  {} hit rate", self.name),
                format!("{:.2} %", self.hit_rate()),
                2, // " %" is 2 chars
            ));
        } else {
            stats.push((format!("  {} hit rate", self.name), "-".to_string(), 0));
        }

        // 2. Writes and failures
        stats.push((
            format!("  {} writes", self.name),
            self.writes.to_string(),
            0,
        ));
        stats.push((
            format!("  {} write failures", self.name),
            self.write_failures.to_string(),
            0,
        ));

        // 3. Backfills
        stats.push((
            format!("  {} backfills from", self.name),
            self.backfills_from.to_string(),
            0,
        ));
        stats.push((
            format!("  {} backfills to", self.name),
            self.backfills_to.to_string(),
            0,
        ));

        // 4. Timing stats
        let avg_write_duration = if self.writes > 0 {
            self.write_duration / self.writes as u32
        } else {
            Duration::default()
        };
        stats.push((
            format!("  {} avg cache write", self.name),
            crate::util::fmt_duration_as_secs(&avg_write_duration),
            2, // " s" is 2 chars
        ));

        let avg_read_duration = if self.hits > 0 {
            self.hit_duration / self.hits as u32
        } else {
            Duration::default()
        };
        stats.push((
            format!("  {} avg cache read hit", self.name),
            crate::util::fmt_duration_as_secs(&avg_read_duration),
            2, // " s" is 2 chars
        ));

        stats
    }
}

impl MultiLevelStats {
    /// Format all stats for human-readable display
    /// Returns a vector of (label, value, suffix_type) tuples
    /// suffix_type: 0=none, 1=%, 2=ms
    pub fn format_stats(&self) -> Vec<(String, String, usize)> {
        let mut result = vec![];

        if self.levels.is_empty() {
            return result;
        }

        // Global stats
        result.push((
            "Multi-level cache levels".to_string(),
            self.levels.len().to_string(),
            0,
        ));

        // Per-level stats
        for level_stats in &self.levels {
            result.extend(level_stats.format_stats());
        }

        result
    }
}

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
    /// Lock-free atomic statistics per level
    atomic_stats: Vec<Arc<AtomicLevelStats>>,
}

impl MultiLevelStorage {
    /// Create a new multi-level storage from a list of storage backends.
    ///
    /// Levels are checked in order (L0, L1, L2, ...) during reads.
    /// All levels receive writes in parallel.
    pub fn new(levels: Vec<Arc<dyn Storage>>) -> Self {
        let atomic_stats = AtomicLevelStats::from_levels(&levels);

        MultiLevelStorage {
            levels,
            write_policy: WritePolicy::default(),
            atomic_stats,
        }
    }

    /// Create a new multi-level storage with explicit write policy.
    pub fn with_write_policy(levels: Vec<Arc<dyn Storage>>, write_policy: WritePolicy) -> Self {
        let atomic_stats = AtomicLevelStats::from_levels(&levels);

        MultiLevelStorage {
            levels,
            write_policy,
            atomic_stats,
        }
    }

    /// Get a snapshot of current multi-level cache statistics.
    pub fn stats(&self) -> MultiLevelStats {
        MultiLevelStats {
            levels: self.atomic_stats.iter().map(|s| s.snapshot()).collect(),
        }
    }

    /// Record a successful write to a level
    fn record_write_success(&self, idx: usize, duration: Duration) {
        if let Some(stats) = self.atomic_stats.get(idx) {
            stats.writes.fetch_add(1, Ordering::Relaxed);
            stats
                .write_duration_nanos
                .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
        }
    }

    /// Record a failed write to a level
    fn record_write_failure(&self, idx: usize) {
        if let Some(stats) = self.atomic_stats.get(idx) {
            stats.write_failures.fetch_add(1, Ordering::Relaxed);
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
            let stats_arc = self.atomic_stats.get(idx).map(Arc::clone);

            tokio::spawn(async move {
                let start = Instant::now();
                match Self::write_entry_from_bytes(&level, &key, &data).await {
                    Ok(_) => {
                        let duration = start.elapsed();
                        trace!("Backfilled cache level {} on write in {:?}", idx, duration);
                        if let Some(stats) = stats_arc {
                            stats.writes.fetch_add(1, Ordering::Relaxed);
                            stats
                                .write_duration_nanos
                                .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        debug!("Background write to level {} failed: {}", idx, e);
                        if let Some(stats) = stats_arc {
                            stats.write_failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    }
}

#[async_trait]
impl Storage for MultiLevelStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        for (idx, level) in self.levels.iter().enumerate() {
            let start = Instant::now();
            match level.get(key).await {
                Ok(Cache::Hit(entry)) => {
                    let duration = start.elapsed();
                    debug!("Cache hit at level {} in {:?}", idx, duration);

                    // Update stats
                    if let Some(stats) = self.atomic_stats.get(idx) {
                        stats.hits.fetch_add(1, Ordering::Relaxed);
                        stats
                            .hit_duration_nanos
                            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
                    }
                    // Mark misses for all levels checked before this hit
                    for miss_idx in 0..idx {
                        if let Some(stats) = self.atomic_stats.get(miss_idx) {
                            stats.misses.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // If hit at level > 0, backfill to faster levels (L0 to L(idx-1))
                    if idx > 0 {
                        let key_str = key.to_string();
                        let hit_level = idx;

                        // Try to get raw bytes for backfilling
                        match level.get_raw(key).await {
                            Ok(Some(raw_bytes)) => {
                                let raw_bytes = Arc::new(raw_bytes);

                                // Update backfill stats
                                if let Some(stats) = self.atomic_stats.get(hit_level) {
                                    stats
                                        .backfills_from
                                        .fetch_add(idx as u64, Ordering::Relaxed);
                                }

                                // Spawn background backfill tasks for each faster level
                                // Iterate slice directly instead of creating Vec
                                for backfill_idx in 0..idx {
                                    let key_bf = key_str.clone();
                                    let bytes_bf = Arc::clone(&raw_bytes);
                                    let level_bf = Arc::clone(&self.levels[backfill_idx]);
                                    let stats_arc =
                                        self.atomic_stats.get(backfill_idx).map(Arc::clone);

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
                                                // Update backfill_to stats
                                                if let Some(stats) = stats_arc {
                                                    stats
                                                        .backfills_to
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
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

        // Mark final miss for all checked levels
        for idx in 0..self.levels.len() {
            if let Some(stats) = self.atomic_stats.get(idx) {
                stats.misses.fetch_add(1, Ordering::Relaxed);
            }
        }

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
                        let start = Instant::now();
                        match Self::write_entry_from_bytes(l0, &key_str, &data).await {
                            Ok(_) => {
                                let duration = start.elapsed();
                                trace!("Stored in cache level 0 in {:?}", duration);
                                self.record_write_success(0, duration);
                            }
                            Err(e) => {
                                self.record_write_failure(0);
                                return Err(e);
                            }
                        }
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
                    let stats_arc = self.atomic_stats.get(idx).map(Arc::clone);

                    let write_task = async move {
                        let start = Instant::now();
                        let result = Self::write_entry_from_bytes(&level, &key_str, &data).await;
                        let duration = start.elapsed();
                        (idx, result, level, duration, stats_arc)
                    };

                    if idx == 0 {
                        // L0 synchronous
                        let (idx, result, level, duration, stats_arc) = write_task.await;
                        if let Err(e) = result {
                            // Check if read-only before failing
                            if !matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                                if let Some(stats) = stats_arc {
                                    stats.write_failures.fetch_add(1, Ordering::Relaxed);
                                }
                                return Err(anyhow!(
                                    "Failed to write to cache level {}: {}",
                                    idx,
                                    e
                                ));
                            }
                        } else if let Some(stats) = stats_arc {
                            stats.writes.fetch_add(1, Ordering::Relaxed);
                            stats
                                .write_duration_nanos
                                .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
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
                while let Some((idx, result, level, duration, stats_arc)) = rx.recv().await {
                    if let Err(e) = result {
                        // Check if read-only before failing
                        if !matches!(level.check().await, Ok(CacheMode::ReadOnly)) {
                            if let Some(stats) = stats_arc {
                                stats.write_failures.fetch_add(1, Ordering::Relaxed);
                            }
                            return Err(anyhow!("Failed to write to cache level {}: {}", idx, e));
                        }
                    } else if let Some(stats) = stats_arc {
                        stats.writes.fetch_add(1, Ordering::Relaxed);
                        stats
                            .write_duration_nanos
                            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
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

    fn multilevel_stats(&self) -> Option<crate::cache::multilevel::MultiLevelStats> {
        Some(self.stats())
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
        // Write preprocessor cache to all levels in parallel (best-effort)
        // Unlike regular cache entries, preprocessor cache writes are not critical
        // and shouldn't fail the compilation
        let futures: Vec<_> = self
            .levels
            .iter()
            .enumerate()
            .map(|(idx, level)| {
                let key = key.to_string();
                let entry = preprocessor_cache_entry.clone();
                let level = Arc::clone(level);

                tokio::spawn(async move {
                    if let Err(e) = level.put_preprocessor_cache_entry(&key, entry).await {
                        warn!(
                            "Failed to write preprocessor cache entry to level {}: {}",
                            idx, e
                        );
                    }
                })
            })
            .collect();

        // Wait for all writes to complete (errors are logged, not propagated)
        futures::future::join_all(futures).await;

        Ok(())
    }
}

#[cfg(test)]
#[path = "multilevel_test.rs"]
mod test;
