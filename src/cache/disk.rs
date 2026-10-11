// Copyright 2016 Mozilla Foundation
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

use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, GetPathResult, Storage};
use crate::compiler::PreprocessorCacheEntry;
use crate::lru_disk_cache::{Error as LruError, LruDiskCache, ReadSeek, Result as LruResult};
use async_trait::async_trait;
use bytes::Bytes;
use std::ffi::OsStr;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::*;

use super::lazy_disk_cache::LazyDiskCache;
use super::utils::normalize_key;
use crate::config::PreprocessorCacheModeConfig;

/// A cache that stores entries at local disk paths.
pub struct DiskCache {
    /// `LruDiskCache` does all the real work here.
    lru: Arc<Mutex<LazyDiskCache>>,
    /// Thread pool to execute disk I/O
    pool: tokio::runtime::Handle,
    preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
    preprocessor_cache: Arc<Mutex<LazyDiskCache>>,
    rw_mode: CacheMode,
    basedirs: Vec<Vec<u8>>,
}

impl DiskCache {
    /// Create a new `DiskCache` rooted at `root`, with `max_size` as the maximum cache size on-disk, in bytes.
    pub fn new<T: AsRef<OsStr>>(
        root: T,
        max_size: u64,
        pool: &tokio::runtime::Handle,
        preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
        rw_mode: CacheMode,
        basedirs: Vec<Vec<u8>>,
    ) -> DiskCache {
        DiskCache {
            lru: Arc::new(Mutex::new(LazyDiskCache::Uninit {
                root: root.as_ref().to_os_string(),
                max_size,
            })),
            pool: pool.clone(),
            preprocessor_cache_mode_config,
            preprocessor_cache: Arc::new(Mutex::new(LazyDiskCache::Uninit {
                root: Path::new(root.as_ref())
                    .join("preprocessor")
                    .into_os_string(),
                max_size,
            })),
            rw_mode,
            basedirs,
        }
    }
}

/// Open the entry at `key`. A hit normally refreshes the entry's file times to keep the LRU
/// order on disk. A read-only cache may be on a read-only mount, or hold entries the reader
/// can read but not write, so that update would fail and turn every hit into a read error.
fn open_entry<K: AsRef<OsStr>>(
    cache: &mut LruDiskCache,
    key: K,
    rw_mode: CacheMode,
) -> LruResult<Box<dyn ReadSeek>> {
    match rw_mode {
        CacheMode::ReadOnly => cache.get_untouched(key),
        CacheMode::ReadWrite => cache.get(key),
    }
}

/// Make a path to the cache entry with key `key`.
fn make_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}

#[async_trait]
impl Storage for DiskCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        trace!("DiskCache::get({})", key);
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let key = key.to_owned();
        let rw_mode = self.rw_mode;

        self.pool
            .spawn_blocking(move || {
                let io = match open_entry(lru.lock().unwrap().get_or_init()?, &path, rw_mode) {
                    Ok(f) => f,
                    Err(LruError::FileNotInCache) => {
                        trace!("DiskCache::get({}): FileNotInCache", key);
                        return Ok(Cache::Miss);
                    }
                    Err(LruError::Io(e)) => {
                        trace!("DiskCache::get({}): IoError: {:?}", key, e);
                        return Err(e.into());
                    }
                    Err(_) => unreachable!(),
                };
                let hit = CacheRead::from(io)?;
                Ok(Cache::Hit(hit))
            })
            .await?
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        match self.get_raw(key).await? {
            Some(data) => {
                let hit = CacheRead::from(std::io::Cursor::new(data.clone()))?;
                Ok((Cache::Hit(hit), Some(data)))
            }
            None => Ok((Cache::Miss, None)),
        }
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        trace!("DiskCache::get_raw({})", key);
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let key = key.to_owned();
        let rw_mode = self.rw_mode;

        self.pool
            .spawn_blocking(move || {
                match open_entry(lru.lock().unwrap().get_or_init()?, &path, rw_mode) {
                    Ok(mut io) => {
                        let mut data = Vec::new();
                        io.read_to_end(&mut data)?;
                        trace!("DiskCache::get_raw({}): Found {} bytes", key, data.len());
                        Ok(Some(Bytes::from(data)))
                    }
                    Err(LruError::FileNotInCache) => {
                        trace!("DiskCache::get_raw({}): FileNotInCache", key);
                        Ok(None)
                    }
                    Err(LruError::Io(e)) => {
                        trace!("DiskCache::get_raw({}): IoError: {:?}", key, e);
                        Err(e.into())
                    }
                    Err(_) => unreachable!(),
                }
            })
            .await?
    }

    async fn get_path(&self, key: &str) -> GetPathResult {
        let rel_path = make_key_path(key);
        let lru = self.lru.clone();
        self.pool
            .spawn_blocking(move || {
                match lru
                    .lock()
                    .unwrap()
                    .get_or_init()
                    .ok()
                    .and_then(|c| c.get_abs_path(&rel_path))
                {
                    Some(p) => GetPathResult::Found(p),
                    None => GetPathResult::Miss,
                }
            })
            .await
            .unwrap_or(GetPathResult::Miss)
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        trace!("DiskCache::put({})", key);
        // Delegate to put_raw after serializing the entry
        let data = entry.finish()?;
        self.put_raw(key, data.into()).await
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        trace!("DiskCache::put_raw({}, {} bytes)", key, data.len());

        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        let lru = self.lru.clone();
        let key = make_key_path(key);

        self.pool
            .spawn_blocking(move || {
                let start = Instant::now();
                let mut f = lru
                    .lock()
                    .unwrap()
                    .get_or_init()?
                    .prepare_add(key, data.len() as u64)?;
                f.as_file_mut().write_all(&data)?;
                lru.lock().unwrap().get().unwrap().commit(f)?;
                Ok(start.elapsed())
            })
            .await?
    }

    async fn check(&self) -> Result<CacheMode> {
        Ok(self.rw_mode)
    }

    fn location(&self) -> String {
        format!("Local disk: {:?}", self.lru.lock().unwrap().path())
    }

    fn cache_type_name(&self) -> &'static str {
        "disk"
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(self.lru.lock().unwrap().get().map(|l| l.size()))
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(Some(self.lru.lock().unwrap().capacity()))
    }
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.preprocessor_cache_mode_config
    }
    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }
    async fn get_preprocessor_cache_entry(&self, key: &str) -> Result<Option<Box<dyn ReadSeek>>> {
        let key = normalize_key(key);
        Ok(open_entry(
            self.preprocessor_cache.lock().unwrap().get_or_init()?,
            key,
            self.rw_mode,
        )
        .ok())
    }
    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        let key = normalize_key(key);
        let mut f = self
            .preprocessor_cache
            .lock()
            .unwrap()
            .get_or_init()?
            .prepare_add(key, 0)?;
        preprocessor_cache_entry.serialize_to(BufWriter::new(f.as_file_mut()))?;
        Ok(self
            .preprocessor_cache
            .lock()
            .unwrap()
            .get()
            .unwrap()
            .commit(f)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_cache_type_name() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let disk = DiskCache::new(
            tempdir.path(),
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        assert_eq!(disk.cache_type_name(), "disk");
    }

    const KEY: &str = "0123456789abcdef";

    fn read_only_fixture() -> (tempfile::TempDir, tokio::runtime::Runtime) {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        (tempdir, runtime)
    }

    fn disk_cache(root: &Path, runtime: &tokio::runtime::Runtime, rw_mode: CacheMode) -> DiskCache {
        DiskCache::new(
            root,
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            rw_mode,
            vec![],
        )
    }

    /// Backdate `entry`'s times, so that any refresh by a read is visible.
    fn backdate(entry: &Path) -> filetime::FileTime {
        let old = filetime::FileTime::from_unix_time(1_000_000_000, 0);
        filetime::set_file_times(entry, old, old).unwrap();
        old
    }

    fn mtime(entry: &Path) -> filetime::FileTime {
        filetime::FileTime::from_last_modification_time(&std::fs::metadata(entry).unwrap())
    }

    #[test]
    fn test_read_only_get_leaves_entry_untouched() {
        let (tempdir, runtime) = read_only_fixture();
        runtime
            .block_on(
                disk_cache(tempdir.path(), &runtime, CacheMode::ReadWrite)
                    .put(KEY, CacheWrite::new()),
            )
            .unwrap();
        let entry = tempdir.path().join(make_key_path(KEY));
        let old = backdate(&entry);

        let hit = runtime
            .block_on(disk_cache(tempdir.path(), &runtime, CacheMode::ReadOnly).get(KEY))
            .unwrap();
        assert!(matches!(hit, Cache::Hit(_)));
        assert_eq!(mtime(&entry), old);
    }

    #[test]
    fn test_read_only_get_raw_leaves_entry_untouched() {
        let (tempdir, runtime) = read_only_fixture();
        runtime
            .block_on(
                disk_cache(tempdir.path(), &runtime, CacheMode::ReadWrite)
                    .put(KEY, CacheWrite::new()),
            )
            .unwrap();
        let entry = tempdir.path().join(make_key_path(KEY));
        let old = backdate(&entry);

        let disk = disk_cache(tempdir.path(), &runtime, CacheMode::ReadOnly);
        let data = runtime.block_on(disk.get_raw(KEY)).unwrap();
        assert_eq!(data.as_deref(), Some(&std::fs::read(&entry).unwrap()[..]));
        let (hit, _) = runtime.block_on(disk.get_with_raw(KEY)).unwrap();
        assert!(matches!(hit, Cache::Hit(_)));
        assert_eq!(mtime(&entry), old);
    }

    #[test]
    fn test_read_only_preprocessor_entry_leaves_entry_untouched() {
        let (tempdir, runtime) = read_only_fixture();
        runtime
            .block_on(
                disk_cache(tempdir.path(), &runtime, CacheMode::ReadWrite)
                    .put_preprocessor_cache_entry(KEY, PreprocessorCacheEntry::new()),
            )
            .unwrap();
        let entry = tempdir.path().join("preprocessor").join(normalize_key(KEY));
        let old = backdate(&entry);

        let found = runtime
            .block_on(
                disk_cache(tempdir.path(), &runtime, CacheMode::ReadOnly)
                    .get_preprocessor_cache_entry(KEY),
            )
            .unwrap();
        assert!(found.is_some());
        assert_eq!(mtime(&entry), old);
    }
}
