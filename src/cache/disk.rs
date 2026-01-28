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

use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, Storage};
use crate::compiler::PreprocessorCacheEntry;
use crate::lru_disk_cache::{Error as LruError, ReadSeek};
use async_trait::async_trait;
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

        self.pool
            .spawn_blocking(move || {
                let io = match lru.lock().unwrap().get_or_init()?.get(&path) {
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

    async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        trace!("DiskCache::get_raw({})", key);
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let key = key.to_owned();

        self.pool
            .spawn_blocking(
                move || match lru.lock().unwrap().get_or_init()?.get(&path) {
                    Ok(mut io) => {
                        let mut data = Vec::new();
                        io.read_to_end(&mut data)?;
                        trace!("DiskCache::get_raw({}): Found {} bytes", key, data.len());
                        Ok(Some(data))
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
                },
            )
            .await?
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        // We should probably do this on a background thread if we're going to buffer
        // everything in memory...
        trace!("DiskCache::finish_put({})", key);

        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        let lru = self.lru.clone();
        let key = make_key_path(key);

        self.pool
            .spawn_blocking(move || {
                let start = Instant::now();
                let v = entry.finish()?;
                let mut f = lru
                    .lock()
                    .unwrap()
                    .get_or_init()?
                    .prepare_add(key, v.len() as u64)?;
                f.as_file_mut().write_all(&v)?;
                lru.lock().unwrap().get().unwrap().commit(f)?;
                Ok(start.elapsed())
            })
            .await?
    }

    async fn put_raw(&self, key: &str, data: Vec<u8>) -> Result<Duration> {
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
        Ok(self
            .preprocessor_cache
            .lock()
            .unwrap()
            .get_or_init()?
            .get(key)
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
}
