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
use crate::lru_disk_cache::{CACHE_LOCK_FILE_NAME, Error as LruError, LruDiskCache, ReadSeek};
use async_trait::async_trait;
use bytes::Bytes;
use filetime::{FileTime, set_file_times};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
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
    process_safe: bool,
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
        Self::new_inner(
            root,
            max_size,
            pool,
            preprocessor_cache_mode_config,
            rw_mode,
            basedirs,
            false,
        )
    }

    pub fn new_process_safe<T: AsRef<OsStr>>(
        root: T,
        max_size: u64,
        pool: &tokio::runtime::Handle,
        preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
        rw_mode: CacheMode,
        basedirs: Vec<Vec<u8>>,
    ) -> DiskCache {
        Self::new_inner(
            root,
            max_size,
            pool,
            preprocessor_cache_mode_config,
            rw_mode,
            basedirs,
            true,
        )
    }

    fn new_inner<T: AsRef<OsStr>>(
        root: T,
        max_size: u64,
        pool: &tokio::runtime::Handle,
        preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
        rw_mode: CacheMode,
        basedirs: Vec<Vec<u8>>,
        process_safe: bool,
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
            process_safe,
        }
    }
}

/// Make a path to the cache entry with key `key`.
fn make_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}

pub(crate) fn lock_cache_directory(root: &Path) -> Result<File> {
    std::fs::create_dir_all(root)?;
    let path = root.join(CACHE_LOCK_FILE_NAME);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.lock()
        .with_context(|| format!("failed to lock {}", path.display()))?;
    Ok(file)
}

#[async_trait]
impl Storage for DiskCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        if self.process_safe {
            let root = self.lru.lock().unwrap().path().to_path_buf();
            let path = root.join(make_key_path(key));
            let file = self
                .pool
                .spawn_blocking(move || -> Result<Option<File>> {
                    let _lock = lock_cache_directory(&root)?;
                    let file = match File::open(&path) {
                        Ok(file) => file,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(None);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let now = FileTime::now();
                    set_file_times(&path, now, now)?;
                    Ok(Some(file))
                })
                .await??;
            return match file {
                Some(file) => Ok(Cache::Hit(CacheRead::from(file)?)),
                None => Ok(Cache::Miss),
            };
        }
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
        if self.process_safe {
            let root = self.lru.lock().unwrap().path().to_path_buf();
            let path = root.join(make_key_path(key));
            return self
                .pool
                .spawn_blocking(move || {
                    let file = {
                        let _lock = lock_cache_directory(&root)?;
                        let file = match File::open(&path) {
                            Ok(file) => file,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                return Ok(None);
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let now = FileTime::now();
                        set_file_times(&path, now, now)?;
                        file
                    };
                    let mut data = Vec::new();
                    let mut file = file;
                    file.read_to_end(&mut data)?;
                    Ok(Some(Bytes::from(data)))
                })
                .await?;
        }
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
                },
            )
            .await?
    }

    async fn get_path(&self, key: &str) -> GetPathResult {
        if self.process_safe {
            let root = self.lru.lock().unwrap().path().to_path_buf();
            let rel_path = make_key_path(key);
            return self
                .pool
                .spawn_blocking(move || {
                    let _lock = lock_cache_directory(&root).ok()?;
                    let path = root.join(rel_path);
                    let file = File::open(&path).ok()?;
                    let now = FileTime::now();
                    set_file_times(&path, now, now).ok()?;
                    drop(file);
                    Some(GetPathResult::Found(path))
                })
                .await
                .unwrap_or(None)
                .unwrap_or(GetPathResult::Miss);
        }
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

        if self.process_safe {
            let root = self.lru.lock().unwrap().path().to_path_buf();
            let max_size = self.lru.lock().unwrap().capacity();
            let key = make_key_path(key);
            return self
                .pool
                .spawn_blocking(move || {
                    let _lock = lock_cache_directory(&root)?;
                    let start = Instant::now();
                    let mut lru = LruDiskCache::new(&root, max_size)?;
                    let mut file = lru.prepare_add(key, data.len() as u64)?;
                    file.as_file_mut().write_all(&data)?;
                    lru.commit(file)?;
                    Ok(start.elapsed())
                })
                .await?;
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
        if self.process_safe {
            let root = self.lru.lock().unwrap().path().to_path_buf();
            let max_size = self.lru.lock().unwrap().capacity();
            return self
                .pool
                .spawn_blocking(move || {
                    let _lock = lock_cache_directory(&root)?;
                    Ok(Some(LruDiskCache::new(&root, max_size)?.size()))
                })
                .await?;
        }
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
        if self.process_safe {
            let root = self.preprocessor_cache.lock().unwrap().path().to_path_buf();
            let lock_root = self.lru.lock().unwrap().path().to_path_buf();
            let path = root.join(&key);
            return self
                .pool
                .spawn_blocking(move || {
                    let _lock = lock_cache_directory(&lock_root)?;
                    let file = match File::open(&path) {
                        Ok(file) => file,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(None);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let now = FileTime::now();
                    set_file_times(&path, now, now)?;
                    Ok(Some(Box::new(file) as Box<dyn ReadSeek>))
                })
                .await?;
        }
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
        if self.process_safe {
            let root = self.preprocessor_cache.lock().unwrap().path().to_path_buf();
            let lock_root = self.lru.lock().unwrap().path().to_path_buf();
            let max_size = self.preprocessor_cache.lock().unwrap().capacity();
            return self
                .pool
                .spawn_blocking(move || {
                    let _lock = lock_cache_directory(&lock_root)?;
                    let mut lru = LruDiskCache::new(&root, max_size)?;
                    let mut file = lru.prepare_add(key, 0)?;
                    let mut writer = BufWriter::new(file.as_file_mut());
                    preprocessor_cache_entry.serialize_to(&mut writer)?;
                    writer.flush()?;
                    drop(writer);
                    lru.commit(file)?;
                    Ok(())
                })
                .await?;
        }
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
    use std::thread;

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

    #[test]
    fn process_safe_disk_cache_preserves_capacity_with_concurrent_writers() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("cache");
        let workers: Vec<_> = (0..4)
            .map(|worker| {
                let root = root.clone();
                thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    let disk = DiskCache::new_process_safe(
                        &root,
                        1024,
                        runtime.handle(),
                        PreprocessorCacheModeConfig::default(),
                        CacheMode::ReadWrite,
                        vec![],
                    );
                    runtime.block_on(async {
                        for entry in 0..8 {
                            let key = format!("key-{worker}-{entry}");
                            disk.put_raw(&key, Bytes::from(vec![worker as u8; 256]))
                                .await
                                .unwrap();
                        }
                    });
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let size: u64 = walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.metadata().unwrap().len())
            .sum();
        assert!(size <= 1024, "cache uses {size} bytes");
    }

    #[test]
    fn process_safe_disk_cache_supports_path_reads_and_size() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("cache");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let disk = DiskCache::new_process_safe(
            &root,
            1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        runtime.block_on(async {
            disk.put_raw("path-read", Bytes::from_static(b"cache entry"))
                .await
                .unwrap();
            assert!(root.join(CACHE_LOCK_FILE_NAME).exists());
            assert!(!root.with_file_name("cache.sccache.lock").exists());
            let GetPathResult::Found(path) = disk.get_path("path-read").await else {
                panic!("process-safe disk cache should expose local paths");
            };
            assert_eq!(std::fs::read(path).unwrap(), b"cache entry");
            assert_eq!(disk.current_size().await.unwrap(), Some(11));
        });
    }
}
