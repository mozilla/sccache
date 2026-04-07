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

use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, Storage, UncompressedCacheEntry};
use crate::compiler::PreprocessorCacheEntry;
use crate::lru_disk_cache::{Error as LruError, ReadSeek};
use async_trait::async_trait;
use std::ffi::OsStr;
use std::io::{BufWriter, Write};
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
    use_uncompressed: bool,
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
        file_clone: bool,
    ) -> DiskCache {
        let use_uncompressed = if file_clone {
            let root_path = Path::new(root.as_ref());
            // Ensure the cache directory exists before testing reflink support,
            // since LazyDiskCache hasn't created it yet at this point.
            if let Err(e) = std::fs::create_dir_all(root_path) {
                log::warn!(
                    "file_clone: failed to create cache directory {:?}: {}. \
                     Falling back to compressed mode.",
                    root_path,
                    e
                );
                false
            } else if crate::reflink::is_reflink_supported(root_path) {
                log::info!("file_clone enabled: using uncompressed storage");
                true
            } else {
                log::warn!(
                    "file_clone enabled but CoW filesystem not detected, using compressed storage"
                );
                false
            }
        } else {
            false
        };

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
            use_uncompressed,
        }
    }
}

/// Make a path to the cache entry with key `key`.
fn make_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}

/// Check if a cache entry is stored as an uncompressed directory.
/// Requires both a directory at the key path and the presence of the marker file,
/// to avoid treating partially-written directories (e.g., crash during write) as valid hits.
fn is_uncompressed_entry(cache_root: &Path, key: &str) -> bool {
    let path = cache_root.join(make_key_path(key));
    path.is_dir() && path.join(crate::lru_disk_cache::DIR_ENTRY_MARKER).exists()
}

fn write_uncompressed_entry(cache_root: &Path, key_dir: &Path, entry: CacheWrite) -> Result<()> {
    let entry_dir = cache_root.join(key_dir);
    fs_err::create_dir_all(&entry_dir)?;

    // Remove the marker file first so concurrent get() calls won't see a
    // partially-written entry as valid during an overwrite (e.g. force-recache).
    let _ = std::fs::remove_file(entry_dir.join(crate::lru_disk_cache::DIR_ENTRY_MARKER));

    let compressed = entry.finish()?;
    let cursor = std::io::Cursor::new(&compressed);
    let mut zip = zip::ZipArchive::new(cursor).context("Failed to parse cache entry")?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file.name().to_string();

        let dest_path = entry_dir.join(&name);
        let mut output = fs_err::File::create(&dest_path)?;

        zstd::stream::copy_decode(&mut file, &mut output)
            .context("Failed to decompress cache entry")?;

        if name != "stdout" && name != "stderr" {
            if let Some(mode) = file.unix_mode() {
                crate::cache::utils::set_file_mode(&dest_path, mode)?;
            }
        }
    }

    Ok(())
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
                let mut binding = lru.lock().unwrap();
                let cache = binding.get_or_init()?;
                let cache_root = cache.path().to_path_buf();

                // Check for uncompressed entry first (regardless of current mode)
                if is_uncompressed_entry(&cache_root, &key) {
                    let full_dir = cache_root.join(&path);
                    // Update LRU recency so directory entries aren't evicted prematurely
                    let _ = cache.touch(&path);
                    drop(binding);
                    let entry = UncompressedCacheEntry::new(full_dir);
                    return Ok(Cache::UncompressedHit(entry));
                }

                // Try compressed entry
                match cache.get(&path) {
                    Ok(io) => {
                        let hit = CacheRead::from(io)?;
                        Ok(Cache::Hit(hit))
                    }
                    Err(LruError::FileNotInCache) => {
                        trace!("DiskCache::get({}): FileNotInCache", key);
                        Ok(Cache::Miss)
                    }
                    Err(LruError::Io(e)) => {
                        trace!("DiskCache::get({}): IoError: {:?}", key, e);
                        Err(e.into())
                    }
                    Err(_) => unreachable!(),
                }
            })
            .await?
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        // We should probably do this on a background thread if we're going to buffer
        // everything in memory...
        trace!("DiskCache::finish_put({})", key);

        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        let use_uncompressed = self.use_uncompressed;
        let lru = self.lru.clone();
        let key = make_key_path(key);

        self.pool
            .spawn_blocking(move || {
                let start = Instant::now();

                if use_uncompressed {
                    // Get the cache root path while holding the lock briefly
                    let cache_root = {
                        let mut binding = lru.lock().unwrap();
                        let cache = binding.get_or_init()?;
                        cache.path().to_path_buf()
                    };

                    // Perform I/O without holding the lock
                    write_uncompressed_entry(&cache_root, &key, entry)?;

                    // Re-acquire the lock to register the directory entry
                    let mut binding = lru.lock().unwrap();
                    let cache = binding.get_or_init()?;
                    cache.add_dir(&key)?;
                } else {
                    let v = entry.finish()?;
                    let mut f = lru
                        .lock()
                        .unwrap()
                        .get_or_init()?
                        .prepare_add(&key, v.len() as u64)?;
                    f.as_file_mut().write_all(&v)?;
                    lru.lock().unwrap().get().unwrap().commit(f)?;
                }

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
            false,
        );

        assert_eq!(disk.cache_type_name(), "disk");
    }

    #[test]
    fn test_disk_cache_file_clone_detection() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let disk_default = DiskCache::new(
            tempdir.path(),
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
            false,
        );
        assert!(!disk_default.use_uncompressed);

        let tempdir2 = tempfile::tempdir().unwrap();
        let disk_file_clone = DiskCache::new(
            tempdir2.path(),
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
            true,
        );
        let is_cow = crate::reflink::is_reflink_supported(tempdir2.path());
        assert_eq!(
            disk_file_clone.use_uncompressed, is_cow,
            "use_uncompressed should match reflink support when file_clone is enabled"
        );
    }

    /// Test that writing an uncompressed entry and reading it back returns UncompressedHit,
    /// and that extract_objects() restores expected file contents (using regular copy fallback
    /// when reflink is not available).
    #[tokio::test]
    async fn test_uncompressed_put_get_extract_roundtrip() {
        use crate::cache::cache_io::FileObjectSource;

        let tempdir = tempfile::tempdir().unwrap();
        let cache_dir = tempdir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let runtime = tokio::runtime::Handle::current();

        // Create a DiskCache. Force use_uncompressed = true regardless of FS support,
        // since we want to test the uncompressed storage path.
        let mut disk = DiskCache::new(
            &cache_dir,
            10 * 1024 * 1024,
            &runtime,
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
            false, // We'll override use_uncompressed below
        );
        disk.use_uncompressed = true;

        // Build a CacheWrite entry with a test object and stderr
        let mut entry = CacheWrite::new();
        let obj_content = b"hello world object content";
        entry
            .put_object(
                "output.rlib",
                &mut std::io::Cursor::new(obj_content),
                Some(0o644),
            )
            .unwrap();
        entry.put_stderr(b"some stderr output").unwrap();

        // Write the entry
        let key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        disk.put(key, entry).await.unwrap();

        // Verify the directory structure was created with marker file
        let key_path = make_key_path(key);
        let entry_dir = cache_dir.join(&key_path);
        assert!(entry_dir.is_dir(), "cache entry should be a directory");
        assert!(
            entry_dir
                .join(crate::lru_disk_cache::DIR_ENTRY_MARKER)
                .exists(),
            "marker file should exist"
        );
        assert!(
            entry_dir.join("output.rlib").exists(),
            "object file should exist"
        );
        assert!(
            entry_dir.join("stderr").exists(),
            "stderr file should exist"
        );
        // Read it back — should be an UncompressedHit
        let result = disk.get(key).await.unwrap();
        match result {
            Cache::UncompressedHit(ref uncompressed) => {
                // Verify stdout/stderr
                assert_eq!(uncompressed.get_stderr(), b"some stderr output");
                assert!(uncompressed.get_stdout().is_empty());
            }
            other => panic!("Expected UncompressedHit, got {:?}", other),
        }

        // Test extract_objects: extract the .rlib to a temp location
        if let Cache::UncompressedHit(uncompressed) = result {
            let output_dir = tempdir.path().join("output");
            std::fs::create_dir_all(&output_dir).unwrap();
            let output_path = output_dir.join("output.rlib");

            let objects = vec![FileObjectSource {
                key: "output.rlib".to_string(),
                path: output_path.clone(),
                optional: false,
            }];

            uncompressed
                .extract_objects(objects, &runtime)
                .await
                .unwrap();

            // Verify the extracted file has the correct content
            let extracted = std::fs::read(&output_path).unwrap();
            assert_eq!(
                extracted, obj_content,
                "extracted content should match original"
            );
        }
    }

    /// Test that a directory without a marker file is NOT treated as an UncompressedHit.
    #[tokio::test]
    async fn test_orphan_directory_not_returned_as_hit() {
        let tempdir = tempfile::tempdir().unwrap();
        let cache_dir = tempdir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let runtime = tokio::runtime::Handle::current();

        let disk = DiskCache::new(
            &cache_dir,
            10 * 1024 * 1024,
            &runtime,
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
            false,
        );

        // Manually create a directory that looks like a cache entry but has no marker
        let key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key_path = make_key_path(key);
        let orphan_dir = cache_dir.join(&key_path);
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("output.rlib"), b"some data").unwrap();

        // get() should return Miss, not UncompressedHit
        let result = disk.get(key).await.unwrap();
        assert!(
            matches!(result, Cache::Miss),
            "directory without marker should be a cache miss, got {:?}",
            result
        );
    }
}
