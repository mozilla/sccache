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

use crate::cache::cache_io::{
    FileObjectSource, OBJECTS_SUBDIR, is_path_null, serialize_mode_manifest, validate_object_key,
};
use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, Storage, UncompressedCacheEntry};
use crate::compiler::PreprocessorCacheEntry;
use crate::lru_disk_cache::{DIR_ENTRY_MARKER, Error as LruError, ReadSeek, TEMPFILE_PREFIX};
use async_trait::async_trait;
use bytes::Bytes;
use fs_err as fs;
use std::ffi::OsStr;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::*;

use super::lazy_disk_cache::LazyDiskCache;
use super::utils::{file_mode_of, normalize_key, set_file_mode};
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
    /// `file_clone`: store entries uncompressed and restore them via reflinks.
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
        if file_clone {
            let root_path = Path::new(root.as_ref());
            #[cfg(unix)]
            let preexisting_mode = {
                use std::os::unix::fs::PermissionsExt;
                std::fs::metadata(root_path)
                    .ok()
                    .map(|m| m.permissions().mode() & 0o7777)
            };
            let _ = std::fs::create_dir_all(root_path);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = preexisting_mode {
                    if mode & 0o077 != 0 {
                        warn!(
                            "file_clone: tightening pre-existing cache directory {root_path:?} \
                             permissions from {mode:#o} to 0700 (an uncompressed cache must be \
                             user-private). Do not point SCCACHE_DIR at a shared/group cache \
                             directory when using file_clone."
                        );
                    }
                }
                match std::fs::set_permissions(root_path, std::fs::Permissions::from_mode(0o700)) {
                    Ok(()) => {
                        debug!("file_clone: cache directory {root_path:?} is private (0700)");
                    }
                    Err(e) => warn!(
                        "file_clone: could not make cache directory {root_path:?} private (chmod \
                         0700 failed: {e}). An uncompressed cache readable/writable by other users \
                         can be poisoned; point SCCACHE_DIR at a directory you own."
                    ),
                }
            }
            if crate::reflink::is_reflink_supported(root_path) {
                debug!("file_clone enabled: uncompressed storage with reflink (copy-on-write)");
            } else {
                warn!(
                    "file_clone enabled but the cache directory's filesystem does not support \
                     reflinks: entries are stored uncompressed and restored via copies, so they \
                     will not share disk blocks with the cache. Put the cache directory and the \
                     build directory on the same copy-on-write filesystem (Btrfs/XFS/APFS/ReFS) \
                     for the full benefit."
                );
            }
        }
        DiskCache {
            lru: Arc::new(Mutex::new(LazyDiskCache::Uninit {
                root: root.as_ref().to_os_string(),
                max_size,
                support_dir_entries: file_clone,
            })),
            pool: pool.clone(),
            preprocessor_cache_mode_config,
            preprocessor_cache: Arc::new(Mutex::new(LazyDiskCache::Uninit {
                root: Path::new(root.as_ref())
                    .join("preprocessor")
                    .into_os_string(),
                max_size,
                support_dir_entries: false,
            })),
            rw_mode,
            basedirs,
            use_uncompressed: file_clone,
        }
    }
}

/// Make a path to the cache entry with key `key`.
fn make_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}

fn is_uncompressed_entry(cache_root: &Path, key_path: &Path) -> bool {
    let path = cache_root.join(key_path);
    path.is_dir() && path.join(DIR_ENTRY_MARKER).exists()
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    set_file_mode(path, 0o600)?;
    Ok(())
}

#[async_trait]
impl Storage for DiskCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        trace!("DiskCache::get({})", key);
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let key = key.to_owned();
        let use_uncompressed = self.use_uncompressed;

        self.pool
            .spawn_blocking(move || {
                let mut binding = lru.lock().unwrap();
                let cache = binding.get_or_init()?;

                if use_uncompressed {
                    let cache_root = cache.path().to_path_buf();
                    if is_uncompressed_entry(&cache_root, &path) {
                        let _ = cache.touch(&path);
                        trace!("DiskCache::get({}): UncompressedHit", key);
                        return Ok(Cache::UncompressedHit(UncompressedCacheEntry::new(
                            cache_root.join(&path),
                        )));
                    }
                }

                let io = match cache.get(&path) {
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

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        trace!("DiskCache::get_raw({})", key);
        let path = make_key_path(key);
        let lru = self.lru.clone();
        let key = key.to_owned();
        let use_uncompressed = self.use_uncompressed;

        self.pool
            .spawn_blocking(move || {
                let mut binding = lru.lock().unwrap();
                let cache = binding.get_or_init()?;
                if use_uncompressed && is_uncompressed_entry(cache.path(), &path) {
                    trace!(
                        "DiskCache::get_raw({}): uncompressed entry, returning None",
                        key
                    );
                    return Ok(None);
                }
                match cache.get(&path) {
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

    async fn put_objects(
        &self,
        key: &str,
        objects: Vec<FileObjectSource>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        pool: &tokio::runtime::Handle,
    ) -> Result<Duration> {
        if self.rw_mode == CacheMode::ReadOnly {
            return Err(anyhow!("Cannot write to a read-only cache"));
        }

        if !self.use_uncompressed {
            let mut entry = CacheWrite::from_objects(objects, pool).await?;
            entry.put_stdout(&stdout)?;
            entry.put_stderr(&stderr)?;
            return self.put(key, entry).await;
        }

        let lru = self.lru.clone();
        let key_path = make_key_path(key);

        pool.spawn_blocking(move || {
            let start = Instant::now();
            let cache_root = {
                let mut binding = lru.lock().unwrap();
                binding.get_or_init()?.path().to_path_buf()
            };

            let mut builder = tempfile::Builder::new();
            builder.prefix(TEMPFILE_PREFIX);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                builder.permissions(std::fs::Permissions::from_mode(0o700));
            }
            let staging = builder.tempdir_in(&cache_root)?;
            let objects_dir = staging.path().join(OBJECTS_SUBDIR);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&objects_dir)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(&objects_dir)?;

            let mut mode_manifest: Vec<(String, u32)> = Vec::new();
            let mut stored_count = 0usize;

            for FileObjectSource {
                key: obj_key,
                path,
                optional,
            } in objects
            {
                if let Err(e) = validate_object_key(&obj_key) {
                    if optional {
                        continue;
                    }
                    return Err(e);
                }
                let dest = objects_dir.join(&obj_key);
                if is_path_null(&path) {
                    write_private(&dest, b"")?;
                    stored_count += 1;
                    continue;
                }
                let mode = match fs::metadata(&path) {
                    Ok(meta) => file_mode_of(&meta),
                    Err(e) => {
                        if optional {
                            continue;
                        }
                        return Err(e).with_context(|| {
                            format!("failed to read compiler output `{}`", path.display())
                        });
                    }
                };
                if let Err(e) = crate::reflink::reflink_or_copy_new(&path, &dest, Some(0o600)) {
                    let _ = fs::remove_file(&dest);
                    if optional {
                        continue;
                    }
                    return Err(anyhow::Error::from(e)).with_context(|| {
                        format!("failed to store compiler output `{}`", path.display())
                    });
                }
                if let Some(mode) = mode {
                    mode_manifest.push((obj_key, mode));
                }
                stored_count += 1;
            }

            if stored_count == 0 {
                return Ok(start.elapsed());
            }

            if !stdout.is_empty() {
                write_private(&staging.path().join("stdout"), &stdout)?;
            }
            if !stderr.is_empty() {
                write_private(&staging.path().join("stderr"), &stderr)?;
            }
            write_private(
                &staging.path().join(DIR_ENTRY_MARKER),
                &serialize_mode_manifest(&mode_manifest),
            )?;

            let mut binding = lru.lock().unwrap();
            let cache = binding.get_or_init()?;
            #[allow(deprecated)] // `into_path` is not deprecated in the locked tempfile 3.10.1
            let staging_path = staging.into_path();
            if let Err(e) = cache.insert_dir(&key_path, &staging_path) {
                let _ = fs::remove_dir_all(&staging_path);
                return Err(e.into());
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

    fn new_disk_cache(
        root: &Path,
        runtime: &tokio::runtime::Runtime,
        file_clone: bool,
    ) -> DiskCache {
        DiskCache::new(
            root,
            100 * 1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
            file_clone,
        )
    }

    fn fobj(key: &str, path: &Path) -> FileObjectSource {
        FileObjectSource {
            key: key.to_string(),
            path: path.to_path_buf(),
            optional: false,
        }
    }

    const TEST_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn mt_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_disk_cache_type_name() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let disk = new_disk_cache(tempdir.path(), &runtime, false);

        assert_eq!(disk.cache_type_name(), "disk");
    }

    #[test]
    fn test_uncompressed_put_objects_get_roundtrip() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let build = tempdir.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        let obj_path = build.join("output.o");
        std::fs::write(&obj_path, b"raw object bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&obj_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                b"the stdout".to_vec(),
                b"the stderr".to_vec(),
                runtime.handle(),
            ))
            .unwrap();

        let entry_dir = cache_dir.join(make_key_path(TEST_KEY));
        assert!(entry_dir.is_dir(), "entry should be a directory");
        assert!(entry_dir.join(DIR_ENTRY_MARKER).exists(), "marker present");
        let obj_file = entry_dir.join(OBJECTS_SUBDIR).join("obj");
        assert_eq!(
            std::fs::read(&obj_file).unwrap(),
            b"raw object bytes",
            "stored object is uncompressed and byte-identical"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&obj_file).unwrap().permissions().mode() & 0o777,
                0o600,
                "cache object must be stored 0600"
            );
        }

        match runtime.block_on(disk.get(TEST_KEY)).unwrap() {
            Cache::UncompressedHit(entry) => {
                assert_eq!(entry.get_stdout(), b"the stdout");
                assert_eq!(entry.get_stderr(), b"the stderr");
            }
            other => panic!("expected UncompressedHit, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_uncompressed_put_objects_dirs_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let obj_path = tempdir.path().join("orig.o");
        std::fs::write(&obj_path, b"data").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();

        let entry_dir = cache_dir.join(make_key_path(TEST_KEY));
        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_of(&entry_dir),
            0o700,
            "entry directory must be user-private (0700)"
        );
        assert_eq!(
            mode_of(&entry_dir.join(OBJECTS_SUBDIR)),
            0o700,
            "objects/ subdir must be user-private (0700)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_uncompressed_empty_stdio_and_mode_restore() {
        use std::os::unix::fs::PermissionsExt;
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let bin = tempdir.path().join("a.out");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &bin)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();

        let entry_dir = cache_dir.join(make_key_path(TEST_KEY));
        assert!(
            !entry_dir.join("stdout").exists(),
            "empty stdout not stored"
        );
        assert!(
            !entry_dir.join("stderr").exists(),
            "empty stderr not stored"
        );

        let out = tempdir.path().join("restored.out");
        let Cache::UncompressedHit(entry) = runtime.block_on(disk.get(TEST_KEY)).unwrap() else {
            panic!("expected UncompressedHit");
        };
        runtime
            .block_on(entry.extract_objects(vec![fobj("obj", &out)], runtime.handle()))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn test_object_key_named_stdout_does_not_collide() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let obj = tempdir.path().join("obj_named_stdout");
        std::fs::write(&obj, b"object-content").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("stdout", &obj)],
                b"PROCESS STDOUT".to_vec(),
                vec![],
                runtime.handle(),
            ))
            .unwrap();

        let out = tempdir.path().join("restored_stdout_obj");
        let Cache::UncompressedHit(entry) = runtime.block_on(disk.get(TEST_KEY)).unwrap() else {
            panic!("expected UncompressedHit");
        };
        assert_eq!(entry.get_stdout(), b"PROCESS STDOUT");
        runtime
            .block_on(entry.extract_objects(vec![fobj("stdout", &out)], runtime.handle()))
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"object-content");
    }

    #[test]
    fn test_uncompressed_extract_roundtrip() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let obj_path = tempdir.path().join("orig.o");
        std::fs::write(&obj_path, b"hello reflink world").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();

        let restore_path = tempdir.path().join("restored").join("out.o");
        let cache = runtime.block_on(disk.get(TEST_KEY)).unwrap();
        let Cache::UncompressedHit(entry) = cache else {
            panic!("expected UncompressedHit");
        };
        let stats = runtime
            .block_on(entry.extract_objects(vec![fobj("obj", &restore_path)], runtime.handle()))
            .unwrap();
        assert_eq!(
            std::fs::read(&restore_path).unwrap(),
            b"hello reflink world"
        );
        assert_eq!(stats.objects_reflinked + stats.objects_copied, 1);
    }

    #[test]
    fn test_mode_switch_compressed_then_uncompressed() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");

        {
            let disk = new_disk_cache(&cache_dir, &runtime, false);
            let mut entry = CacheWrite::new();
            entry
                .put_object("obj", &mut std::io::Cursor::new(b"compressed"), Some(0o644))
                .unwrap();
            runtime.block_on(disk.put(TEST_KEY, entry)).unwrap();
            assert!(matches!(
                runtime.block_on(disk.get(TEST_KEY)).unwrap(),
                Cache::Hit(_)
            ));
        }
        {
            let disk = new_disk_cache(&cache_dir, &runtime, true);
            let obj_path = tempdir.path().join("orig.o");
            std::fs::write(&obj_path, b"uncompressed").unwrap();
            runtime
                .block_on(disk.put_objects(
                    TEST_KEY,
                    vec![fobj("obj", &obj_path)],
                    vec![],
                    vec![],
                    runtime.handle(),
                ))
                .unwrap();
            assert!(matches!(
                runtime.block_on(disk.get(TEST_KEY)).unwrap(),
                Cache::UncompressedHit(_)
            ));
            let entry_path = cache_dir.join(make_key_path(TEST_KEY));
            assert!(entry_path.is_dir(), "key should now be a directory");
        }
    }

    #[test]
    fn test_mode_switch_uncompressed_then_compressed() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let obj_path = tempdir.path().join("orig.o");
        std::fs::write(&obj_path, b"uncompressed").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();
        assert!(cache_dir.join(make_key_path(TEST_KEY)).is_dir());

        let mut entry = CacheWrite::new();
        entry
            .put_object("obj", &mut std::io::Cursor::new(b"compressed"), Some(0o644))
            .unwrap();
        runtime.block_on(disk.put(TEST_KEY, entry)).unwrap();
        assert!(cache_dir.join(make_key_path(TEST_KEY)).is_file());
        assert!(matches!(
            runtime.block_on(disk.get(TEST_KEY)).unwrap(),
            Cache::Hit(_)
        ));
    }

    #[test]
    fn test_default_cache_uses_compressed_entries() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, false);

        let obj_path = tempdir.path().join("orig.o");
        std::fs::write(&obj_path, b"data").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();
        assert!(cache_dir.join(make_key_path(TEST_KEY)).is_file());
        assert!(matches!(
            runtime.block_on(disk.get(TEST_KEY)).unwrap(),
            Cache::Hit(_)
        ));
    }

    #[test]
    fn test_preprocessor_cache_untouched_with_file_clone() {
        use crate::compiler::PreprocessorCacheEntry;

        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let obj_path = tempdir.path().join("orig.o");
        std::fs::write(&obj_path, b"obj").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();
        let object_size = runtime.block_on(disk.current_size()).unwrap();
        runtime
            .block_on(disk.put_preprocessor_cache_entry(TEST_KEY, PreprocessorCacheEntry::new()))
            .unwrap();

        let preprocessor_root = cache_dir.join("preprocessor");
        assert!(
            preprocessor_root.is_dir(),
            "preprocessor subtree must exist"
        );

        // Re-open the object cache and force its file_clone init walk, which prunes the sibling
        // preprocessor subtree from the object cache's own bookkeeping.
        drop(disk);
        let disk = new_disk_cache(&cache_dir, &runtime, true);
        assert!(matches!(
            runtime.block_on(disk.get(TEST_KEY)).unwrap(),
            Cache::UncompressedHit(_)
        ));

        // That init must leave the preprocessor subtree and its entry untouched on disk.
        assert!(
            preprocessor_root.is_dir(),
            "preprocessor subtree must survive object cache re-init"
        );
        let preprocessor_entry = cache_dir
            .join("preprocessor")
            .join(&TEST_KEY[0..1])
            .join(&TEST_KEY[1..2])
            .join(&TEST_KEY[2..3])
            .join(TEST_KEY);
        assert!(
            preprocessor_entry.is_file(),
            "preprocessor entry must not be pruned by the object cache"
        );

        // The object cache must not count the preprocessor files toward its size.
        assert_eq!(
            runtime.block_on(disk.current_size()).unwrap(),
            object_size,
            "object cache must not count preprocessor files after re-init"
        );
    }

    #[test]
    fn test_get_raw_uncompressed_returns_none() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();
        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);

        let obj_path = tempdir.path().join("orig.o");
        std::fs::write(&obj_path, b"data").unwrap();
        runtime
            .block_on(disk.put_objects(
                TEST_KEY,
                vec![fobj("obj", &obj_path)],
                vec![],
                vec![],
                runtime.handle(),
            ))
            .unwrap();
        assert!(
            runtime.block_on(disk.get_raw(TEST_KEY)).unwrap().is_none(),
            "uncompressed entry must not expose raw bytes"
        );

        // A compressed entry on the same cache does expose raw bytes.
        const KEY2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let mut entry = CacheWrite::new();
        entry
            .put_object("obj", &mut std::io::Cursor::new(b"x"), Some(0o644))
            .unwrap();
        runtime.block_on(disk.put(KEY2, entry)).unwrap();
        assert!(runtime.block_on(disk.get_raw(KEY2)).unwrap().is_some());
    }

    #[test]
    fn test_put_objects_branches() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();

        let ro_dir = tempdir.path().join("ro");
        let ro = DiskCache::new(
            &ro_dir,
            100 * 1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadOnly,
            vec![],
            true,
        );
        let f = tempdir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        assert!(
            runtime
                .block_on(ro.put_objects(
                    TEST_KEY,
                    vec![fobj("obj", &f)],
                    vec![],
                    vec![],
                    runtime.handle()
                ))
                .is_err()
        );

        let cache_dir = tempdir.path().join("cache");
        let disk = new_disk_cache(&cache_dir, &runtime, true);
        let missing = FileObjectSource {
            key: "obj".to_string(),
            path: tempdir.path().join("does-not-exist"),
            optional: true,
        };
        runtime
            .block_on(disk.put_objects(TEST_KEY, vec![missing], vec![], vec![], runtime.handle()))
            .unwrap();
        assert!(
            !cache_dir.join(make_key_path(TEST_KEY)).exists(),
            "no entry for empty object set"
        );
        assert!(matches!(
            runtime.block_on(disk.get(TEST_KEY)).unwrap(),
            Cache::Miss
        ));

        let required_missing = FileObjectSource {
            key: "obj".to_string(),
            path: tempdir.path().join("also-missing"),
            optional: false,
        };
        assert!(
            runtime
                .block_on(disk.put_objects(
                    TEST_KEY,
                    vec![required_missing],
                    vec![],
                    vec![],
                    runtime.handle()
                ))
                .is_err()
        );

        #[cfg(unix)]
        {
            const KEY3: &str = "1111111111111111111111111111111111111111111111111111111111111111";
            runtime
                .block_on(disk.put_objects(
                    KEY3,
                    vec![fobj("obj", Path::new("/dev/null"))],
                    vec![],
                    vec![],
                    runtime.handle(),
                ))
                .unwrap();
            let obj = cache_dir
                .join(make_key_path(KEY3))
                .join(OBJECTS_SUBDIR)
                .join("obj");
            assert!(obj.exists(), "null output stored as empty object");
            assert_eq!(std::fs::metadata(&obj).unwrap().len(), 0);
        }
    }

    #[test]
    fn test_concurrent_same_key_put_objects() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = mt_runtime();
        let cache_dir = tempdir.path().join("cache");
        let disk = std::sync::Arc::new(new_disk_cache(&cache_dir, &runtime, true));

        runtime.block_on(async {
            let mut handles = Vec::new();
            for i in 0..8u8 {
                let disk = disk.clone();
                let src = tempdir.path().join(format!("src{i}"));
                std::fs::write(&src, vec![b'a' + i; 4096]).unwrap();
                let handle = disk.pool.clone();
                handles.push(tokio::spawn(async move {
                    disk.put_objects(
                        TEST_KEY,
                        vec![FileObjectSource {
                            key: "obj".to_string(),
                            path: src,
                            optional: false,
                        }],
                        vec![],
                        vec![],
                        &handle,
                    )
                    .await
                }));
            }
            for h in handles {
                h.await.unwrap().unwrap();
            }
        });

        let entry_dir = cache_dir.join(make_key_path(TEST_KEY));
        assert!(entry_dir.join(DIR_ENTRY_MARKER).exists());
        let content = std::fs::read(entry_dir.join(OBJECTS_SUBDIR).join("obj")).unwrap();
        assert_eq!(content.len(), 4096);
        assert!((b'a'..=b'h').contains(&content[0]) && content.iter().all(|&b| b == content[0]));
        let leftovers: Vec<_> = std::fs::read_dir(&cache_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(TEMPFILE_PREFIX))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no leftover .sccachetmp* staging dirs"
        );
        assert!(matches!(
            runtime.block_on(disk.get(TEST_KEY)).unwrap(),
            Cache::UncompressedHit(_)
        ));
    }
}
