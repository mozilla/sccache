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

#[cfg(feature = "azure")]
use crate::cache::azure::AzureBlobCache;
use crate::cache::disk::DiskCache;
#[cfg(feature = "gcs")]
use crate::cache::gcs::GCSCache;
#[cfg(feature = "gha")]
use crate::cache::gha::GHACache;
#[cfg(feature = "memcached")]
use crate::cache::memcached::MemcachedCache;
#[cfg(feature = "oss")]
use crate::cache::oss::OSSCache;
#[cfg(feature = "redis")]
use crate::cache::redis::RedisCache;
#[cfg(feature = "s3")]
use crate::cache::s3::S3Cache;
#[cfg(feature = "webdav")]
use crate::cache::webdav::WebdavCache;
use crate::compiler::PreprocessorCacheEntry;
use crate::config::Config;
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss"
))]
use crate::config::{self, CacheType};
use async_trait::async_trait;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::errors::*;

#[cfg(unix)]
fn get_file_mode(file: &fs::File) -> Result<Option<u32>> {
    use std::os::unix::fs::MetadataExt;
    Ok(Some(file.metadata()?.mode()))
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn get_file_mode(_file: &fs::File) -> Result<Option<u32>> {
    Ok(None)
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let p = Permissions::from_mode(mode);
    fs::set_permissions(path, p)?;
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Cache object sourced by a file.
#[derive(Clone)]
pub struct FileObjectSource {
    /// Identifier for this object. Should be unique within a compilation unit.
    /// Note that a compilation unit is a single source file in C/C++ and a crate in Rust.
    pub key: String,
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Whether the file must be present on disk and is essential for the compilation.
    pub optional: bool,
}

/// Result of a cache lookup.
pub enum Cache {
    /// Result was found in cache.
    Hit(CacheRead),
    /// Result was not found in cache.
    Miss,
    /// Cache entry should be ignored, force compilation.
    Recache,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Cache::Hit(_) => write!(f, "Cache::Hit(...)"),
            Cache::Miss => write!(f, "Cache::Miss"),
            Cache::Recache => write!(f, "Cache::Recache"),
        }
    }
}

/// CacheMode is used to represent which mode we are using.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheMode {
    /// Only read cache from storage.
    ReadOnly,
    /// Full support of cache storage: read and write.
    ReadWrite,
}

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Data stored in the compiler cache.
pub struct CacheRead {
    zip: ZipArchive<Box<dyn ReadSeek>>,
}

/// Represents a failure to decompress stored object data.
#[derive(Debug)]
pub struct DecompressionFailure;

impl std::fmt::Display for DecompressionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to decompress content")
    }
}

impl std::error::Error for DecompressionFailure {}

impl CacheRead {
    /// Create a cache entry from `reader`.
    pub fn from<R>(reader: R) -> Result<CacheRead>
    where
        R: ReadSeek + 'static,
    {
        let z = ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>)
            .context("Failed to parse cache entry")?;
        Ok(CacheRead { zip: z })
    }

    /// Get an object from this cache entry at `name` and write it to `to`.
    /// If the file has stored permissions, return them.
    pub fn get_object<T>(&mut self, name: &str, to: &mut T) -> Result<Option<u32>>
    where
        T: Write,
    {
        let file = self.zip.by_name(name).or(Err(DecompressionFailure))?;
        if file.compression() != CompressionMethod::Stored {
            bail!(DecompressionFailure);
        }
        let mode = file.unix_mode();
        zstd::stream::copy_decode(file, to).or(Err(DecompressionFailure))?;
        Ok(mode)
    }

    /// Get the stdout from this cache entry, if it exists.
    pub fn get_stdout(&mut self) -> Vec<u8> {
        self.get_bytes("stdout")
    }

    /// Get the stderr from this cache entry, if it exists.
    pub fn get_stderr(&mut self) -> Vec<u8> {
        self.get_bytes("stderr")
    }

    fn get_bytes(&mut self, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        drop(self.get_object(name, &mut bytes));
        bytes
    }

    pub async fn extract_objects<T>(
        mut self,
        objects: T,
        pool: &tokio::runtime::Handle,
    ) -> Result<()>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                let dir = match path.parent() {
                    Some(d) => d,
                    None => bail!("Output file without a parent directory!"),
                };
                // Write the cache entry to a tempfile and then atomically
                // move it to its final location so that other rustc invocations
                // happening in parallel don't see a partially-written file.
                let mut tmp = NamedTempFile::new_in(dir)?;
                match (self.get_object(&key, &mut tmp), optional) {
                    (Ok(mode), _) => {
                        tmp.persist(&path)?;
                        if let Some(mode) = mode {
                            set_file_mode(&path, mode)?;
                        }
                    }
                    (Err(e), false) => return Err(e),
                    // skip if no object found and it's optional
                    (Err(_), true) => continue,
                }
            }
            Ok(())
        })
        .await?
    }
}

/// Data to be stored in the compiler cache.
pub struct CacheWrite {
    zip: ZipWriter<io::Cursor<Vec<u8>>>,
}

impl CacheWrite {
    /// Create a new, empty cache entry.
    pub fn new() -> CacheWrite {
        CacheWrite {
            zip: ZipWriter::new(io::Cursor::new(vec![])),
        }
    }

    /// Create a new cache entry populated with the contents of `objects`.
    pub async fn from_objects<T>(objects: T, pool: &tokio::runtime::Handle) -> Result<CacheWrite>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            let mut entry = CacheWrite::new();
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                let f = fs::File::open(&path)
                    .with_context(|| format!("failed to open file `{:?}`", path));
                match (f, optional) {
                    (Ok(mut f), _) => {
                        let mode = get_file_mode(&f)?;
                        entry.put_object(&key, &mut f, mode).with_context(|| {
                            format!("failed to put object `{:?}` in cache entry", path)
                        })?;
                    }
                    (Err(e), false) => return Err(e),
                    (Err(_), true) => continue,
                }
            }
            Ok(entry)
        })
        .await?
    }

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    /// If `mode` is `Some`, store the file entry with that mode.
    pub fn put_object<T>(&mut self, name: &str, from: &mut T, mode: Option<u32>) -> Result<()>
    where
        T: Read,
    {
        // We're going to declare the compression method as "stored",
        // but we're actually going to store zstd-compressed blobs.
        let opts = FileOptions::default().compression_method(CompressionMethod::Stored);
        let opts = if let Some(mode) = mode {
            opts.unix_permissions(mode)
        } else {
            opts
        };
        self.zip
            .start_file(name, opts)
            .context("Failed to start cache entry object")?;

        let compression_level = std::env::var("SCCACHE_CACHE_ZSTD_LEVEL")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(3);
        zstd::stream::copy_encode(from, &mut self.zip, compression_level)?;
        Ok(())
    }

    pub fn put_stdout(&mut self, bytes: &[u8]) -> Result<()> {
        self.put_bytes("stdout", bytes)
    }

    pub fn put_stderr(&mut self, bytes: &[u8]) -> Result<()> {
        self.put_bytes("stderr", bytes)
    }

    fn put_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        if !bytes.is_empty() {
            let mut cursor = Cursor::new(bytes);
            return self.put_object(name, &mut cursor, None);
        }
        Ok(())
    }

    /// Finish writing data to the cache entry writer, and return the data.
    pub fn finish(self) -> Result<Vec<u8>> {
        let CacheWrite { mut zip } = self;
        let cur = zip.finish().context("Failed to finish cache entry zip")?;
        Ok(cur.into_inner())
    }
}

impl Default for CacheWrite {
    fn default() -> Self {
        Self::new()
    }
}

/// An interface to cache storage.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    async fn get(&self, key: &str) -> Result<Cache>;

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration>;

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

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;

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

/// Configuration switches for preprocessor cache mode.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct PreprocessorCacheModeConfig {
    /// Whether to use preprocessor cache mode entirely
    pub use_preprocessor_cache_mode: bool,
    /// If false (default), only compare header files by hashing their contents.
    /// If true, will use size + ctime + mtime to check whether a file has changed.
    /// See other flags below for more control over this behavior.
    pub file_stat_matches: bool,
    /// If true (default), uses the ctime (file status change on UNIX,
    /// creation time on Windows) to check that a file has/hasn't changed.
    /// Can be useful to disable when backdating modification times
    /// in a controlled manner.
    pub use_ctime_for_stat: bool,
    /// If true, ignore `__DATE__`, `__TIME__` and `__TIMESTAMP__` being present
    /// in the source code. Will speed up preprocessor cache mode,
    /// but can result in false positives.
    pub ignore_time_macros: bool,
    /// If true, preprocessor cache mode will not cache system headers, only
    /// add them to the hash.
    pub skip_system_headers: bool,
    /// If true (default), will add the current working directory in the hash to
    /// distinguish two compilations from different directories.
    pub hash_working_directory: bool,
}

impl Default for PreprocessorCacheModeConfig {
    fn default() -> Self {
        Self {
            use_preprocessor_cache_mode: false,
            file_stat_matches: false,
            use_ctime_for_stat: true,
            ignore_time_macros: false,
            skip_system_headers: false,
            hash_working_directory: true,
        }
    }
}

impl PreprocessorCacheModeConfig {
    /// Return a default [`Self`], but with the cache active.
    pub fn activated() -> Self {
        Self {
            use_preprocessor_cache_mode: true,
            ..Default::default()
        }
    }
}

/// Implement storage for operator.
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
))]
#[async_trait]
impl Storage for opendal::Operator {
    async fn get(&self, key: &str) -> Result<Cache> {
        match self.read(&normalize_key(key)).await {
            Ok(res) => {
                let hit = CacheRead::from(io::Cursor::new(res.to_bytes()))?;
                Ok(Cache::Hit(hit))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(Cache::Miss),
            Err(e) => {
                warn!("Got unexpected error: {:?}", e);
                Ok(Cache::Miss)
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let start = std::time::Instant::now();

        self.write(&normalize_key(key), entry.finish()?).await?;

        Ok(start.elapsed())
    }

    async fn check(&self) -> Result<CacheMode> {
        use opendal::ErrorKind;

        let path = ".sccache_check";

        // Read is required, return error directly if we can't read .
        match self.read(path).await {
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
                eprintln!("cache storage read check: {err:?}, but we decide to keep running")
            }
            Err(err) => bail!("cache storage failed to read: {:?}", err),
        };

        let can_write = match self.write(path, "Hello, World!").await {
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
        let meta = self.info();
        format!(
            "{}, name: {}, prefix: {}",
            meta.scheme(),
            meta.name(),
            meta.root()
        )
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

/// Normalize key `abcdef` into `a/b/c/abcdef`
pub(in crate::cache) fn normalize_key(key: &str) -> String {
    format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key)
}

/// Get a suitable `Storage` implementation from configuration.
#[allow(clippy::cognitive_complexity)] // TODO simplify!
pub fn storage_from_config(
    config: &Config,
    pool: &tokio::runtime::Handle,
) -> Result<Arc<dyn Storage>> {
    if let Some(cache_type) = &config.cache {
        match cache_type {
            #[cfg(feature = "azure")]
            CacheType::Azure(config::AzureCacheConfig {
                ref connection_string,
                ref container,
                ref key_prefix,
            }) => {
                debug!("Init azure cache with container {container}, key_prefix {key_prefix}");
                let storage = AzureBlobCache::build(connection_string, container, key_prefix)
                    .map_err(|err| anyhow!("create azure cache failed: {err:?}"))?;
                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "gcs")]
            CacheType::GCS(config::GCSCacheConfig {
                ref bucket,
                ref key_prefix,
                ref cred_path,
                rw_mode,
                ref service_account,
                ref credential_url,
            }) => {
                debug!("Init gcs cache with bucket {bucket}, key_prefix {key_prefix}");

                let storage = GCSCache::build(
                    bucket,
                    key_prefix,
                    cred_path.as_deref(),
                    service_account.as_deref(),
                    (*rw_mode).into(),
                    credential_url.as_deref(),
                )
                .map_err(|err| anyhow!("create gcs cache failed: {err:?}"))?;

                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "gha")]
            CacheType::GHA(config::GHACacheConfig { ref version, .. }) => {
                debug!("Init gha cache with version {version}");

                let storage = GHACache::build(version)
                    .map_err(|err| anyhow!("create gha cache failed: {err:?}"))?;
                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "memcached")]
            CacheType::Memcached(config::MemcachedCacheConfig {
                ref url,
                ref username,
                ref password,
                ref expiration,
                ref key_prefix,
            }) => {
                debug!("Init memcached cache with url {url}");

                let storage = MemcachedCache::build(
                    url,
                    username.as_deref(),
                    password.as_deref(),
                    key_prefix,
                    *expiration,
                )
                .map_err(|err| anyhow!("create memcached cache failed: {err:?}"))?;
                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "redis")]
            CacheType::Redis(config::RedisCacheConfig {
                ref endpoint,
                ref cluster_endpoints,
                ref username,
                ref password,
                ref db,
                ref url,
                ref ttl,
                ref key_prefix,
            }) => {
                let storage = match (endpoint, cluster_endpoints, url) {
                    (Some(url), None, None) => {
                        debug!("Init redis single-node cache with url {url}");
                        RedisCache::build_single(
                            url,
                            username.as_deref(),
                            password.as_deref(),
                            *db,
                            key_prefix,
                            *ttl,
                        )
                    }
                    (None, Some(urls), None) => {
                        debug!("Init redis cluster cache with urls {urls}");
                        RedisCache::build_cluster(
                            urls,
                            username.as_deref(),
                            password.as_deref(),
                            *db,
                            key_prefix,
                            *ttl,
                        )
                    }
                    (None, None, Some(url)) => {
                        warn!("Init redis single-node cache from deprecated API with url {url}");
                        if username.is_some() || password.is_some() || *db != crate::config::DEFAULT_REDIS_DB {
                            bail!("`username`, `password` and `db` has no effect when `url` is set. Please use `endpoint` or `cluster_endpoints` for new API accessing");
                        }

                        RedisCache::build_from_url(url, key_prefix, *ttl)
                    }
                    _ => bail!("Only one of `endpoint`, `cluster_endpoints`, `url` must be set"),
                }
                .map_err(|err| anyhow!("create redis cache failed: {err:?}"))?;
                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "s3")]
            CacheType::S3(ref c) => {
                debug!(
                    "Init s3 cache with bucket {}, endpoint {:?}",
                    c.bucket, c.endpoint
                );

                let storage = S3Cache::build(
                    &c.bucket,
                    c.region.as_deref(),
                    &c.key_prefix,
                    c.no_credentials,
                    c.endpoint.as_deref(),
                    c.use_ssl,
                    c.server_side_encryption,
                )
                .map_err(|err| anyhow!("create s3 cache failed: {err:?}"))?;

                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "webdav")]
            CacheType::Webdav(ref c) => {
                debug!("Init webdav cache with endpoint {}", c.endpoint);

                let storage = WebdavCache::build(
                    &c.endpoint,
                    &c.key_prefix,
                    c.username.as_deref(),
                    c.password.as_deref(),
                    c.token.as_deref(),
                )
                .map_err(|err| anyhow!("create webdav cache failed: {err:?}"))?;

                return Ok(Arc::new(storage));
            }
            #[cfg(feature = "oss")]
            CacheType::OSS(ref c) => {
                debug!(
                    "Init oss cache with bucket {}, endpoint {:?}",
                    c.bucket, c.endpoint
                );

                let storage = OSSCache::build(
                    &c.bucket,
                    &c.key_prefix,
                    c.endpoint.as_deref(),
                    c.no_credentials,
                )
                .map_err(|err| anyhow!("create oss cache failed: {err:?}"))?;

                return Ok(Arc::new(storage));
            }
            #[allow(unreachable_patterns)]
            // if we build only with `cargo build --no-default-features`
            // we only want to use sccache with a local cache (no remote storage)
            _ => {}
        }
    }

    let (dir, size) = (&config.fallback_cache.dir, config.fallback_cache.size);
    let preprocessor_cache_mode_config = config.fallback_cache.preprocessor_cache_mode;
    let rw_mode = config.fallback_cache.rw_mode.into();
    debug!("Init disk cache with dir {:?}, size {}", dir, size);
    Ok(Arc::new(DiskCache::new(
        dir,
        size,
        pool,
        preprocessor_cache_mode_config,
        rw_mode,
    )))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::CacheModeConfig;

    #[test]
    fn test_normalize_key() {
        assert_eq!(
            normalize_key("0123456789abcdef0123456789abcdef"),
            "0/1/2/0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_read_write_mode_local() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Use disk cache.
        let mut config = Config {
            cache: None,
            ..Default::default()
        };

        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test_rust_cargo")
            .tempdir()
            .context("Failed to create tempdir")
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        config.fallback_cache.dir = cache_dir;

        // Test Read Write
        config.fallback_cache.rw_mode = CacheModeConfig::ReadWrite;

        {
            let cache = storage_from_config(&config, runtime.handle()).unwrap();

            runtime.block_on(async move {
                cache.put("test1", CacheWrite::default()).await.unwrap();
                cache
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .await
                    .unwrap();
            });
        }

        // Test Read-only
        config.fallback_cache.rw_mode = CacheModeConfig::ReadOnly;

        {
            let cache = storage_from_config(&config, runtime.handle()).unwrap();

            runtime.block_on(async move {
                assert_eq!(
                    cache
                        .put("test1", CacheWrite::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
                assert_eq!(
                    cache
                        .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
            });
        }
    }
}
