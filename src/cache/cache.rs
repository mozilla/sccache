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

use crate::cache::disk::DiskCache;
#[cfg(feature = "gcs")]
use crate::cache::gcs::{self, GCSCache, GCSCredentialProvider, RWMode, ServiceAccountInfo};
#[cfg(feature = "memcached")]
use crate::cache::memcached::MemcachedCache;
#[cfg(feature = "redis")]
use crate::cache::redis::RedisCache;
#[cfg(feature = "s3")]
use crate::cache::s3::S3Cache;
use crate::config::{self, CacheType, Config};
#[cfg(feature = "azure")]
use crate::{azure, cache::azure::AzureBlobCache};
use std::fmt;
use std::fs;
#[cfg(feature = "gcs")]
use std::fs::File;
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
        T: IntoIterator<Item = (String, PathBuf)> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            for (key, path) in objects {
                let dir = match path.parent() {
                    Some(d) => d,
                    None => bail!("Output file without a parent directory!"),
                };
                // Write the cache entry to a tempfile and then atomically
                // move it to its final location so that other rustc invocations
                // happening in parallel don't see a partially-written file.
                let mut tmp = NamedTempFile::new_in(dir)?;
                let mode = self.get_object(&key, &mut tmp)?;
                tmp.persist(&path)?;
                if let Some(mode) = mode {
                    set_file_mode(&path, mode)?;
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
        T: IntoIterator<Item = (String, PathBuf)> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            let mut entry = CacheWrite::new();
            for (key, path) in objects {
                let mut f = fs::File::open(&path)
                    .with_context(|| format!("failed to open file `{:?}`", path))?;
                let mode = get_file_mode(&f)?;
                entry
                    .put_object(&key, &mut f, mode)
                    .with_context(|| format!("failed to put object `{:?}` in cache entry", path))?;
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
        zstd::stream::copy_encode(from, &mut self.zip, 3)?;
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

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;
}

/// Get a suitable `Storage` implementation from configuration.
#[allow(clippy::cognitive_complexity)] // TODO simplify!
pub fn storage_from_config(config: &Config, pool: &tokio::runtime::Handle) -> Arc<dyn Storage> {
    for cache_type in config.caches.iter() {
        match *cache_type {
            CacheType::Azure(config::AzureCacheConfig { ref key_prefix }) => {
                debug!("Trying Azure Blob Store account({})", key_prefix);
                #[cfg(feature = "azure")]
                match azure::credentials_from_environment() {
                    Ok(creds) => match AzureBlobCache::new(creds, key_prefix) {
                        Ok(storage) => {
                            trace!("Using AzureBlobCache");
                            return Arc::new(storage);
                        }
                        Err(e) => warn!("Failed to create Azure cache: {:?}", e),
                    },
                    Err(err) => warn!(
                        "Failed to create Azure cache: could not find Azure credentials in the environment: {}",
                        err
                    ),
                }
            }
            CacheType::GCS(config::GCSCacheConfig {
                ref bucket,
                ref key_prefix,
                ref cred_path,
                ref deprecated_url,
                ref oauth_url,
                rw_mode,
            }) => {
                debug!(
                    "Trying GCS bucket({}, {}, {:?}, {:?}, {:?}, {:?})",
                    bucket, key_prefix, cred_path, deprecated_url, oauth_url, rw_mode
                );
                #[cfg(feature = "gcs")]
                {
                    let service_account_info_opt: Option<gcs::ServiceAccountInfo> =
                        if let Some(ref cred_path) = *cred_path {
                            // Attempt to read the service account key from file
                            let service_account_key_res: Result<gcs::ServiceAccountKey> = (|| {
                                let mut file = File::open(&cred_path)?;
                                let mut service_account_json = String::new();
                                file.read_to_string(&mut service_account_json)?;
                                Ok(serde_json::from_str(&service_account_json)?)
                            })(
                            );

                            // warn! if an error was encountered reading the key from the file
                            if let Err(ref e) = service_account_key_res {
                                warn!(
                                    "Failed to parse service account credentials from file: {:?}. \
                                     Continuing without authentication.",
                                    e
                                );
                            }

                            service_account_key_res
                                .ok()
                                .map(ServiceAccountInfo::AccountKey)
                        } else if let Some(ref url) = *deprecated_url {
                            Some(ServiceAccountInfo::DeprecatedUrl(url.clone()))
                        } else if let Some(ref url) = *oauth_url {
                            Some(ServiceAccountInfo::OAuthUrl(url.clone()))
                        } else {
                            warn!(
                            "No SCCACHE_GCS_KEY_PATH specified-- no authentication will be used."
                        );
                            None
                        };

                    let gcs_read_write_mode = match rw_mode {
                        config::GCSCacheRWMode::ReadOnly => RWMode::ReadOnly,
                        config::GCSCacheRWMode::ReadWrite => RWMode::ReadWrite,
                    };

                    let gcs_cred_provider = service_account_info_opt
                        .map(|info| GCSCredentialProvider::new(gcs_read_write_mode, info));

                    match GCSCache::new(
                        bucket.to_owned(),
                        key_prefix.to_owned(),
                        gcs_cred_provider,
                        gcs_read_write_mode,
                    ) {
                        Ok(s) => {
                            trace!("Using GCSCache");
                            return Arc::new(s);
                        }
                        Err(e) => warn!("Failed to create GCS Cache: {:?}", e),
                    }
                }
            }
            CacheType::Memcached(config::MemcachedCacheConfig { ref url }) => {
                debug!("Trying Memcached({})", url);
                #[cfg(feature = "memcached")]
                match MemcachedCache::new(url, pool) {
                    Ok(s) => {
                        trace!("Using Memcached: {}", url);
                        return Arc::new(s);
                    }
                    Err(e) => warn!("Failed to create MemcachedCache: {:?}", e),
                }
            }
            CacheType::Redis(config::RedisCacheConfig { ref url }) => {
                debug!("Trying Redis({})", url);
                #[cfg(feature = "redis")]
                match RedisCache::new(url) {
                    Ok(s) => {
                        trace!("Using Redis: {}", url);
                        return Arc::new(s);
                    }
                    Err(e) => warn!("Failed to create RedisCache: {:?}", e),
                }
            }
            CacheType::S3(ref c) => {
                debug!("Trying S3Cache({}, {})", c.bucket, c.endpoint);
                #[cfg(feature = "s3")]
                match S3Cache::new(&c.bucket, &c.endpoint, c.use_ssl, &c.key_prefix) {
                    Ok(s) => {
                        trace!("Using S3Cache");
                        return Arc::new(s);
                    }
                    Err(e) => warn!("Failed to create S3Cache: {:?}", e),
                }
            }
        }
    }

    info!("No configured caches successful, falling back to default");
    let (dir, size) = (&config.fallback_cache.dir, config.fallback_cache.size);
    trace!("Using DiskCache({:?}, {})", dir, size);
    Arc::new(DiskCache::new(&dir, size, pool))
}
