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
use cache::azure::AzureBlobCache;
use cache::disk::DiskCache;
#[cfg(feature = "gcs")]
use cache::gcs::{self, GCSCache, GCSCredentialProvider, RWMode};
#[cfg(feature = "memcached")]
use cache::memcached::MemcachedCache;
#[cfg(feature = "redis")]
use cache::redis::RedisCache;
#[cfg(feature = "s3")]
use cache::s3::S3Cache;
use config::{self, CacheType, Config};
use futures_cpupool::CpuPool;
#[cfg(feature = "gcs")]
use serde_json;
use std::fmt;
#[cfg(feature = "gcs")]
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::sync::Arc;
use std::time::Duration;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use errors::*;

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    zip: ZipArchive<Box<ReadSeek>>,
}

impl CacheRead {
    /// Create a cache entry from `reader`.
    pub fn from<R>(reader: R) -> Result<CacheRead>
    where
        R: ReadSeek + 'static,
    {
        let z = ZipArchive::new(Box::new(reader) as Box<ReadSeek>)
            .chain_err(|| "Failed to parse cache entry")?;
        Ok(CacheRead { zip: z })
    }

    /// Get an object from this cache entry at `name` and write it to `to`.
    /// If the file has stored permissions, return them.
    pub fn get_object<T>(&mut self, name: &str, to: &mut T) -> Result<Option<u32>>
    where
        T: Write,
    {
        let mut file = self
            .zip
            .by_name(name)
            .chain_err(|| "Failed to read object from cache entry")?;
        io::copy(&mut file, to)?;
        Ok(file.unix_mode())
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

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    /// If `mode` is `Some`, store the file entry with that mode.
    pub fn put_object<T>(&mut self, name: &str, from: &mut T, mode: Option<u32>) -> Result<()>
    where
        T: Read,
    {
        let opts = FileOptions::default().compression_method(CompressionMethod::Deflated);
        let opts = if let Some(mode) = mode {
            opts.unix_permissions(mode)
        } else {
            opts
        };
        self.zip
            .start_file(name, opts)
            .chain_err(|| "Failed to start cache entry object")?;
        io::copy(from, &mut self.zip)?;
        Ok(())
    }

    /// Finish writing data to the cache entry writer, and return the data.
    pub fn finish(self) -> Result<Vec<u8>> {
        let CacheWrite { mut zip } = self;
        let cur = zip
            .finish()
            .chain_err(|| "Failed to finish cache entry zip")?;
        Ok(cur.into_inner())
    }
}

/// An interface to cache storage.
pub trait Storage {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    fn get(&self, key: &str) -> SFuture<Cache>;

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration>;

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the current storage usage, if applicable.
    fn current_size(&self) -> SFuture<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    fn max_size(&self) -> SFuture<Option<u64>>;
}

/// Get a suitable `Storage` implementation from configuration.
pub fn storage_from_config(config: &Config, pool: &CpuPool) -> Arc<Storage> {
    for cache_type in config.caches.iter() {
        match *cache_type {
            CacheType::Azure(config::AzureCacheConfig) => {
                debug!("Trying Azure Blob Store account");
                #[cfg(feature = "azure")]
                match AzureBlobCache::new() {
                    Ok(storage) => {
                        trace!("Using AzureBlobCache");
                        return Arc::new(storage);
                    }
                    Err(e) => warn!("Failed to create Azure cache: {:?}", e),
                }
            }
            CacheType::GCS(config::GCSCacheConfig {
                ref bucket,
                ref cred_path,
                rw_mode,
            }) => {
                debug!(
                    "Trying GCS bucket({}, {:?}, {:?})",
                    bucket, cred_path, rw_mode
                );
                #[cfg(feature = "gcs")]
                {
                    let service_account_key_opt: Option<gcs::ServiceAccountKey> =
                        if let Some(ref cred_path) = *cred_path {
                            // Attempt to read the service account key from file
                            let service_account_key_res: Result<
                                gcs::ServiceAccountKey,
                            > = (|| {
                                let mut file = File::open(&cred_path)?;
                                let mut service_account_json = String::new();
                                file.read_to_string(&mut service_account_json)?;
                                Ok(serde_json::from_str(&service_account_json)?)
                            })();

                            // warn! if an error was encountered reading the key from the file
                            if let Err(ref e) = service_account_key_res {
                                warn!(
                                    "Failed to parse service account credentials from file: {:?}. \
                                     Continuing without authentication.",
                                    e
                                );
                            }

                            service_account_key_res.ok()
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

                    let gcs_cred_provider = service_account_key_opt
                        .map(|path| GCSCredentialProvider::new(gcs_read_write_mode, path));

                    match GCSCache::new(bucket.to_owned(), gcs_cred_provider, gcs_read_write_mode) {
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
                match MemcachedCache::new(&url, pool) {
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
                match RedisCache::new(&url) {
                    Ok(s) => {
                        trace!("Using Redis: {}", url);
                        return Arc::new(s);
                    }
                    Err(e) => warn!("Failed to create RedisCache: {:?}", e),
                }
            }
            CacheType::S3(ref config) => {
                debug!("Trying S3Cache: {:?}", config);
                #[cfg(feature = "s3")]
                match S3Cache::new(config) {
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
