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
use cache::two_tier_disk::TwoTierDiskCache;
#[cfg(feature = "memcached")]
use cache::memcached::MemcachedCache;
#[cfg(feature = "redis")]
use cache::redis::RedisCache;
#[cfg(feature = "s3")]
use cache::s3::S3Cache;
#[cfg(feature = "gcs")]
use cache::gcs::{self, GCSCache, GCSCredentialProvider, RWMode};
use directories::ProjectDirs;
use futures_cpupool::CpuPool;
use regex::Regex;
#[cfg(feature = "gcs")]
use serde_json;
use std::env;
use std::fmt;
use std::io::{
    self,
    Read,
    Seek,
    Write,
};
#[cfg(feature = "gcs")]
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_core::reactor::Handle;
use zip::{CompressionMethod, ZipArchive, ZipWriter};
use zip::write::FileOptions;

use errors::*;

//TODO: might need to put this somewhere more central
const ORGANIZATION: &str = "Mozilla";
const APP_NAME: &str = "sccache";
const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;

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
pub trait ReadSeek : Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Data stored in the compiler cache.
pub struct CacheRead {
    zip: ZipArchive<Box<ReadSeek>>,
}

impl CacheRead {
    /// Create a cache entry from `reader`.
    pub fn from<R>(reader: R) -> Result<CacheRead>
        where R: ReadSeek + 'static,
    {
        let z = ZipArchive::new(Box::new(reader) as Box<ReadSeek>).chain_err(|| {
            "Failed to parse cache entry"
        })?;
        Ok(CacheRead {
            zip: z,
        })
    }

    /// Get an object from this cache entry at `name` and write it to `to`.
    /// If the file has stored permissions, return them.
    pub fn get_object<T>(&mut self, name: &str, to: &mut T) -> Result<Option<u32>>
        where T: Write,
    {
        let mut file = self.zip.by_name(name).chain_err(|| {
            "Failed to read object from cache entry"
        })?;
        io::copy(&mut file, to)?;
        Ok(file.unix_mode())
    }

    pub fn to_write(&mut self) -> CacheWrite {
        let mut write = CacheWrite::new();
        for i in 0..self.zip.len() {
            // Mutable borrows mean we have to unwrap twice
            let mut file = self.zip.by_index(i).unwrap();
            let file_name = String::from(file.name());
            let mode = file.unix_mode();
            write.put_object(&file_name, &mut file, mode);
        }
        write
    }
}

/// Data to be stored in the compiler cache.
pub struct CacheWrite {
    zip: ZipWriter<io::Cursor<Vec<u8>>>,
}

impl CacheWrite {
    /// Create a new, empty cache entry.
    pub fn new() -> CacheWrite
    {
        CacheWrite {
            zip: ZipWriter::new(io::Cursor::new(vec!())),
        }
    }

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    /// If `mode` is `Some`, store the file entry with that mode.
    pub fn put_object<T>(&mut self, name: &str, from: &mut T, mode: Option<u32>) -> Result<()>
        where T: Read,
    {
        let opts = FileOptions::default().compression_method(CompressionMethod::Deflated);
        let opts = if let Some(mode) = mode { opts.unix_permissions(mode) } else { opts };
        self.zip.start_file(name, opts).chain_err(|| {
            "Failed to start cache entry object"
        })?;
        io::copy(from, &mut self.zip)?;
        Ok(())
    }

    /// Finish writing data to the cache entry writer, and return the data.
    pub fn finish(self) -> Result<Vec<u8>>
    {
        let CacheWrite { mut zip } = self;
        let cur = zip.finish().chain_err(|| "Failed to finish cache entry zip")?;
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
    fn current_size(&self) -> Option<u64>;

    /// Get the maximum storage size, if applicable.
    fn max_size(&self) -> Option<u64>;
}

fn parse_size(val: &str) -> Option<u64> {
    let re = Regex::new(r"^(\d+)([KMGT])$").unwrap();
    re.captures(val)
        .and_then(|caps| {
            caps.get(1)
                .and_then(|size| u64::from_str(size.as_str()).ok())
                .and_then(|size| Some((size, caps.get(2))))
        })
        .and_then(|(size, suffix)| {
            match suffix.map(|s| s.as_str()) {
                Some("K") => Some(1024 * size),
                Some("M") => Some(1024 * 1024 * size),
                Some("G") => Some(1024 * 1024 * 1024 * size),
                Some("T") => Some(1024 * 1024 * 1024 * 1024 * size),
                _ => None,
            }
        })
}

/// Get a suitable `Storage` implementation from the environment.
pub fn storage_from_environment(pool: &CpuPool, _handle: &Handle) -> Arc<Storage> {
    let base = base_storage_from_environment(pool, _handle);
    if let Ok(_use_two_tier) = env::var("SCCACHE_TWO_TIER") {
        trace!("Using two tier cache");
        return Arc::new(TwoTierDiskCache::new(base, get_disk_storage(pool)))
    }
    base
}
pub fn get_disk_storage(pool: &CpuPool) -> Arc<DiskCache> {
    let disk_cache_path = env::var_os("SCCACHE_DIR")
        .map(|p| PathBuf::from(p))
        .unwrap_or_else(|| {
            let dirs = ProjectDirs::from("", ORGANIZATION, APP_NAME);
            dirs.cache_dir().to_owned()
        });
    let disk_cache_size: u64 = env::var("SCCACHE_CACHE_SIZE")
        .ok()
        .and_then(|v| parse_size(&v))
        .unwrap_or(TEN_GIGS);
    trace!("Using DiskCache({:?})", disk_cache_path);
    trace!("DiskCache size: {}", disk_cache_size);
    Arc::new(DiskCache::new(&disk_cache_path, disk_cache_size, pool))
}
pub fn base_storage_from_environment(pool: &CpuPool, _handle: &Handle) -> Arc<Storage> {
    if cfg!(feature = "s3") {
        if let Ok(bucket) = env::var("SCCACHE_BUCKET") {
            let endpoint = match env::var("SCCACHE_ENDPOINT") {
                Ok(endpoint) => format!("{}/{}", endpoint, bucket),
                _ => match env::var("SCCACHE_REGION") {
                    Ok(ref region) if region != "us-east-1" =>
                        format!("{}.s3-{}.amazonaws.com", bucket, region),
                    _ => format!("{}.s3.amazonaws.com", bucket),
                },
            };
            debug!("Trying S3Cache({})", endpoint);
            #[cfg(feature = "s3")]
            match S3Cache::new(&bucket, &endpoint, _handle) {
                Ok(s) => {
                    trace!("Using S3Cache");
                    return Arc::new(s);
                }
                Err(e) => warn!("Failed to create S3Cache: {:?}", e),
            }
        }
    }

    if cfg!(feature = "redis") {
        if let Ok(url) = env::var("SCCACHE_REDIS") {
            debug!("Trying Redis({})", url);
            #[cfg(feature = "redis")]
            match RedisCache::new(&url, pool) {
                Ok(s) => {
                    trace!("Using Redis: {}", url);
                    return Arc::new(s);
                }
                Err(e) => warn!("Failed to create RedisCache: {:?}", e),
            }
        }
    }

    if cfg!(feature = "memcached") {
        if let Ok(url) = env::var("SCCACHE_MEMCACHED") {
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
    }

    if cfg!(feature = "gcs") {
        if let Ok(bucket) = env::var("SCCACHE_GCS_BUCKET")
        {
            debug!("Trying GCS bucket({})", bucket);
            #[cfg(feature = "gcs")]
            {
                let cred_path_res = env::var("SCCACHE_GCS_KEY_PATH");
                if cred_path_res.is_err() {
                    warn!("No SCCACHE_GCS_KEY_PATH specified-- no authentication will be used.");
                }

                let service_account_key_opt: Option<gcs::ServiceAccountKey> =
                    if let Ok(cred_path) = cred_path_res
                {
                    // Attempt to read the service account key from file
                    let service_account_key_res: Result<gcs::ServiceAccountKey> = (|| {
                        let mut file = File::open(&cred_path)?;
                        let mut service_account_json = String::new();
                        file.read_to_string(&mut service_account_json)?;
                        Ok(serde_json::from_str(&service_account_json)?)
                    })();

                    // warn! if an error was encountered reading the key from the file
                    if let Err(ref e) = service_account_key_res {
                        warn!("Failed to parse service account credentials from file: {:?}. \
                            Continuing without authentication.", e);
                    }

                    service_account_key_res.ok()
                } else { None };

                let gcs_read_write_mode = match env::var("SCCACHE_GCS_RW_MODE")
                                          .as_ref().map(String::as_str)
                {
                    Ok("READ_ONLY") => RWMode::ReadOnly,
                    Ok("READ_WRITE") => RWMode::ReadWrite,
                    Ok(_) => {
                        warn!("Invalid SCCACHE_GCS_RW_MODE-- defaulting to READ_ONLY.");
                        RWMode::ReadOnly
                    },
                    _ => {
                        warn!("No SCCACHE_GCS_RW_MODE specified-- defaulting to READ_ONLY.");
                        RWMode::ReadOnly
                    }
                };

                let gcs_cred_provider =
                    service_account_key_opt.map(|path|
                        GCSCredentialProvider::new(gcs_read_write_mode, path));

                match GCSCache::new(bucket, gcs_cred_provider, gcs_read_write_mode, _handle) {
                    Ok(s) => {
                        trace!("Using GCSCache");
                        return Arc::new(s);
                    }
                    Err(e) => warn!("Failed to create GCS Cache: {:?}", e),
                }
            }
        }
    }

    if cfg!(feature = "azure") {
        if let Ok(_) = env::var("SCCACHE_AZURE_CONNECTION_STRING") {
            debug!("Trying Azure Blob Store account");
            #[cfg(feature = "azure")]
            match AzureBlobCache::new(_handle) {
                Ok(storage) => {
                    trace!("Using AzureBlobCache");
                    return Arc::new(storage);
                }
                Err(e) => warn!("Failed to create Azure cache: {:?}", e),
            }
        }
    }

    get_disk_storage(pool)
}

#[test]
fn test_parse_size() {
    assert_eq!(None, parse_size(""));
    assert_eq!(None, parse_size("100"));
    assert_eq!(Some(2048), parse_size("2K"));
    assert_eq!(Some(10 * 1024 * 1024), parse_size("10M"));
    assert_eq!(Some(TEN_GIGS), parse_size("10G"));
    assert_eq!(Some(1024 * TEN_GIGS), parse_size("10T"));
}
