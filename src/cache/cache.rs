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

use app_dirs::{
    AppDataType,
    AppInfo,
    app_dir,
};
use cache::disk::DiskCache;
#[cfg(feature = "redis")]
use cache::redis::RedisCache;
#[cfg(feature = "s3")]
use cache::s3::S3Cache;
use futures_cpupool::CpuPool;
use regex::Regex;
use std::env;
use std::fmt;
use std::io::{
    self,
    Read,
    Seek,
    Write,
};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_core::reactor::Handle;
use zip::{CompressionMethod, ZipArchive, ZipWriter};
use zip::write::FileOptions;

use errors::*;

//TODO: might need to put this somewhere more central
const APP_INFO: AppInfo = AppInfo {
    name: "sccache",
    author: "Mozilla",
};

const TEN_GIGS: usize = 10 * 1024 * 1024 * 1024;

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

    /// Get a cache entry for `key` that can be filled with data.
    fn start_put(&self, key: &str) -> Result<CacheWrite>;

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    fn finish_put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration>;

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the current storage usage, if applicable.
    fn current_size(&self) -> Option<usize>;

    /// Get the maximum storage size, if applicable.
    fn max_size(&self) -> Option<usize>;
}

fn parse_size(val: &str) -> Option<usize> {
    let re = Regex::new(r"^(\d+)([KMGT])$").unwrap();
    re.captures(val)
        .and_then(|caps| caps.at(1).and_then(|size| usize::from_str(size).ok()).and_then(|size| Some((size, caps.at(2)))))
        .and_then(|(size, suffix)| {
            match suffix {
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

    let d = env::var_os("SCCACHE_DIR")
        .map(|p| PathBuf::from(p))
        .or_else(|| app_dir(AppDataType::UserCache, &APP_INFO, "").ok())
        // Fall back to something, even if it's not very good.
        .unwrap_or(env::temp_dir().join("sccache_cache"));
    trace!("Using DiskCache({:?})", d);
    let cache_size = env::var("SCCACHE_CACHE_SIZE")
        .ok()
        .and_then(|v| parse_size(&v))
        .unwrap_or(TEN_GIGS);
    trace!("DiskCache size: {}", cache_size);
    Arc::new(DiskCache::new(&d, cache_size, pool))
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
