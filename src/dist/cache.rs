use config::parse_size;
use directories::ProjectDirs;
use futures::Future;
use futures_cpupool::CpuPool;
use lru_disk_cache::{LruDiskCache, ReadSeek};
use lru_disk_cache::Result as LruResult;
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use util;

use errors::*;

use config::{
    ORGANIZATION,
    TEN_GIGS,
};
const APP_NAME: &str = "sccache-dist";

pub enum CacheOwner {
    Client,
    Server,
}

impl CacheOwner {
    fn to_dirname(&self) -> &str {
        match *self {
            CacheOwner::Client => "client",
            CacheOwner::Server => "server",
        }
    }
}

pub struct TcCache {
    inner: LruDiskCache,
    pool: CpuPool,
}

impl TcCache {
    pub fn new(owner: CacheOwner) -> Result<TcCache> {
        let d = env::var_os("SCCACHE_TC_DIR")
            .map(|p| PathBuf::from(p))
            .unwrap_or_else(|| {
                let dirs = ProjectDirs::from("", ORGANIZATION, APP_NAME);
                dirs.cache_dir().join(owner.to_dirname()).join("tc")
            });
        trace!("Using TcCache({:?})", d);
        let cache_size: u64 = env::var("SCCACHE_TC_CACHE_SIZE")
            .ok()
            .and_then(|v| parse_size(&v))
            .unwrap_or(TEN_GIGS);
        trace!("TcCache size: {}", cache_size);
        // TODO: pass this in from the global pool
        let pool = CpuPool::new(1);
        Ok(TcCache { inner: LruDiskCache::new(d, cache_size)?, pool })
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    fn file_key<RS: ReadSeek + 'static>(&self, rs: RS) -> Result<String> {
        // TODO: should be dispatched on the event loop rather than relying on it being
        // dispatched on a cpu pool (`.wait()` could end up blocking)
        util::Digest::reader(rs, &self.pool).wait()
    }

    pub fn insert_with<F: Fn(File) -> io::Result<()>>(&mut self, key: &str, with: F) -> Result<()> {
        self.inner.insert_with(key, with).map_err(|e| -> Error { e.into() })?;
        let verified_key = self.get(key).map_err(|e| e.into())
            .and_then(|rs| self.file_key(rs))?;
        // TODO: remove created toolchain?
        if verified_key == key { Ok(()) } else { Err("written file does not match expected hash key".into()) }
    }

    pub fn insert_file<P: AsRef<OsStr>>(&mut self, path: P) -> Result<String> {
        let file = File::open(path.as_ref())?;
        let key = self.file_key(file)?;
        self.inner.insert_file(&key, path).map_err(|e| -> Error { e.into() })?;
        Ok(key)
    }

    pub fn get(&mut self, key: &str) -> LruResult<Box<ReadSeek>> {
        self.inner.get(key)
    }
}
