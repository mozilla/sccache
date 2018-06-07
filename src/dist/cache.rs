use config::CONFIG;
use futures::Future;
use futures_cpupool::CpuPool;
use lru_disk_cache::{LruDiskCache, ReadSeek};
use lru_disk_cache::Result as LruResult;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;
use util;

use errors::*;

pub struct TcCache {
    inner: LruDiskCache,
    pool: CpuPool,
}

impl TcCache {
    pub fn new(cache_dir: &Path) -> Result<TcCache> {
        let d = cache_dir.join("tc");
        let cache_size = CONFIG.dist.toolchain_cache_size;
        trace!("Using TcCache({:?}, {})", d, cache_size);
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
        // TODO: should also really explicitly pick the hash
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
