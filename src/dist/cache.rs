use config::CONFIG;
use futures::Future;
use futures_cpupool::CpuPool;
use lru_disk_cache::{LruDiskCache, ReadSeek};
use lru_disk_cache::Error as LruError;
use lru_disk_cache::Result as LruResult;
use serde_json;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use util;

use errors::*;

// TODO: possibly shouldn't be public
pub struct ClientToolchainCache {
    client_cache_dir: PathBuf,
    cache: Mutex<TcCache>,
    // Local machine mapping from 'weak' hashes to strong toolchain hashes
    weak_map: Mutex<HashMap<String, String>>,
}

impl ClientToolchainCache {
    pub fn new() -> Self {
        let client_cache_dir = CONFIG.dist.cache_dir.join("client");
        fs::create_dir_all(&client_cache_dir).unwrap();

        let weak_map_path = client_cache_dir.join("weak_map.json");
        if !weak_map_path.exists() {
            fs::File::create(&weak_map_path).unwrap().write_all(b"{}").unwrap()
        }
        let weak_map = serde_json::from_reader(fs::File::open(weak_map_path).unwrap()).unwrap();

        let cache = Mutex::new(TcCache::new(&client_cache_dir).unwrap());

        Self {
            client_cache_dir,
            cache,
            // TODO: shouldn't clear on restart, but also should have some
            // form of pruning
            weak_map: Mutex::new(weak_map),
        }
    }

    // Get the bytes of a toolchain tar
    pub fn get_toolchain_cache(&self, key: &str) -> Option<Vec<u8>> {
        let mut toolchain_reader = match self.cache.lock().unwrap().get(key) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => return None,
            Err(e) => panic!("{}", e),
        };
        let mut ret = vec![];
        toolchain_reader.read_to_end(&mut ret).unwrap();
        Some(ret)
    }
    // TODO: It's more correct to have a FnBox or Box<FnOnce> here
    // If the toolchain doesn't already exist, create it and insert into the cache
    pub fn put_toolchain_cache(&self, weak_key: &str, create: &mut FnMut(fs::File)) -> Result<String> {
        if let Some(strong_key) = self.weak_to_strong(weak_key) {
            debug!("Using cached toolchain {} -> {}", weak_key, strong_key);
            return Ok(strong_key)
        }
        debug!("Weak key {} appears to be new", weak_key);
        // TODO: don't use this as a poor exclusive lock on this global file
        let mut cache = self.cache.lock().unwrap();
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("/tmp/toolchain_cache.tar")?;
        create(file);
        // TODO: after, if still exists, remove it
        let strong_key = cache.insert_file("/tmp/toolchain_cache.tar")?;
        self.record_weak(weak_key.to_owned(), strong_key.clone());
        Ok(strong_key)
    }

    fn weak_to_strong(&self, weak_key: &str) -> Option<String> {
        self.weak_map.lock().unwrap().get(weak_key).map(String::to_owned)
    }
    fn record_weak(&self, weak_key: String, key: String) {
        let mut weak_map = self.weak_map.lock().unwrap();
        weak_map.insert(weak_key, key);
        let weak_map_path = self.client_cache_dir.join("weak_map.json");
        serde_json::to_writer(fs::File::create(weak_map_path).unwrap(), &*weak_map).unwrap()
    }
}

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

    pub fn insert_with<F: FnOnce(File) -> io::Result<()>>(&mut self, key: &str, with: F) -> Result<()> {
        self.inner.insert_with(key, with).map_err(|e| -> Error { e.into() })?;
        let verified_key = self.get(key).map_err(Into::into)
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
