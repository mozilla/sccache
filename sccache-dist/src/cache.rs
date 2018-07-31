use lru_disk_cache::{LruDiskCache, ReadSeek};
use lru_disk_cache::Error as LruError;
use lru_disk_cache::Result as LruResult;
use ring::digest::{SHA512, Context};
use serde_json;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use errors::*;

// TODO: possibly shouldn't be public
pub struct ClientToolchainCache {
    cache_dir: PathBuf,
    cache: Mutex<TcCache>,
    // Local machine mapping from 'weak' hashes to strong toolchain hashes
    weak_map: Mutex<HashMap<String, String>>,
}

impl ClientToolchainCache {
    pub fn new(cache_dir: &Path, cache_size: u64) -> Self {
        let cache_dir = cache_dir.to_owned();
        fs::create_dir_all(&cache_dir).unwrap();

        let weak_map_path = cache_dir.join("weak_map.json");
        if !weak_map_path.exists() {
            fs::File::create(&weak_map_path).unwrap().write_all(b"{}").unwrap()
        }
        let weak_map = serde_json::from_reader(fs::File::open(weak_map_path).unwrap()).unwrap();

        let tc_cache_dir = cache_dir.join("tc");
        let cache = Mutex::new(TcCache::new(&tc_cache_dir, cache_size).unwrap());

        Self {
            cache_dir,
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
    pub fn put_toolchain_cache(&self, weak_key: &str, create: &mut FnMut(fs::File) -> io::Result<()>) -> Result<String> {
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
        create(file)?;
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
        let weak_map_path = self.cache_dir.join("weak_map.json");
        serde_json::to_writer(fs::File::create(weak_map_path).unwrap(), &*weak_map).unwrap()
    }
}

// Partially copied from util.rs
fn hash_reader<R: Read + Send + 'static>(rdr: R) -> Result<String> {
    let mut m = Context::new(&SHA512);
    let mut reader = BufReader::new(rdr);
    loop {
        let mut buffer = [0; 1024];
        let count = reader.read(&mut buffer[..])?;
        if count == 0 {
            break;
        }
        m.update(&buffer[..count]);
    }
    Ok(hex(m.finish().as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(hex(byte & 0xf));
        s.push(hex((byte >> 4)& 0xf));
    }
    return s;

    fn hex(byte: u8) -> char {
        match byte {
            0...9 => (b'0' + byte) as char,
            _ => (b'a' + byte - 10) as char,
        }
    }
}

pub struct TcCache {
    inner: LruDiskCache,
}

impl TcCache {
    pub fn new(cache_dir: &Path, cache_size: u64) -> Result<TcCache> {
        trace!("Using TcCache({:?}, {})", cache_dir, cache_size);
        Ok(TcCache { inner: LruDiskCache::new(cache_dir, cache_size)? })
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    fn file_key<RS: ReadSeek + 'static>(&self, rs: RS) -> Result<String> {
        // TODO: should explicitly pick the hash
        hash_reader(rs)
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
