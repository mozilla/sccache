use dist::Toolchain;
use lru_disk_cache::{LruDiskCache, ReadSeek};
use lru_disk_cache::Result as LruResult;
use ring::digest::{SHA512, Context};
use std::fs;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use util;

use errors::*;

#[cfg(feature = "dist-client")]
pub use self::client::ClientToolchains;

#[cfg(feature = "dist-client")]
mod client {
    use config;
    use dist::Toolchain;
    use dist::pkg::ToolchainPackager;
    use lru_disk_cache::Error as LruError;
    use serde_json;
    use std::collections::HashMap;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tempfile;

    use super::{TcCache, path_key};
    use errors::*;

    #[derive(Clone, Debug)]
    pub struct CustomToolchain {
        archive: PathBuf,
        compiler_executable: String,
    }

    // TODO: possibly shouldn't be public
    #[cfg(feature = "dist-client")]
    pub struct ClientToolchains {
        cache_dir: PathBuf,
        cache: Mutex<TcCache>,
        // Lookup from dist toolchain -> toolchain details
        custom_toolchains: Mutex<HashMap<Toolchain, CustomToolchain>>,
        // Lookup from local path -> toolchain details
        custom_toolchain_paths: Mutex<HashMap<PathBuf, (CustomToolchain, Option<Toolchain>)>>,
        // Local machine mapping from 'weak' hashes to strong toolchain hashes
        // - Weak hashes are what sccache uses to determine if a compiler has changed
        //   on the local machine - they're fast and 'good enough' (assuming we trust
        //   the local machine), but not safe if other users can update the cache.
        // - Strong hashes (or 'archive ids') are the hash of the complete compiler contents that
        //   will be sent over the wire for use in distributed compilation - it is assumed
        //   that if two of them match, the contents of a compiler archive cannot
        //   have been tampered with
        weak_map: Mutex<HashMap<String, String>>,
    }

    #[cfg(feature = "dist-client")]
    impl ClientToolchains {
        pub fn new(cache_dir: &Path, cache_size: u64, config_custom_toolchains: &[config::DistCustomToolchain]) -> Self {
            let cache_dir = cache_dir.to_owned();
            fs::create_dir_all(&cache_dir).unwrap();

            let toolchain_creation_dir = cache_dir.join("toolchain_tmp");
            if toolchain_creation_dir.exists() {
                fs::remove_dir_all(&toolchain_creation_dir).unwrap()
            }
            fs::create_dir(&toolchain_creation_dir).unwrap();

            let weak_map_path = cache_dir.join("weak_map.json");
            if !weak_map_path.exists() {
                fs::File::create(&weak_map_path).unwrap().write_all(b"{}").unwrap()
            }
            let weak_map = serde_json::from_reader(fs::File::open(weak_map_path).unwrap()).unwrap();

            let tc_cache_dir = cache_dir.join("tc");
            let cache = Mutex::new(TcCache::new(&tc_cache_dir, cache_size).unwrap());

            let mut custom_toolchain_paths = HashMap::new();
            for ct in config_custom_toolchains.into_iter() {
                if custom_toolchain_paths.contains_key(&ct.compiler_executable) {
                    panic!("Multiple toolchains for {:?}", ct.compiler_executable)
                }
                let config::DistCustomToolchain { compiler_executable, archive, archive_compiler_executable } = ct;

                debug!("Registering custom toolchain for {:?}", compiler_executable);
                let custom_tc = CustomToolchain {
                    archive: archive.clone(),
                    compiler_executable: archive_compiler_executable.clone(),
                };
                assert!(custom_toolchain_paths.insert(compiler_executable.clone(), (custom_tc, None)).is_none());
            }
            let custom_toolchain_paths = Mutex::new(custom_toolchain_paths);

            Self {
                cache_dir,
                cache,
                custom_toolchains: Mutex::new(HashMap::new()),
                custom_toolchain_paths,
                // TODO: shouldn't clear on restart, but also should have some
                // form of pruning
                weak_map: Mutex::new(weak_map),
            }
        }

        // Get the bytes of a toolchain tar
        // TODO: by this point the toolchain should be known to exist
        pub fn get_toolchain(&self, tc: &Toolchain) -> Option<fs::File> {
            // TODO: be more relaxed about path casing and slashes on Windows
            let file = if let Some(custom_tc) = self.custom_toolchains.lock().unwrap().get(tc) {
                fs::File::open(&custom_tc.archive).unwrap()
            } else {
                match self.cache.lock().unwrap().get_file(tc) {
                    Ok(file) => file,
                    Err(LruError::FileNotInCache) => return None,
                    Err(e) => panic!("{}", e),
                }
            };
            Some(file)
        }
        // TODO: It's more correct to have a FnBox or Box<FnOnce> here
        // If the toolchain doesn't already exist, create it and insert into the cache
        pub fn put_toolchain(&self, compiler_path: &Path, weak_key: &str, toolchain_packager: Box<ToolchainPackager>) -> Result<(Toolchain, Option<String>)> {
            if let Some(tc_and_compiler_path) = self.get_custom_toolchain(compiler_path) {
                debug!("Using custom toolchain for {:?}", compiler_path);
                let (tc, compiler_path) = tc_and_compiler_path.unwrap();
                return Ok((tc, Some(compiler_path)))
            }
            if let Some(archive_id) = self.weak_to_strong(weak_key) {
                debug!("Using cached toolchain {} -> {}", weak_key, archive_id);
                return Ok((Toolchain { archive_id }, None))
            }
            debug!("Weak key {} appears to be new", weak_key);
            // Only permit one toolchain creation at a time. Not an issue if there are multiple attempts
            // to create the same toolchain, just a waste of time
            let mut cache = self.cache.lock().unwrap();
            let tmpfile = tempfile::NamedTempFile::new_in(self.cache_dir.join("toolchain_tmp"))?;
            toolchain_packager.write_pkg(tmpfile.reopen()?).chain_err(|| "Could not package toolchain")?;
            let tc = cache.insert_file(tmpfile.path())?;
            self.record_weak(weak_key.to_owned(), tc.archive_id.clone());
            Ok((tc, None))
        }

        fn get_custom_toolchain(&self, compiler_path: &Path) -> Option<Result<(Toolchain, String)>> {
            return match self.custom_toolchain_paths.lock().unwrap().get_mut(compiler_path) {
                Some((custom_tc, Some(tc))) => Some(Ok((tc.clone(), custom_tc.compiler_executable.clone()))),
                Some((custom_tc, maybe_tc @ None)) => {
                    let archive_id = match path_key(&custom_tc.archive) {
                        Ok(archive_id) => archive_id,
                        Err(e) => return Some(Err(e)),
                    };
                    let tc = Toolchain { archive_id };
                    *maybe_tc = Some(tc.clone());
                    assert!(self.custom_toolchains.lock().unwrap().insert(tc.clone(), custom_tc.clone()).is_none());
                    Some(Ok((tc, custom_tc.compiler_executable.clone())))
                },
                None => None,
            }
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
}

pub struct TcCache {
    inner: LruDiskCache,
}

impl TcCache {
    pub fn new(cache_dir: &Path, cache_size: u64) -> Result<TcCache> {
        trace!("Using TcCache({:?}, {})", cache_dir, cache_size);
        Ok(TcCache { inner: LruDiskCache::new(cache_dir, cache_size)? })
    }

    pub fn contains_toolchain(&self, tc: &Toolchain) -> bool {
        self.inner.contains_key(make_lru_key_path(&tc.archive_id))
    }

    pub fn insert_with<F: FnOnce(fs::File) -> io::Result<()>>(&mut self, tc: &Toolchain, with: F) -> Result<()> {
        self.inner.insert_with(make_lru_key_path(&tc.archive_id), with).map_err(|e| -> Error { e.into() })?;
        let verified_archive_id = file_key(self.get(tc)?)?;
        // TODO: remove created toolchain?
        if verified_archive_id == tc.archive_id { Ok(()) } else { Err("written file does not match expected hash key".into()) }
    }

    pub fn get_file(&mut self, tc: &Toolchain) -> LruResult<fs::File> {
        self.inner.get_file(make_lru_key_path(&tc.archive_id))
    }

    pub fn get(&mut self, tc: &Toolchain) -> LruResult<Box<ReadSeek>> {
        self.inner.get(make_lru_key_path(&tc.archive_id))
    }

    #[cfg(feature = "dist-client")]
    fn insert_file(&mut self, path: &Path) -> Result<Toolchain> {
        let archive_id = path_key(&path)?;
        self.inner.insert_file(make_lru_key_path(&archive_id), path).map_err(|e| -> Error { e.into() })?;
        Ok(Toolchain { archive_id })
    }
}

#[cfg(feature = "dist-client")]
fn path_key(path: &Path) -> Result<String> {
    file_key(fs::File::open(path)?)
}
fn file_key<RS: ReadSeek + 'static>(rs: RS) -> Result<String> {
    hash_reader(rs)
}
/// Make a path to the cache entry with key `key`.
fn make_lru_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
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
    Ok(util::hex(m.finish().as_ref()))
}
