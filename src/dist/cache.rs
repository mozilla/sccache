use crate::dist::Toolchain;
use crate::lru_disk_cache::Result as LruResult;
use crate::lru_disk_cache::{LruDiskCache, ReadSeek};
use anyhow::{anyhow, Result};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "dist-client")]
pub use self::client::ClientToolchains;
use crate::util::Digest;
use std::io::Read;

#[cfg(feature = "dist-client")]
mod client {
    use crate::config;
    use crate::dist::pkg::ToolchainPackager;
    use crate::dist::Toolchain;
    use crate::lru_disk_cache::Error as LruError;
    use anyhow::{bail, Context, Error, Result};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::{path_key, TcCache};

    #[derive(Clone, Debug)]
    pub struct CustomToolchain {
        archive: PathBuf,
        compiler_executable: String,
    }

    // TODO: possibly shouldn't be public
    pub struct ClientToolchains {
        cache_dir: PathBuf,
        cache: Mutex<TcCache>,
        // Lookup from dist toolchain -> path to custom toolchain archive
        custom_toolchain_archives: Mutex<HashMap<Toolchain, PathBuf>>,
        // Lookup from local path -> toolchain details
        // The Option<Toolchain> could be populated on startup, but it's lazy for efficiency
        custom_toolchain_paths: Mutex<HashMap<PathBuf, (CustomToolchain, Option<Toolchain>)>>,
        // Toolchains configured to not be distributed
        disabled_toolchains: HashSet<PathBuf>,
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

    impl ClientToolchains {
        pub fn new(
            cache_dir: &Path,
            cache_size: u64,
            toolchain_configs: &[config::DistToolchainConfig],
        ) -> Result<Self> {
            let cache_dir = cache_dir.to_owned();
            fs::create_dir_all(&cache_dir)
                .context("failed to create top level toolchain cache dir")?;

            let toolchain_creation_dir = cache_dir.join("toolchain_tmp");
            if toolchain_creation_dir.exists() {
                fs::remove_dir_all(&toolchain_creation_dir)
                    .context("failed to clean up temporary toolchain creation directory")?
            }
            fs::create_dir(&toolchain_creation_dir)
                .context("failed to create temporary toolchain creation directory")?;

            let weak_map_path = cache_dir.join("weak_map.json");
            if !weak_map_path.exists() {
                fs::File::create(&weak_map_path)
                    .and_then(|mut f| f.write_all(b"{}"))
                    .context("failed to create new toolchain weak map file")?
            }
            let weak_map = fs::File::open(weak_map_path)
                .map_err(Error::from)
                .and_then(|f| serde_json::from_reader(f).map_err(Error::from))
                .context("failed to load toolchain weak map")?;

            let tc_cache_dir = cache_dir.join("tc");
            let cache = TcCache::new(&tc_cache_dir, cache_size)
                .map(Mutex::new)
                .context("failed to initialise a toolchain cache")?;

            // Load in toolchain configuration
            let mut custom_toolchain_paths = HashMap::new();
            let mut disabled_toolchains = HashSet::new();
            for ct in toolchain_configs.iter() {
                match ct {
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable,
                        archive,
                        archive_compiler_executable,
                    } => {
                        debug!(
                            "Registering custom toolchain for {}",
                            compiler_executable.display()
                        );
                        let custom_tc = CustomToolchain {
                            archive: archive.clone(),
                            compiler_executable: archive_compiler_executable.clone(),
                        };
                        if custom_toolchain_paths
                            .insert(compiler_executable.clone(), (custom_tc, None))
                            .is_some()
                        {
                            bail!("Multiple toolchains for {}", compiler_executable.display())
                        }
                        if disabled_toolchains.contains(compiler_executable) {
                            bail!(
                                "Override for toolchain {} conflicts with it being disabled",
                                compiler_executable.display()
                            )
                        }
                    }
                    config::DistToolchainConfig::NoDist {
                        compiler_executable,
                    } => {
                        debug!("Disabling toolchain {}", compiler_executable.display());
                        if !disabled_toolchains.insert(compiler_executable.clone()) {
                            bail!(
                                "Disabled toolchain {} multiple times",
                                compiler_executable.display()
                            )
                        }
                        if custom_toolchain_paths.contains_key(compiler_executable) {
                            bail!(
                                "Override for toolchain {} conflicts with it being disabled",
                                compiler_executable.display()
                            )
                        }
                    }
                }
            }
            let custom_toolchain_paths = Mutex::new(custom_toolchain_paths);

            Ok(Self {
                cache_dir,
                cache,
                custom_toolchain_archives: Mutex::new(HashMap::new()),
                custom_toolchain_paths,
                disabled_toolchains,
                // TODO: shouldn't clear on restart, but also should have some
                // form of pruning
                weak_map: Mutex::new(weak_map),
            })
        }

        // Get the bytes of a toolchain tar
        // TODO: by this point the toolchain should be known to exist
        pub fn get_toolchain(&self, tc: &Toolchain) -> Result<Option<fs::File>> {
            // TODO: be more relaxed about path casing and slashes on Windows
            let file = if let Some(custom_tc_archive) =
                self.custom_toolchain_archives.lock().unwrap().get(tc)
            {
                fs::File::open(custom_tc_archive).with_context(|| {
                    format!(
                        "could not open file for toolchain {}",
                        custom_tc_archive.display()
                    )
                })?
            } else {
                match self.cache.lock().unwrap().get_file(tc) {
                    Ok(file) => file,
                    Err(LruError::FileNotInCache) => return Ok(None),
                    Err(e) => return Err(e).context("error while retrieving toolchain from cache"),
                }
            };
            Ok(Some(file))
        }
        // If the toolchain doesn't already exist, create it and insert into the cache
        pub fn put_toolchain(
            &self,
            compiler_path: &Path,
            weak_key: &str,
            toolchain_packager: Box<dyn ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            if self.disabled_toolchains.contains(compiler_path) {
                bail!(
                    "Toolchain distribution for {} is disabled",
                    compiler_path.display()
                )
            }
            if let Some(tc_and_paths) = self.get_custom_toolchain(compiler_path) {
                debug!("Using custom toolchain for {:?}", compiler_path);
                let (tc, compiler_path, archive) = tc_and_paths?;
                return Ok((tc, Some((compiler_path, archive))));
            }
            // Only permit one toolchain creation at a time. Not an issue if there are multiple attempts
            // to create the same toolchain, just a waste of time
            let mut cache = self.cache.lock().unwrap();
            if let Some(archive_id) = self.weak_to_strong(weak_key) {
                debug!("Using cached toolchain {} -> {}", weak_key, archive_id);
                return Ok((Toolchain { archive_id }, None));
            }
            debug!("Weak key {} appears to be new", weak_key);
            let tmpfile = tempfile::NamedTempFile::new_in(self.cache_dir.join("toolchain_tmp"))?;
            toolchain_packager
                .write_pkg(tmpfile.reopen()?)
                .context("Could not package toolchain")?;
            let tc = cache.insert_file(tmpfile.path())?;
            self.record_weak(weak_key.to_owned(), tc.archive_id.clone())?;
            Ok((tc, None))
        }

        pub fn get_custom_toolchain(
            &self,
            compiler_path: &Path,
        ) -> Option<Result<(Toolchain, String, PathBuf)>> {
            match self
                .custom_toolchain_paths
                .lock()
                .unwrap()
                .get_mut(compiler_path)
            {
                Some((custom_tc, Some(tc))) => Some(Ok((
                    tc.clone(),
                    custom_tc.compiler_executable.clone(),
                    custom_tc.archive.clone(),
                ))),
                Some((custom_tc, maybe_tc @ None)) => {
                    let archive_id = match path_key(&custom_tc.archive) {
                        Ok(archive_id) => archive_id,
                        Err(e) => return Some(Err(e)),
                    };
                    let tc = Toolchain { archive_id };
                    *maybe_tc = Some(tc.clone());
                    // If this entry already exists, someone has two custom toolchains with the same strong hash
                    if let Some(old_path) = self
                        .custom_toolchain_archives
                        .lock()
                        .unwrap()
                        .insert(tc.clone(), custom_tc.archive.clone())
                    {
                        // Log a warning if the user has identical toolchains at two different locations - it's
                        // not strictly wrong, but it is a bit odd
                        if old_path != custom_tc.archive {
                            warn!(
                                "Detected interchangeable toolchain archives at {} and {}",
                                old_path.display(),
                                custom_tc.archive.display()
                            )
                        }
                    }
                    Some(Ok((
                        tc,
                        custom_tc.compiler_executable.clone(),
                        custom_tc.archive.clone(),
                    )))
                }
                None => None,
            }
        }

        fn weak_to_strong(&self, weak_key: &str) -> Option<String> {
            self.weak_map
                .lock()
                .unwrap()
                .get(weak_key)
                .map(String::to_owned)
        }
        fn record_weak(&self, weak_key: String, key: String) -> Result<()> {
            let mut weak_map = self.weak_map.lock().unwrap();
            weak_map.insert(weak_key, key);
            let weak_map_path = self.cache_dir.join("weak_map.json");
            fs::File::create(weak_map_path)
                .map_err(Error::from)
                .and_then(|f| serde_json::to_writer(f, &*weak_map).map_err(Error::from))
                .context("failed to enter toolchain in weak map")
        }
    }

    #[cfg(test)]
    mod test {
        use crate::config;
        use crate::test::utils::create_file;
        use std::io::Write;

        use super::ClientToolchains;

        struct PanicToolchainPackager;
        impl PanicToolchainPackager {
            fn new() -> Box<Self> {
                Box::new(PanicToolchainPackager)
            }
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        impl crate::dist::pkg::ToolchainPackager for PanicToolchainPackager {
            fn write_pkg(self: Box<Self>, _f: ::std::fs::File) -> crate::errors::Result<()> {
                panic!("should not have called packager")
            }
        }

        #[test]
        fn test_client_toolchains_custom() {
            let td = tempfile::Builder::new()
                .prefix("sccache")
                .tempdir()
                .unwrap();

            let ct1 =
                create_file(td.path(), "ct1", |mut f| f.write_all(b"toolchain_contents")).unwrap();

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[config::DistToolchainConfig::PathOverride {
                    compiler_executable: "/my/compiler".into(),
                    archive: ct1.clone(),
                    archive_compiler_executable: "/my/compiler/in_archive".into(),
                }],
            )
            .unwrap();

            let (_tc, newpath) = client_toolchains
                .put_toolchain(
                    "/my/compiler".as_ref(),
                    "weak_key",
                    PanicToolchainPackager::new(),
                )
                .unwrap();
            assert!(newpath.unwrap() == ("/my/compiler/in_archive".to_string(), ct1));
        }

        #[test]
        fn test_client_toolchains_custom_multiuse_archive() {
            let td = tempfile::Builder::new()
                .prefix("sccache")
                .tempdir()
                .unwrap();

            let ct1 =
                create_file(td.path(), "ct1", |mut f| f.write_all(b"toolchain_contents")).unwrap();

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler".into(),
                        archive: ct1.clone(),
                        archive_compiler_executable: "/my/compiler/in_archive".into(),
                    },
                    // Uses the same archive, but a maps a different external compiler to a different archive compiler
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler2".into(),
                        archive: ct1.clone(),
                        archive_compiler_executable: "/my/compiler2/in_archive".into(),
                    },
                    // Uses the same archive, but a maps a different external compiler to the same archive compiler as the first
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler3".into(),
                        archive: ct1.clone(),
                        archive_compiler_executable: "/my/compiler/in_archive".into(),
                    },
                ],
            )
            .unwrap();

            let (_tc, newpath) = client_toolchains
                .put_toolchain(
                    "/my/compiler".as_ref(),
                    "weak_key",
                    PanicToolchainPackager::new(),
                )
                .unwrap();
            assert!(newpath.unwrap() == ("/my/compiler/in_archive".to_string(), ct1.clone()));
            let (_tc, newpath) = client_toolchains
                .put_toolchain(
                    "/my/compiler2".as_ref(),
                    "weak_key2",
                    PanicToolchainPackager::new(),
                )
                .unwrap();
            assert!(newpath.unwrap() == ("/my/compiler2/in_archive".to_string(), ct1.clone()));
            let (_tc, newpath) = client_toolchains
                .put_toolchain(
                    "/my/compiler3".as_ref(),
                    "weak_key2",
                    PanicToolchainPackager::new(),
                )
                .unwrap();
            assert!(newpath.unwrap() == ("/my/compiler/in_archive".to_string(), ct1));
        }

        #[test]
        fn test_client_toolchains_nodist() {
            let td = tempfile::Builder::new()
                .prefix("sccache")
                .tempdir()
                .unwrap();

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[config::DistToolchainConfig::NoDist {
                    compiler_executable: "/my/compiler".into(),
                }],
            )
            .unwrap();

            assert!(client_toolchains
                .put_toolchain(
                    "/my/compiler".as_ref(),
                    "weak_key",
                    PanicToolchainPackager::new()
                )
                .is_err());
        }

        #[test]
        fn test_client_toolchains_custom_nodist_conflict() {
            let td = tempfile::Builder::new()
                .prefix("sccache")
                .tempdir()
                .unwrap();

            let ct1 =
                create_file(td.path(), "ct1", |mut f| f.write_all(b"toolchain_contents")).unwrap();

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler".into(),
                        archive: ct1,
                        archive_compiler_executable: "/my/compiler".into(),
                    },
                    config::DistToolchainConfig::NoDist {
                        compiler_executable: "/my/compiler".into(),
                    },
                ],
            );
            assert!(client_toolchains.is_err())
        }
    }
}

pub struct TcCache {
    inner: LruDiskCache,
}

impl TcCache {
    pub fn new(cache_dir: &Path, cache_size: u64) -> Result<TcCache> {
        trace!("Using TcCache({:?}, {})", cache_dir, cache_size);
        Ok(TcCache {
            inner: LruDiskCache::new(cache_dir, cache_size)?,
        })
    }

    pub fn contains_toolchain(&self, tc: &Toolchain) -> bool {
        self.inner.contains_key(make_lru_key_path(&tc.archive_id))
    }

    pub fn insert_with<F: FnOnce(fs::File) -> io::Result<()>>(
        &mut self,
        tc: &Toolchain,
        with: F,
    ) -> Result<()> {
        self.inner
            .insert_with(make_lru_key_path(&tc.archive_id), with)?;
        let verified_archive_id = file_key(self.get(tc)?)?;
        // TODO: remove created toolchain?
        if verified_archive_id == tc.archive_id {
            Ok(())
        } else {
            Err(anyhow!("written file does not match expected hash key"))
        }
    }

    pub fn get_file(&mut self, tc: &Toolchain) -> LruResult<fs::File> {
        self.inner.get_file(make_lru_key_path(&tc.archive_id))
    }

    pub fn get(&mut self, tc: &Toolchain) -> LruResult<Box<dyn ReadSeek>> {
        self.inner.get(make_lru_key_path(&tc.archive_id))
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn remove(&mut self, tc: &Toolchain) -> LruResult<()> {
        self.inner.remove(make_lru_key_path(&tc.archive_id))
    }

    #[cfg(feature = "dist-client")]
    fn insert_file(&mut self, path: &Path) -> Result<Toolchain> {
        let archive_id = path_key(path)?;
        self.inner
            .insert_file(make_lru_key_path(&archive_id), path)?;
        Ok(Toolchain { archive_id })
    }
}

#[cfg(feature = "dist-client")]
fn path_key(path: &Path) -> Result<String> {
    file_key(fs::File::open(path)?)
}

fn file_key<R: Read>(rdr: R) -> Result<String> {
    Digest::reader_sync(rdr)
}
/// Make a path to the cache entry with key `key`.
fn make_lru_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}
