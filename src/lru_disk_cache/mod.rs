pub mod lru_cache;

use fs::File;
use fs_err as fs;
use std::borrow::Borrow;
use std::boxed::Box;
use std::collections::hash_map::RandomState;
use std::error::Error as StdError;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::hash::BuildHasher;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use filetime::{set_file_times, FileTime};
pub use lru_cache::{LruCache, Meter};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::util::OsStrExt;

const TEMPFILE_PREFIX: &str = ".sccachetmp";

struct FileSize;

/// Given a tuple of (path, filesize), use the filesize for measurement.
impl<K> Meter<K, u64> for FileSize {
    type Measure = usize;
    fn measure<Q: ?Sized>(&self, _: &Q, v: &u64) -> usize
    where
        K: Borrow<Q>,
    {
        *v as usize
    }
}

/// Return an iterator of `(path, size)` of files under `path` sorted by ascending last-modified
/// time, such that the oldest modified file is returned first.
fn get_all_files<P: AsRef<Path>>(path: P) -> Box<dyn Iterator<Item = (PathBuf, u64)>> {
    let mut files: Vec<_> = WalkDir::new(path.as_ref())
        .into_iter()
        .filter_map(|e| {
            e.ok().and_then(|f| {
                // Only look at files
                if f.file_type().is_file() {
                    // Get the last-modified time, size, and the full path.
                    f.metadata().ok().and_then(|m| {
                        m.modified()
                            .ok()
                            .map(|mtime| (mtime, f.path().to_owned(), m.len()))
                    })
                } else {
                    None
                }
            })
        })
        .collect();
    // Sort by last-modified-time, so oldest file first.
    files.sort_by_key(|k| k.0);
    Box::new(files.into_iter().map(|(_mtime, path, size)| (path, size)))
}

/// An LRU cache of files on disk.
pub struct LruDiskCache<S: BuildHasher = RandomState> {
    lru: LruCache<OsString, u64, S, FileSize>,
    root: PathBuf,
    pending: Vec<OsString>,
    pending_size: u64,
}

/// Errors returned by this crate.
#[derive(Debug)]
pub enum Error {
    /// The file was too large to fit in the cache.
    FileTooLarge,
    /// The file was not in the cache.
    FileNotInCache,
    /// An IO Error occurred.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FileTooLarge => write!(f, "File too large"),
            Error::FileNotInCache => write!(f, "File not in cache"),
            Error::Io(ref e) => write!(f, "{}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FileTooLarge => None,
            Error::FileNotInCache => None,
            Error::Io(ref e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// A convenience `Result` type
pub type Result<T> = std::result::Result<T, Error>;

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

enum AddFile<'a> {
    AbsPath(PathBuf),
    RelPath(&'a OsStr),
}

pub struct LruDiskCacheAddEntry {
    file: NamedTempFile,
    key: OsString,
    size: u64,
}

impl LruDiskCacheAddEntry {
    pub fn as_file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_file_mut()
    }
}

impl LruDiskCache {
    /// Create an `LruDiskCache` that stores files in `path`, limited to `size` bytes.
    ///
    /// Existing files in `path` will be stored with their last-modified time from the filesystem
    /// used as the order for the recency of their use. Any files that are individually larger
    /// than `size` bytes will be removed.
    ///
    /// The cache is not observant of changes to files under `path` from external sources, it
    /// expects to have sole maintence of the contents.
    pub fn new<T>(path: T, size: u64) -> Result<Self>
    where
        PathBuf: From<T>,
    {
        LruDiskCache {
            lru: LruCache::with_meter(size, FileSize),
            root: PathBuf::from(path),
            pending: vec![],
            pending_size: 0,
        }
        .init()
    }

    /// Return the current size of all the files in the cache.
    pub fn size(&self) -> u64 {
        self.lru.size() + self.pending_size
    }

    /// Return the count of entries in the cache.
    pub fn len(&self) -> usize {
        self.lru.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lru.len() == 0
    }

    /// Return the maximum size of the cache.
    pub fn capacity(&self) -> u64 {
        self.lru.capacity()
    }

    /// Return the path in which the cache is stored.
    pub fn path(&self) -> &Path {
        self.root.as_path()
    }

    /// Return the path that `key` would be stored at.
    fn rel_to_abs_path<K: AsRef<Path>>(&self, rel_path: K) -> PathBuf {
        self.root.join(rel_path)
    }

    /// Scan `self.root` for existing files and store them.
    fn init(mut self) -> Result<Self> {
        fs::create_dir_all(&self.root)?;
        for (file, size) in get_all_files(&self.root) {
            if file
                .file_name()
                .expect("Bad path?")
                .starts_with(TEMPFILE_PREFIX)
            {
                fs::remove_file(&file).unwrap_or_else(|e| {
                    error!("Error removing temporary file `{}`: {}", file.display(), e)
                });
            } else if !self.can_store(size) {
                fs::remove_file(file).unwrap_or_else(|e| {
                    error!(
                        "Error removing file `{}` which is too large for the cache ({} bytes)",
                        e, size
                    )
                });
            } else {
                self.add_file(AddFile::AbsPath(file), size)
                    .unwrap_or_else(|e| error!("Error adding file: {}", e));
            }
        }
        Ok(self)
    }

    /// Returns `true` if the disk cache can store a file of `size` bytes.
    pub fn can_store(&self, size: u64) -> bool {
        size <= self.lru.capacity()
    }

    fn make_space(&mut self, size: u64) -> Result<()> {
        if !self.can_store(size) {
            return Err(Error::FileTooLarge);
        }
        //TODO: ideally LRUCache::insert would give us back the entries it had to remove.
        while self.size() + size > self.capacity() {
            let (rel_path, _) = self.lru.remove_lru().expect("Unexpectedly empty cache!");
            let remove_path = self.rel_to_abs_path(rel_path);
            //TODO: check that files are removable during `init`, so that this is only
            // due to outside interference.
            fs::remove_file(&remove_path).unwrap_or_else(|e| {
                panic!("Error removing file from cache: `{:?}`: {}", remove_path, e)
            });
        }
        Ok(())
    }

    /// Add the file at `path` of size `size` to the cache.
    fn add_file(&mut self, addfile_path: AddFile<'_>, size: u64) -> Result<()> {
        let rel_path = match addfile_path {
            AddFile::AbsPath(ref p) => p.strip_prefix(&self.root).expect("Bad path?").as_os_str(),
            AddFile::RelPath(p) => p,
        };
        self.make_space(size)?;
        self.lru.insert(rel_path.to_owned(), size);
        Ok(())
    }

    fn insert_by<K: AsRef<OsStr>, F: FnOnce(&Path) -> io::Result<()>>(
        &mut self,
        key: K,
        size: Option<u64>,
        by: F,
    ) -> Result<()> {
        if let Some(size) = size {
            if !self.can_store(size) {
                return Err(Error::FileTooLarge);
            }
        }
        let rel_path = key.as_ref();
        let path = self.rel_to_abs_path(rel_path);
        fs::create_dir_all(path.parent().expect("Bad path?"))?;
        by(&path)?;
        let size = match size {
            Some(size) => size,
            None => fs::metadata(path)?.len(),
        };
        self.add_file(AddFile::RelPath(rel_path), size)
            .map_err(|e| {
                error!(
                    "Failed to insert file `{}`: {}",
                    rel_path.to_string_lossy(),
                    e
                );
                fs::remove_file(self.rel_to_abs_path(rel_path))
                    .expect("Failed to remove file we just created!");
                e
            })
    }

    /// Add a file by calling `with` with the open `File` corresponding to the cache at path `key`.
    pub fn insert_with<K: AsRef<OsStr>, F: FnOnce(File) -> io::Result<()>>(
        &mut self,
        key: K,
        with: F,
    ) -> Result<()> {
        self.insert_by(key, None, |path| with(File::create(path)?))
    }

    /// Add a file with `bytes` as its contents to the cache at path `key`.
    pub fn insert_bytes<K: AsRef<OsStr>>(&mut self, key: K, bytes: &[u8]) -> Result<()> {
        self.insert_by(key, Some(bytes.len() as u64), |path| {
            let mut f = File::create(path)?;
            f.write_all(bytes)?;
            Ok(())
        })
    }

    /// Add an existing file at `path` to the cache at path `key`.
    pub fn insert_file<K: AsRef<OsStr>, P: AsRef<OsStr>>(&mut self, key: K, path: P) -> Result<()> {
        let size = fs::metadata(path.as_ref())?.len();
        self.insert_by(key, Some(size), |new_path| {
            fs::rename(path.as_ref(), new_path).or_else(|_| {
                warn!("fs::rename failed, falling back to copy!");
                fs::copy(path.as_ref(), new_path)?;
                fs::remove_file(path.as_ref()).unwrap_or_else(|e| {
                    error!("Failed to remove original file in insert_file: {}", e)
                });
                Ok(())
            })
        })
    }

    /// Prepare the insertion of a file at path `key`. The resulting entry must be
    /// committed with `LruDiskCache::commit`.
    pub fn prepare_add<'a, K: AsRef<OsStr> + 'a>(
        &mut self,
        key: K,
        size: u64,
    ) -> Result<LruDiskCacheAddEntry> {
        // Ensure we have enough space for the advertized space.
        self.make_space(size)?;
        let key = key.as_ref().to_owned();
        self.pending.push(key.clone());
        self.pending_size += size;
        tempfile::Builder::new()
            .prefix(TEMPFILE_PREFIX)
            .tempfile_in(&self.root)
            .map(|file| LruDiskCacheAddEntry { file, key, size })
            .map_err(Into::into)
    }

    /// Commit an entry coming from `LruDiskCache::prepare_add`.
    pub fn commit(&mut self, entry: LruDiskCacheAddEntry) -> Result<()> {
        let LruDiskCacheAddEntry {
            mut file,
            key,
            size,
        } = entry;
        file.flush()?;
        let real_size = file.as_file().metadata()?.len();
        // If the file is larger than the size that had been advertized, ensure
        // we have enough space for it.
        self.make_space(real_size.saturating_sub(size))?;
        self.pending
            .iter()
            .position(|k| k == &key)
            .map(|i| self.pending.remove(i))
            .unwrap();
        self.pending_size -= size;
        let path = self.rel_to_abs_path(&key);
        fs::create_dir_all(path.parent().unwrap())?;
        file.persist(path).map_err(|e| e.error)?;
        self.lru.insert(key, real_size);
        Ok(())
    }

    /// Return `true` if a file with path `key` is in the cache. Entries created
    /// by `LruDiskCache::prepare_add` but not yet committed return `false`.
    pub fn contains_key<K: AsRef<OsStr>>(&self, key: K) -> bool {
        self.lru.contains_key(key.as_ref())
    }

    /// Get an opened `File` for `key`, if one exists and can be opened. Updates the LRU state
    /// of the file if present. Avoid using this method if at all possible, prefer `.get`.
    /// Entries created by `LruDiskCache::prepare_add` but not yet committed return
    /// `Err(Error::FileNotInCache)`.
    pub fn get_file<K: AsRef<OsStr>>(&mut self, key: K) -> Result<File> {
        let rel_path = key.as_ref();
        let path = self.rel_to_abs_path(rel_path);
        self.lru
            .get(rel_path)
            .ok_or(Error::FileNotInCache)
            .and_then(|_| {
                let t = FileTime::now();
                set_file_times(&path, t, t)?;
                File::open(path).map_err(Into::into)
            })
    }

    /// Get an opened readable and seekable handle to the file at `key`, if one exists and can
    /// be opened. Updates the LRU state of the file if present.
    /// Entries created by `LruDiskCache::prepare_add` but not yet committed return
    /// `Err(Error::FileNotInCache)`.
    pub fn get<K: AsRef<OsStr>>(&mut self, key: K) -> Result<Box<dyn ReadSeek>> {
        self.get_file(key).map(|f| Box::new(f) as Box<dyn ReadSeek>)
    }

    /// Remove the given key from the cache.
    pub fn remove<K: AsRef<OsStr>>(&mut self, key: K) -> Result<()> {
        match self.lru.remove(key.as_ref()) {
            Some(_) => {
                let path = self.rel_to_abs_path(key.as_ref());
                fs::remove_file(&path).map_err(|e| {
                    error!("Error removing file from cache: `{:?}`: {}", path, e);
                    Into::into(e)
                })
            }
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fs::{self, File};
    use super::{get_all_files, Error, LruDiskCache, LruDiskCacheAddEntry};

    use filetime::{set_file_times, FileTime};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct TestFixture {
        /// Temp directory.
        pub tempdir: TempDir,
    }

    fn create_file<T: AsRef<Path>, F: FnOnce(File) -> io::Result<()>>(
        dir: &Path,
        path: T,
        fill_contents: F,
    ) -> io::Result<PathBuf> {
        let b = dir.join(path);
        fs::create_dir_all(b.parent().unwrap())?;
        let f = fs::File::create(&b)?;
        fill_contents(f)?;
        b.canonicalize()
    }

    /// Set the last modified time of `path` backwards by `seconds` seconds.
    fn set_mtime_back<T: AsRef<Path>>(path: T, seconds: usize) {
        let m = fs::metadata(path.as_ref()).unwrap();
        let t = FileTime::from_last_modification_time(&m);
        let t = FileTime::from_unix_time(t.unix_seconds() - seconds as i64, t.nanoseconds());
        set_file_times(path, t, t).unwrap();
    }

    fn read_all<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
        let mut v = vec![];
        r.read_to_end(&mut v)?;
        Ok(v)
    }

    impl TestFixture {
        pub fn new() -> TestFixture {
            TestFixture {
                tempdir: tempfile::Builder::new()
                    .prefix("lru-disk-cache-test")
                    .tempdir()
                    .unwrap(),
            }
        }

        pub fn tmp(&self) -> &Path {
            self.tempdir.path()
        }

        pub fn create_file<T: AsRef<Path>>(&self, path: T, size: usize) -> PathBuf {
            create_file(self.tempdir.path(), path, |mut f| {
                f.write_all(&vec![0; size])
            })
            .unwrap()
        }
    }

    #[test]
    fn test_empty_dir() {
        let f = TestFixture::new();
        LruDiskCache::new(f.tmp(), 1024).unwrap();
    }

    #[test]
    fn test_missing_root() {
        let f = TestFixture::new();
        LruDiskCache::new(f.tmp().join("not-here"), 1024).unwrap();
    }

    #[test]
    fn test_some_existing_files() {
        let f = TestFixture::new();
        f.create_file("file1", 10);
        f.create_file("file2", 10);
        let c = LruDiskCache::new(f.tmp(), 20).unwrap();
        assert_eq!(c.size(), 20);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn test_existing_file_too_large() {
        let f = TestFixture::new();
        // Create files explicitly in the past.
        set_mtime_back(f.create_file("file1", 10), 10);
        set_mtime_back(f.create_file("file2", 10), 5);
        let c = LruDiskCache::new(f.tmp(), 15).unwrap();
        assert_eq!(c.size(), 10);
        assert_eq!(c.len(), 1);
        assert!(!c.contains_key("file1"));
        assert!(c.contains_key("file2"));
    }

    #[test]
    fn test_existing_files_lru_mtime() {
        let f = TestFixture::new();
        // Create files explicitly in the past.
        set_mtime_back(f.create_file("file1", 10), 5);
        set_mtime_back(f.create_file("file2", 10), 10);
        let mut c = LruDiskCache::new(f.tmp(), 25).unwrap();
        assert_eq!(c.size(), 20);
        c.insert_bytes("file3", &[0; 10]).unwrap();
        assert_eq!(c.size(), 20);
        // The oldest file on disk should have been removed.
        assert!(!c.contains_key("file2"));
        assert!(c.contains_key("file1"));
    }

    #[test]
    fn test_insert_bytes() {
        let f = TestFixture::new();
        let mut c = LruDiskCache::new(f.tmp(), 25).unwrap();
        c.insert_bytes("a/b/c", &[0; 10]).unwrap();
        assert!(c.contains_key("a/b/c"));
        c.insert_bytes("a/b/d", &[0; 10]).unwrap();
        assert_eq!(c.size(), 20);
        // Adding this third file should put the cache above the limit.
        c.insert_bytes("x/y/z", &[0; 10]).unwrap();
        assert_eq!(c.size(), 20);
        // The least-recently-used file should have been removed.
        assert!(!c.contains_key("a/b/c"));
        assert!(!f.tmp().join("a/b/c").exists());
    }

    #[test]
    fn test_insert_bytes_exact() {
        // Test that files adding up to exactly the size limit works.
        let f = TestFixture::new();
        let mut c = LruDiskCache::new(f.tmp(), 20).unwrap();
        c.insert_bytes("file1", &[1; 10]).unwrap();
        c.insert_bytes("file2", &[2; 10]).unwrap();
        assert_eq!(c.size(), 20);
        c.insert_bytes("file3", &[3; 10]).unwrap();
        assert_eq!(c.size(), 20);
        assert!(!c.contains_key("file1"));
    }

    #[test]
    fn test_add_get_lru() {
        let f = TestFixture::new();
        {
            let mut c = LruDiskCache::new(f.tmp(), 25).unwrap();
            c.insert_bytes("file1", &[1; 10]).unwrap();
            c.insert_bytes("file2", &[2; 10]).unwrap();
            // Get the file to bump its LRU status.
            assert_eq!(
                read_all(&mut c.get("file1").unwrap()).unwrap(),
                vec![1u8; 10]
            );
            // Adding this third file should put the cache above the limit.
            c.insert_bytes("file3", &[3; 10]).unwrap();
            assert_eq!(c.size(), 20);
            // The least-recently-used file should have been removed.
            assert!(!c.contains_key("file2"));
        }
        // Get rid of the cache, to test that the LRU persists on-disk as mtimes.
        // This is hacky, but mtime resolution on my mac with HFS+ is only 1 second, so we either
        // need to have a 1 second sleep in the test (boo) or adjust the mtimes back a bit so
        // that updating one file to the current time actually works to make it newer.
        set_mtime_back(f.tmp().join("file1"), 5);
        set_mtime_back(f.tmp().join("file3"), 5);
        {
            let mut c = LruDiskCache::new(f.tmp(), 25).unwrap();
            // Bump file1 again.
            c.get("file1").unwrap();
        }
        // Now check that the on-disk mtimes were updated and used.
        {
            let mut c = LruDiskCache::new(f.tmp(), 25).unwrap();
            assert!(c.contains_key("file1"));
            assert!(c.contains_key("file3"));
            assert_eq!(c.size(), 20);
            // Add another file to bump out the least-recently-used.
            c.insert_bytes("file4", &[4; 10]).unwrap();
            assert_eq!(c.size(), 20);
            assert!(!c.contains_key("file3"));
            assert!(c.contains_key("file1"));
        }
    }

    #[test]
    fn test_insert_bytes_too_large() {
        let f = TestFixture::new();
        let mut c = LruDiskCache::new(f.tmp(), 1).unwrap();
        match c.insert_bytes("a/b/c", &[0; 2]) {
            Err(Error::FileTooLarge) => {}
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn test_insert_file() {
        let f = TestFixture::new();
        let p1 = f.create_file("file1", 10);
        let p2 = f.create_file("file2", 10);
        let p3 = f.create_file("file3", 10);
        let mut c = LruDiskCache::new(f.tmp().join("cache"), 25).unwrap();
        c.insert_file("file1", &p1).unwrap();
        assert_eq!(c.len(), 1);
        c.insert_file("file2", &p2).unwrap();
        assert_eq!(c.len(), 2);
        // Get the file to bump its LRU status.
        assert_eq!(
            read_all(&mut c.get("file1").unwrap()).unwrap(),
            vec![0u8; 10]
        );
        // Adding this third file should put the cache above the limit.
        c.insert_file("file3", &p3).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c.size(), 20);
        // The least-recently-used file should have been removed.
        assert!(!c.contains_key("file2"));
        assert!(!p1.exists());
        assert!(!p2.exists());
        assert!(!p3.exists());
    }

    #[test]
    fn test_prepare_and_commit() {
        let f = TestFixture::new();
        let cache_dir = f.tmp();
        let mut c = LruDiskCache::new(cache_dir, 25).unwrap();
        let mut tmp = c.prepare_add("a/b/c", 10).unwrap();
        // An entry added but not committed doesn't count, except for the
        // (reserved) size of the disk cache.
        assert!(!c.contains_key("a/b/c"));
        assert_eq!(c.size(), 10);
        assert_eq!(c.lru.size(), 0);
        tmp.as_file_mut().write_all(&[0; 10]).unwrap();
        c.commit(tmp).unwrap();
        // Once committed, the file appears.
        assert!(c.contains_key("a/b/c"));
        assert_eq!(c.size(), 10);
        assert_eq!(c.lru.size(), 10);

        let mut tmp = c.prepare_add("a/b/d", 10).unwrap();
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 10);
        // Even though we haven't committed the second file, preparing for
        // the addition of the third one should put the cache above the
        // limit and trigger cleanup.
        let mut tmp2 = c.prepare_add("x/y/z", 10).unwrap();
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 0);
        // At this point, we expect the first entry to have been removed entirely.
        assert!(!c.contains_key("a/b/c"));
        assert!(!f.tmp().join("a/b/c").exists());
        tmp.as_file_mut().write_all(&[0; 10]).unwrap();
        tmp2.as_file_mut().write_all(&[0; 10]).unwrap();
        c.commit(tmp).unwrap();
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 10);
        c.commit(tmp2).unwrap();
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 20);

        let mut tmp = c.prepare_add("a/b/c", 5).unwrap();
        assert_eq!(c.size(), 25);
        assert_eq!(c.lru.size(), 20);
        // Committing a file bigger than the promised size should properly
        // handle the case where the real size makes the cache go over the limit.
        tmp.as_file_mut().write_all(&[0; 10]).unwrap();
        c.commit(tmp).unwrap();
        assert_eq!(c.size(), 20);
        assert_eq!(c.lru.size(), 20);
        assert!(!c.contains_key("a/b/d"));
        assert!(!f.tmp().join("a/b/d").exists());

        // If for some reason, the cache still contains a temporary file on
        // initialization, the temporary file is removed.
        let LruDiskCacheAddEntry { file, .. } = c.prepare_add("a/b/d", 5).unwrap();
        let (_, path) = file.keep().unwrap();
        std::mem::drop(c);
        // Ensure that the temporary file is indeed there.
        assert!(get_all_files(cache_dir).any(|(file, _)| file == path));
        LruDiskCache::new(cache_dir, 25).unwrap();
        // The temporary file should not be there anymore.
        assert!(get_all_files(cache_dir).all(|(file, _)| file != path));
    }

    #[test]
    fn test_remove() {
        let f = TestFixture::new();
        let p1 = f.create_file("file1", 10);
        let p2 = f.create_file("file2", 10);
        let p3 = f.create_file("file3", 10);
        let mut c = LruDiskCache::new(f.tmp().join("cache"), 25).unwrap();
        c.insert_file("file1", &p1).unwrap();
        c.insert_file("file2", &p2).unwrap();
        c.remove("file1").unwrap();
        c.insert_file("file3", &p3).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c.size(), 20);

        // file1 should have been removed.
        assert!(!c.contains_key("file1"));
        assert!(!f.tmp().join("cache").join("file1").exists());
        assert!(f.tmp().join("cache").join("file2").exists());
        assert!(f.tmp().join("cache").join("file3").exists());
        assert!(!p1.exists());
        assert!(!p2.exists());
        assert!(!p3.exists());

        let p4 = f.create_file("file1", 10);
        c.insert_file("file1", &p4).unwrap();
        assert_eq!(c.len(), 2);
        // file2 should have been removed.
        assert!(c.contains_key("file1"));
        assert!(!c.contains_key("file2"));
        assert!(!f.tmp().join("cache").join("file2").exists());
        assert!(!p4.exists());
    }
}
