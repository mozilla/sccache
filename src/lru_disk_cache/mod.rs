pub mod lru_cache;

use fs::File;
use fs_err as fs;
use std::borrow::Borrow;
use std::boxed::Box;
use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::error::Error as StdError;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::hash::BuildHasher;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use filetime::{FileTime, set_file_times};
pub use lru_cache::{LruCache, Meter};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::util::OsStrExt;

pub(crate) const TEMPFILE_PREFIX: &str = ".sccachetmp";

/// Marker file identifying a directory at the cache key depth as a finished `file_clone` entry.
pub const DIR_ENTRY_MARKER: &str = ".sccache_dir_entry";

fn dir_content_size(path: &Path) -> u64 {
    WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// Whether a removal error means the entry is already gone (removed out-of-band, or `ENOTDIR` from
/// a stale inner-file record after `file_clone` was toggled off) and is safe to ignore.
fn is_entry_already_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

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

struct ScannedEntry {
    mtime: SystemTime,
    path: PathBuf,
    size: u64,
    is_dir: bool,
}

/// An LRU cache of files on disk.
pub struct LruDiskCache<S: BuildHasher = RandomState> {
    lru: LruCache<OsString, u64, S, FileSize>,
    root: PathBuf,
    pending: Vec<OsString>,
    pending_size: u64,
    support_dir_entries: bool,
    dir_entries: HashSet<OsString>,
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
            Error::Io(e) => write!(f, "{}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FileTooLarge => None,
            Error::FileNotInCache => None,
            Error::Io(e) => Some(e),
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
        Self::new_with_dir_entries(path, size, false)
    }

    /// Like [`LruDiskCache::new`], but `support_dir_entries` enables recognition, sizing and
    /// eviction of uncompressed directory cache entries (used by the `file_clone` disk cache).
    pub fn new_with_dir_entries<T>(path: T, size: u64, support_dir_entries: bool) -> Result<Self>
    where
        PathBuf: From<T>,
    {
        LruDiskCache {
            lru: LruCache::with_meter(size, FileSize),
            root: PathBuf::from(path),
            pending: vec![],
            pending_size: 0,
            support_dir_entries,
            dir_entries: HashSet::new(),
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

    fn init(self) -> Result<Self> {
        fs::create_dir_all(&self.root)?;
        if self.support_dir_entries {
            self.init_with_dir_entries()
        } else {
            self.init_files_only()
        }
    }

    fn init_files_only(mut self) -> Result<Self> {
        for (file, size) in get_all_files(&self.root) {
            if file
                .file_name()
                .expect("Bad path?")
                .starts_with(TEMPFILE_PREFIX)
            {
                fs::remove_file(&file).unwrap_or_else(|e| {
                    error!("Error removing temporary file `{}`: {}", file.display(), e);
                });
            } else if !self.can_store(size) {
                fs::remove_file(file).unwrap_or_else(|e| {
                    error!(
                        "Error removing file `{}` which is too large for the cache ({} bytes)",
                        e, size
                    );
                });
            } else {
                self.add_file(AddFile::AbsPath(file), size)
                    .unwrap_or_else(|e| error!("Error adding file: {}", e));
            }
        }
        Ok(self)
    }

    fn init_with_dir_entries(mut self) -> Result<Self> {
        self.remove_temp_entries();

        let (mut entries, orphans) = self.scan_entries();

        for orphan in orphans {
            warn!(
                "Removing orphan cache directory without marker: {}",
                orphan.display()
            );
            fs::remove_dir_all(&orphan).unwrap_or_else(|e| {
                error!(
                    "Error removing orphan directory `{}`: {}",
                    orphan.display(),
                    e
                );
            });
        }

        entries.sort_by_key(|e| e.mtime);
        for ScannedEntry {
            path, size, is_dir, ..
        } in entries
        {
            if !self.can_store(size) {
                let res = if is_dir {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
                res.unwrap_or_else(|e| {
                    error!(
                        "Error removing entry `{}` which is too large for the cache ({} bytes): {}",
                        path.display(),
                        size,
                        e
                    );
                });
            } else {
                let rel = path
                    .strip_prefix(&self.root)
                    .expect("Bad path?")
                    .as_os_str()
                    .to_owned();
                match self.add_file(AddFile::RelPath(rel.as_os_str()), size) {
                    Ok(()) => {
                        if is_dir {
                            self.dir_entries.insert(rel);
                        }
                    }
                    Err(e) => error!("Error adding entry: {}", e),
                }
            }
        }
        Ok(self)
    }

    fn remove_temp_entries(&self) {
        let read_dir = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) => {
                error!(
                    "Error reading cache directory `{}`: {}",
                    self.root.display(),
                    e
                );
                return;
            }
        };
        for entry in read_dir.filter_map(std::result::Result::ok) {
            if !entry.file_name().starts_with(TEMPFILE_PREFIX) {
                continue;
            }
            let path = entry.path();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let res = if is_dir {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            res.unwrap_or_else(|e| {
                error!("Error removing temporary entry `{}`: {}", path.display(), e);
            });
        }
    }

    fn scan_entries(&self) -> (Vec<ScannedEntry>, Vec<PathBuf>) {
        let preprocessor_dir = self.root.join("preprocessor");
        let root_depth = self.root.components().count();
        let mut entries: Vec<ScannedEntry> = Vec::new();
        let mut orphans: Vec<PathBuf> = Vec::new();

        let mut walker = WalkDir::new(&self.root).min_depth(1).into_iter();
        loop {
            let entry = match walker.next() {
                None => break,
                Some(Ok(e)) => e,
                Some(Err(_)) => continue,
            };
            let path = entry.path();
            let is_dir = entry.file_type().is_dir();

            // Prune the preprocessor subtree (owned by the sibling cache) and any temp entries.
            if (is_dir && path == preprocessor_dir)
                || entry.file_name().starts_with(TEMPFILE_PREFIX)
            {
                if is_dir {
                    walker.skip_current_dir();
                }
                continue;
            }

            if is_dir {
                let depth = path.components().count() - root_depth;
                if depth < 3 {
                    continue;
                }
                if depth == 3 {
                    if path.join(DIR_ENTRY_MARKER).exists() {
                        if let Ok(meta) = entry.metadata() {
                            if let Ok(mtime) = meta.modified() {
                                let size = dir_content_size(path);
                                entries.push(ScannedEntry {
                                    mtime,
                                    path: path.to_owned(),
                                    size,
                                    is_dir: true,
                                });
                            }
                        }
                    } else {
                        let has_direct_files = fs::read_dir(path)
                            .map(|rd| {
                                rd.filter_map(std::result::Result::ok)
                                    .any(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                            })
                            .unwrap_or(false);
                        if has_direct_files {
                            orphans.push(path.to_owned());
                        }
                    }
                }
                walker.skip_current_dir();
            } else if entry.file_type().is_file() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        entries.push(ScannedEntry {
                            mtime,
                            path: path.to_owned(),
                            size: meta.len(),
                            is_dir: false,
                        });
                    }
                }
            }
        }
        (entries, orphans)
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
            let remove_path = self.rel_to_abs_path(&rel_path);
            let is_dir = self.dir_entries.remove(&rel_path);
            //TODO: check that files are removable during `init`, so that this is only
            // due to outside interference.
            let res = if is_dir {
                fs::remove_dir_all(&remove_path)
            } else {
                fs::remove_file(&remove_path)
            };
            res.unwrap_or_else(|e| {
                // Sometimes the entry has already been removed
                // this seems to happen when the max cache size has been reached
                // https://github.com/mozilla/sccache/issues/2092
                if is_entry_already_gone(&e) {
                    debug!(
                        "Error removing entry from cache as it is already gone: `{:?}`: {}",
                        remove_path, e
                    );
                } else {
                    panic!(
                        "Error removing entry from cache: `{:?}`: {}, {:?}",
                        remove_path,
                        e,
                        e.kind()
                    )
                }
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
                    error!("Failed to remove original file in insert_file: {}", e);
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
        match file.persist(&path) {
            Ok(_) => {}
            Err(persist_err) => {
                if path.is_dir() {
                    self.remove_entry_and_strands(&key);
                    fs::remove_dir_all(&path)?;
                    persist_err.file.persist(&path).map_err(|e| e.error)?;
                } else {
                    return Err(persist_err.error.into());
                }
            }
        }
        self.lru.insert(key, real_size);
        Ok(())
    }

    fn remove_entry_and_strands(&mut self, key: &OsStr) {
        self.dir_entries.remove(key);
        self.lru.remove(key);
        let key_path = Path::new(key);
        let strands: Vec<OsString> = self
            .lru
            .iter()
            .map(|(k, _)| k)
            .filter(|k| {
                let kp = Path::new(k.as_os_str());
                kp != key_path && kp.starts_with(key_path)
            })
            .cloned()
            .collect();
        for strand in strands {
            self.dir_entries.remove(&strand);
            self.lru.remove(&strand);
        }
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
                let res = if self.dir_entries.remove(key.as_ref()) {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
                match res {
                    Ok(()) => Ok(()),
                    Err(e) if is_entry_already_gone(&e) => {
                        debug!("Entry `{:?}` was already gone on remove: {}", path, e);
                        Ok(())
                    }
                    Err(e) => {
                        error!("Error removing entry from cache: `{:?}`: {}", path, e);
                        Err(e.into())
                    }
                }
            }
            None => Ok(()),
        }
    }

    /// Return `true` if `key` is registered as a directory (uncompressed) cache entry.
    pub fn contains_dir_key<K: AsRef<OsStr>>(&self, key: K) -> bool {
        self.dir_entries.contains(key.as_ref())
    }

    /// Update the LRU recency of an entry without opening it. `Ok(true)` if it was present.
    pub fn touch<K: AsRef<OsStr>>(&mut self, key: K) -> Result<bool> {
        let rel_path = key.as_ref();
        if self.lru.get(rel_path).is_some() {
            let path = self.rel_to_abs_path(rel_path);
            let t = FileTime::now();
            set_file_times(&path, t, t).unwrap_or_else(|e| {
                debug!("Failed to update mtime for {:?}: {}", path, e);
            });
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Atomically install the fully-populated `staging_dir` (which must already contain the entry's
    /// files and the marker) as the directory cache entry for `key`, replacing any existing entry.
    pub fn insert_dir<K: AsRef<OsStr>>(&mut self, key: K, staging_dir: &Path) -> Result<()> {
        let rel_path = key.as_ref().to_owned();
        let size = dir_content_size(staging_dir);
        if !self.can_store(size) {
            return Err(Error::FileTooLarge);
        }
        self.remove_any_entry(&rel_path);
        self.make_space(size)?;
        let final_path = self.rel_to_abs_path(&rel_path);
        let parent = final_path.parent().expect("Bad path?");
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        fs::rename(staging_dir, &final_path)?;
        self.dir_entries.insert(rel_path.clone());
        self.lru.insert(rel_path, size);
        Ok(())
    }

    fn remove_any_entry(&mut self, rel_path: &OsStr) {
        let was_dir = self.dir_entries.remove(rel_path);
        self.lru.remove(rel_path);
        let path = self.rel_to_abs_path(rel_path);
        let res = if was_dir || path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if let Err(e) = res {
            if e.kind() != std::io::ErrorKind::NotFound {
                error!("Error removing existing entry `{}`: {}", path.display(), e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fs::{self, File};
    use super::{Error, LruDiskCache, LruDiskCacheAddEntry, get_all_files};

    use filetime::{FileTime, set_file_times};
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

    fn make_staging_dir(root: &Path, name: &str, files: &[(&str, usize)]) -> PathBuf {
        let staging = root.join(format!("{}{}", super::TEMPFILE_PREFIX, name));
        fs::create_dir_all(&staging).unwrap();
        for (fname, size) in files {
            fs::write(staging.join(fname), vec![0u8; *size]).unwrap();
        }
        fs::write(staging.join(super::DIR_ENTRY_MARKER), b"").unwrap();
        staging
    }

    #[test]
    fn test_insert_dir_entry_size_and_reinit() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let key = Path::new("a").join("b").join("abcdef");
        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            let staging = make_staging_dir(&cache_dir, "s1", &[("obj", 20), ("d", 5)]);
            c.insert_dir(&key, &staging).unwrap();
            assert!(c.contains_key(&key));
            assert!(c.contains_dir_key(&key));
            assert_eq!(c.size(), 25);
            assert!(cache_dir.join(&key).is_dir());
            assert!(cache_dir.join(&key).join(super::DIR_ENTRY_MARKER).exists());
            assert_eq!(
                fs::read(cache_dir.join(&key).join("obj")).unwrap().len(),
                20
            );
            assert!(!staging.exists());
        }
        let c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
        assert!(c.contains_key(&key));
        assert!(c.contains_dir_key(&key));
        assert_eq!(c.size(), 25);
    }

    #[test]
    fn test_dir_entry_eviction_uses_remove_dir_all() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 60, true).unwrap();
        let k1 = Path::new("a").join("a").join("k1");
        let k2 = Path::new("b").join("b").join("k2");
        let k3 = Path::new("c").join("c").join("k3");
        c.insert_dir(&k1, &make_staging_dir(&cache_dir, "s1", &[("obj", 30)]))
            .unwrap();
        c.insert_dir(&k2, &make_staging_dir(&cache_dir, "s2", &[("obj", 30)]))
            .unwrap();
        assert_eq!(c.size(), 60);
        c.insert_dir(&k3, &make_staging_dir(&cache_dir, "s3", &[("obj", 30)]))
            .unwrap();
        assert_eq!(c.size(), 60);
        assert!(!c.contains_key(&k1));
        assert!(
            !cache_dir.join(&k1).exists(),
            "evicted directory entry must be fully removed"
        );
        assert!(c.contains_key(&k2));
        assert!(c.contains_key(&k3));
    }

    #[test]
    fn test_preprocessor_subtree_untouched_on_dir_entry_init() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let compressed = Path::new("a").join("b").join("compkey");
        let preproc = Path::new("preprocessor")
            .join("c")
            .join("d")
            .join("e")
            .join("ppkey");
        fs::create_dir_all(cache_dir.join(&compressed).parent().unwrap()).unwrap();
        fs::write(cache_dir.join(&compressed), vec![0u8; 10]).unwrap();
        fs::create_dir_all(cache_dir.join(&preproc).parent().unwrap()).unwrap();
        fs::write(cache_dir.join(&preproc), vec![0u8; 10]).unwrap();

        let c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
        assert!(c.contains_key(&compressed), "compressed entry is tracked");
        assert!(
            cache_dir.join(&preproc).exists(),
            "preprocessor file must NOT be deleted"
        );
        assert!(
            !c.contains_key(&preproc),
            "preprocessor subtree is pruned from the object cache, not tracked"
        );
    }

    #[test]
    fn test_orphan_dir_cleanup_on_init() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let comp = Path::new("a").join("b").join("validkey");
        let good = Path::new("e").join("f").join("goodkey");
        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            c.insert_bytes(&comp, &[0u8; 10]).unwrap();
            c.insert_dir(&good, &make_staging_dir(&cache_dir, "good", &[("obj", 10)]))
                .unwrap();
        }
        let orphan = cache_dir.join("c").join("d").join("orphankey");
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join("obj"), vec![0u8; 10]).unwrap();

        let c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
        assert!(c.contains_key(&comp), "compressed entry survives reinit");
        assert!(
            c.contains_key(&good),
            "marker directory entry survives reinit"
        );
        assert!(c.contains_dir_key(&good));
        assert!(
            !orphan.exists(),
            "marker-less orphan directory at key depth is removed"
        );
        assert!(cache_dir.join(&comp).exists());
    }

    #[test]
    fn test_compressed_entries_survive_dir_entry_reinit() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let key1 = Path::new("a").join("b").join("abcdef1234");
        let key2 = Path::new("a").join("b").join("abcdef5678");
        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            c.insert_bytes(&key1, &[1; 10]).unwrap();
            c.insert_bytes(&key2, &[2; 10]).unwrap();
            assert_eq!(c.len(), 2);
        }
        let c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
        assert!(c.contains_key(&key1));
        assert!(c.contains_key(&key2));
        assert_eq!(c.len(), 2);
        assert_eq!(c.size(), 20);
    }

    #[test]
    fn test_remove_directory_entry() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
        let key = Path::new("a").join("b").join("dirkey");
        c.insert_dir(&key, &make_staging_dir(&cache_dir, "rm", &[("obj", 20)]))
            .unwrap();
        assert!(c.contains_key(&key) && c.contains_dir_key(&key));
        assert_eq!(c.size(), 20);

        c.remove(&key).unwrap();
        assert!(!c.contains_key(&key));
        assert!(!c.contains_dir_key(&key));
        assert!(!cache_dir.join(&key).exists());
        assert_eq!(c.size(), 0);
    }

    #[test]
    fn test_remove_temp_entries_on_init() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        let prefix = super::TEMPFILE_PREFIX;
        let tmp_file = cache_dir.join(format!("{prefix}leftover"));
        fs::write(&tmp_file, b"junk").unwrap();
        let tmp_dir = cache_dir.join(format!("{prefix}dir"));
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join("inner"), b"junk").unwrap();
        let real = Path::new("a").join("b").join("realkey");
        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            c.insert_bytes(&real, &[3; 10]).unwrap();
            // Re-plant temp leftovers after init (insert_bytes doesn't remove them).
            fs::write(&tmp_file, b"junk").unwrap();
            fs::create_dir_all(&tmp_dir).unwrap();
            fs::write(tmp_dir.join("inner"), b"junk").unwrap();
        }
        let c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
        assert!(!tmp_file.exists(), "leftover temp file removed on init");
        assert!(!tmp_dir.exists(), "leftover temp dir removed on init");
        assert!(c.contains_key(&real));
    }

    #[test]
    fn test_dir_entry_small_branches() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 100, true).unwrap();

        assert!(!c.touch(Path::new("a").join("b").join("nope")).unwrap());

        let big = make_staging_dir(&cache_dir, "big", &[("obj", 200)]);
        let key = Path::new("a").join("b").join("big");
        assert!(matches!(c.insert_dir(&key, &big), Err(Error::FileTooLarge)));

        let key2 = Path::new("c").join("d").join("dup");
        c.insert_dir(&key2, &make_staging_dir(&cache_dir, "d1", &[("obj", 10)]))
            .unwrap();
        c.insert_dir(&key2, &make_staging_dir(&cache_dir, "d2", &[("obj", 20)]))
            .unwrap();
        assert!(c.contains_dir_key(&key2));
        assert_eq!(c.size(), 20, "second insert replaced the first");
        assert!(c.touch(&key2).unwrap());
    }

    #[test]
    fn test_toggle_file_clone_off_commit_cleans_strands() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let key = Path::new("a").join("b").join("togglekey");

        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            c.insert_dir(
                &key,
                &make_staging_dir(&cache_dir, "t", &[("obj", 30), ("d", 10)]),
            )
            .unwrap();
            assert!(c.contains_dir_key(&key));
        }

        // Reopen with file_clone off: init_files_only registers the inner files as strands (`<key>/obj`).
        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, false).unwrap();
        let strand = key.join("obj");
        assert!(
            c.contains_key(&strand),
            "inner-file strand is tracked after toggle-off"
        );

        let mut tmp = c.prepare_add(&key, 10).unwrap();
        tmp.as_file_mut().write_all(&[7u8; 10]).unwrap();
        c.commit(tmp).unwrap();

        assert!(
            cache_dir.join(&key).is_file(),
            "key is now a compressed file"
        );
        assert!(!c.contains_dir_key(&key));
        assert!(c.contains_key(&key));
        assert!(
            !c.contains_key(&strand),
            "stranded inner-file record removed"
        );
        assert_eq!(read_all(&mut c.get(&key).unwrap()).unwrap(), vec![7u8; 10]);

        c.insert_bytes(Path::new("x").join("y").join("z"), &[0u8; 995])
            .unwrap();
        assert!(c.contains_key(Path::new("x").join("y").join("z")));
        assert!(!c.contains_key(&key), "the old entry was evicted");
    }

    #[test]
    fn test_evict_strand_under_file_key_no_panic() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let key = Path::new("a").join("b").join("k");

        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 100, true).unwrap();
            c.insert_dir(&key, &make_staging_dir(&cache_dir, "s", &[("obj", 80)]))
                .unwrap();
        }
        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 100, false).unwrap();
        assert!(c.contains_key(key.join("obj")));

        // Replace the key dir with a file so the strand's parent is now a file → ENOTDIR on eviction.
        fs::remove_dir_all(cache_dir.join(&key)).unwrap();
        fs::write(cache_dir.join(&key), [0u8; 5]).unwrap();

        c.insert_bytes(Path::new("c").join("d").join("e"), &[1u8; 90])
            .unwrap();
        assert!(c.contains_key(Path::new("c").join("d").join("e")));
    }

    #[test]
    fn test_remove_strand_under_file_key_is_ok() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        let key = Path::new("a").join("b").join("k");

        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            c.insert_dir(&key, &make_staging_dir(&cache_dir, "s", &[("obj", 20)]))
                .unwrap();
        }
        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, false).unwrap();
        let strand = key.join("obj");
        assert!(c.contains_key(&strand));

        // Replace the key dir with a file so the strand's parent is now a file → ENOTDIR on remove.
        fs::remove_dir_all(cache_dir.join(&key)).unwrap();
        fs::write(cache_dir.join(&key), [0u8; 5]).unwrap();

        c.remove(&strand).unwrap();
        assert!(
            !c.contains_key(&strand),
            "strand record dropped after remove"
        );
    }

    #[test]
    fn test_remove_entry_and_strands_prefix_precision() {
        let f = TestFixture::new();
        let cache_dir = f.tmp().join("cache");
        // Both keys live under `a/b/`; "key2" as a string starts with "key".
        let key = Path::new("a").join("b").join("key");
        let key2 = Path::new("a").join("b").join("key2");

        {
            let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, true).unwrap();
            c.insert_dir(&key, &make_staging_dir(&cache_dir, "a", &[("obj", 10)]))
                .unwrap();
            c.insert_dir(&key2, &make_staging_dir(&cache_dir, "b", &[("obj", 10)]))
                .unwrap();
        }

        let mut c = LruDiskCache::new_with_dir_entries(&cache_dir, 1000, false).unwrap();
        let strand = key.join("obj");
        let sibling_strand = key2.join("obj");
        assert!(c.contains_key(&strand));
        assert!(c.contains_key(&sibling_strand));

        let mut tmp = c.prepare_add(&key, 5).unwrap();
        tmp.as_file_mut().write_all(&[7u8; 5]).unwrap();
        c.commit(tmp).unwrap();

        assert!(cache_dir.join(&key).is_file(), "target replaced by a file");
        assert!(!c.contains_key(&strand), "target strand dropped");
        assert!(
            c.contains_key(&sibling_strand),
            "sibling strand must survive (component-wise prefix precision)"
        );
        assert!(
            cache_dir.join(&key2).join("obj").exists(),
            "sibling entry's files untouched on disk"
        );
    }
}
