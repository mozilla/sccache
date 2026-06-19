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

use super::utils::{get_file_mode, set_file_mode};
use crate::errors::*;
use crate::lru_disk_cache::DIR_ENTRY_MARKER;
use fs_err as fs;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Subdirectory inside a `file_clone` entry holding per-object files, so object keys can't collide
/// with the reserved `stdout`/`stderr`/marker names.
pub(crate) const OBJECTS_SUBDIR: &str = "objects";

/// Validate that an object key is a single normal path component (no separators/`..`/NUL), so it
/// can't escape the `objects/` directory via traversal.
pub(crate) fn validate_object_key(key: &str) -> Result<()> {
    if key.is_empty() || key.contains('\0') {
        bail!("invalid cache object key {:?}", key);
    }
    let mut components = Path::new(key).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(c)), None) if c == OsStr::new(key) => Ok(()),
        _ => bail!("cache object key {:?} is not a single path component", key),
    }
}

/// Serialize the object-key → unix-mode map into the marker file as NUL-separated `<mode>\0<key>\0`
/// records (kept out-of-band so cache objects can stay `0600`).
pub(crate) fn serialize_mode_manifest(modes: &[(String, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, mode) in modes {
        out.extend_from_slice(mode.to_string().as_bytes());
        out.push(0);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
    }
    out
}

/// Parse a marker file produced by [`serialize_mode_manifest`], tolerating empty/corrupt records.
pub(crate) fn parse_mode_manifest(bytes: &[u8]) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    let mut fields = bytes.split(|&b| b == 0);
    while let (Some(mode_b), Some(key_b)) = (fields.next(), fields.next()) {
        if let (Ok(mode_s), Ok(key_s)) = (std::str::from_utf8(mode_b), std::str::from_utf8(key_b)) {
            if let Ok(mode) = mode_s.parse::<u32>() {
                map.insert(key_s.to_owned(), mode);
            }
        }
    }
    map
}

/// Counts of how cache objects were restored (reflinked vs copied), for `--show-stats`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionStats {
    pub objects_reflinked: u64,
    pub objects_copied: u64,
}

impl ExtractionStats {
    fn record(&mut self, outcome: crate::reflink::ReflinkOutcome) {
        if outcome.reflinked() {
            self.objects_reflinked += 1;
        } else {
            self.objects_copied += 1;
        }
    }
}

/// Cache object sourced by a file.
#[derive(Clone)]
pub struct FileObjectSource {
    /// Identifier for this object. Should be unique within a compilation unit.
    /// Note that a compilation unit is a single source file in C/C++ and a crate in Rust.
    pub key: String,
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Whether the file must be present on disk and is essential for the compilation.
    pub optional: bool,
}

/// Result of a cache lookup.
pub enum Cache {
    /// Result was found in cache (compressed ZIP-of-zstd format).
    Hit(CacheRead),
    /// Result was found in cache (uncompressed directory format, `file_clone` mode).
    UncompressedHit(UncompressedCacheEntry),
    /// Result was not found in cache.
    Miss,
    /// Do not cache the results of the compilation.
    None,
    /// Cache entry should be ignored, force compilation.
    Recache,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Cache::Hit(_) => write!(f, "Cache::Hit(...)"),
            Cache::UncompressedHit(_) => write!(f, "Cache::UncompressedHit(...)"),
            Cache::Miss => write!(f, "Cache::Miss"),
            Cache::None => write!(f, "Cache::None"),
            Cache::Recache => write!(f, "Cache::Recache"),
        }
    }
}

/// CacheMode is used to represent which mode we are using.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheMode {
    /// Only read cache from storage.
    ReadOnly,
    /// Full support of cache storage: read and write.
    ReadWrite,
}

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Data stored in the compiler cache.
pub struct CacheRead {
    zip: ZipArchive<Box<dyn ReadSeek>>,
}

/// Represents a failure to decompress stored object data.
#[derive(Debug)]
pub struct DecompressionFailure;

impl std::fmt::Display for DecompressionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to decompress content")
    }
}

impl std::error::Error for DecompressionFailure {}

impl CacheRead {
    /// Create a cache entry from `reader`.
    pub fn from<R>(reader: R) -> Result<CacheRead>
    where
        R: ReadSeek + 'static,
    {
        let z = ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>)
            .context("Failed to parse cache entry")?;
        Ok(CacheRead { zip: z })
    }

    /// Get an object from this cache entry at `name` and write it to `to`.
    /// If the file has stored permissions, return them.
    pub fn get_object<T>(&mut self, name: &str, to: &mut T) -> Result<Option<u32>>
    where
        T: Write,
    {
        let file = self.zip.by_name(name).or(Err(DecompressionFailure))?;
        if file.compression() != CompressionMethod::Stored {
            bail!(DecompressionFailure);
        }
        let mode = file.unix_mode();
        zstd::stream::copy_decode(file, to).or(Err(DecompressionFailure))?;
        Ok(mode)
    }

    /// Get the stdout from this cache entry, if it exists.
    pub fn get_stdout(&mut self) -> Vec<u8> {
        self.get_bytes("stdout")
    }

    /// Get the stderr from this cache entry, if it exists.
    pub fn get_stderr(&mut self) -> Vec<u8> {
        self.get_bytes("stderr")
    }

    fn get_bytes(&mut self, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        drop(self.get_object(name, &mut bytes));
        bytes
    }

    pub async fn extract_objects<T>(
        mut self,
        objects: T,
        pool: &tokio::runtime::Handle,
    ) -> Result<ExtractionStats>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                if is_path_null(&path) {
                    // For unix, this is just a fast path to discard such outputs,
                    // so it is not an issue if `is_path_null` has false-negatives.
                    // But for Windows, since `NUL` looks like a relative path, the
                    // temporary file creation logic would happily succeed, creating
                    // a temp file in the CWD, but then the subsequent `persist`
                    // would fail with `ERROR_ALREADY_EXISTS`, since `NUL` always
                    // exists and cannot be `replaced`, so we really need to
                    // short-circuit more of such cases on Windows.
                    debug!("Skipping output to {}", path.display());
                    continue;
                }
                let dir = match path.parent() {
                    Some(d) => d,
                    None => bail!("Output file without a parent directory!"),
                };
                // Write the cache entry to a tempfile and then atomically
                // move it to its final location so that other rustc invocations
                // happening in parallel don't see a partially-written file.
                match (NamedTempFile::new_in(dir), optional) {
                    (Ok(mut tmp), _) => {
                        match (self.get_object(&key, &mut tmp), optional) {
                            (Ok(mode), _) => {
                                tmp.persist(&path)?;
                                if let Some(mode) = mode {
                                    set_file_mode(path.as_path(), mode)?;
                                }
                            }
                            (Err(e), false) => return Err(e),
                            // skip if no object found and it's optional
                            (Err(_), true) => continue,
                        }
                    }
                    (Err(e), false) => {
                        // Fall back to writing directly to the final location
                        warn!("Failed to create temp file on the same file system: {e}");
                        let mut f = std::fs::File::create(&path)?;
                        // `optional` is false in this branch, so do not ignore errors
                        let mode = self.get_object(&key, &mut f)?;
                        if let Some(mode) = mode {
                            if let Err(e) = set_file_mode(path.as_path(), mode) {
                                // Here we ignore errors from setting file mode because
                                // if we could not create a temp file in the same directory,
                                // we probably can't set the mode either (e.g. /dev/stuff)
                                warn!("Failed to reset file mode: {e}");
                            }
                        }
                    }
                    // skip if no object found and it's optional
                    (Err(_), true) => continue,
                }
            }
            Ok(ExtractionStats::default())
        })
        .await?
    }
}

#[cfg(unix)]
pub(crate) fn is_path_null(path: &Path) -> bool {
    path == Path::new("/dev/null")
}

#[cfg(windows)]
pub(crate) fn is_path_null(path: &Path) -> bool {
    // For Windows, it appears that `NUL` with whatever extension is also a blackhole
    // (at least for `CreateFileX`), so it does not suffice to check for an exact match
    // Also note that gcc, cl.exe, et al. append a correct extension automatically even
    // if the user asks for output to `NUL`.
    let Some(stem) = path.file_stem() else {
        return false;
    };
    stem.eq_ignore_ascii_case("NUL")
}

/// Data to be stored in the compiler cache.
pub struct CacheWrite {
    zip: ZipWriter<Cursor<Vec<u8>>>,
}

impl CacheWrite {
    /// Create a new, empty cache entry.
    pub fn new() -> CacheWrite {
        CacheWrite {
            zip: ZipWriter::new(Cursor::new(vec![])),
        }
    }

    /// Create a new cache entry populated with the contents of `objects`.
    pub async fn from_objects<T>(objects: T, pool: &tokio::runtime::Handle) -> Result<CacheWrite>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            let mut entry = CacheWrite::new();
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                let f = fs::File::open(&path)
                    .with_context(|| format!("failed to open file `{:?}`", path));
                match (f, optional) {
                    (Ok(mut f), _) => {
                        let mode = get_file_mode(&f)?;
                        entry.put_object(&key, &mut f, mode).with_context(|| {
                            format!("failed to put object `{:?}` in cache entry", path)
                        })?;
                    }
                    (Err(e), false) => return Err(e),
                    (Err(_), true) => continue,
                }
            }
            Ok(entry)
        })
        .await?
    }

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    /// If `mode` is `Some`, store the file entry with that mode.
    pub fn put_object<T>(&mut self, name: &str, from: &mut T, mode: Option<u32>) -> Result<()>
    where
        T: Read,
    {
        // We're going to declare the compression method as "stored",
        // but we're actually going to store zstd-compressed blobs.
        let opts = FileOptions::default().compression_method(CompressionMethod::Stored);
        let opts = if let Some(mode) = mode {
            opts.unix_permissions(mode)
        } else {
            opts
        };
        self.zip
            .start_file(name, opts)
            .context("Failed to start cache entry object")?;

        let compression_level = std::env::var("SCCACHE_CACHE_ZSTD_LEVEL")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(3);
        zstd::stream::copy_encode(from, &mut self.zip, compression_level)?;
        Ok(())
    }

    pub fn put_stdout(&mut self, bytes: &[u8]) -> Result<()> {
        self.put_bytes("stdout", bytes)
    }

    pub fn put_stderr(&mut self, bytes: &[u8]) -> Result<()> {
        self.put_bytes("stderr", bytes)
    }

    fn put_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        if !bytes.is_empty() {
            let mut cursor = Cursor::new(bytes);
            return self.put_object(name, &mut cursor, None);
        }
        Ok(())
    }

    /// Finish writing data to the cache entry writer, and return the data.
    pub fn finish(self) -> Result<Vec<u8>> {
        let CacheWrite { mut zip } = self;
        let cur = zip.finish().context("Failed to finish cache entry zip")?;
        Ok(cur.into_inner())
    }
}

impl Default for CacheWrite {
    fn default() -> Self {
        Self::new()
    }
}

/// An uncompressed (`file_clone`) cache entry: a directory with an `objects/` subdir, optional
/// `stdout`/`stderr` files, and a marker file carrying the per-object mode manifest.
#[derive(Debug)]
pub struct UncompressedCacheEntry {
    dir: PathBuf,
}

impl UncompressedCacheEntry {
    /// Create a handle to the entry stored at `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Read the stored stdout, or an empty vector if there is none.
    pub fn get_stdout(&self) -> Vec<u8> {
        self.get_bytes_file("stdout")
    }

    /// Read the stored stderr, or an empty vector if there is none.
    pub fn get_stderr(&self) -> Vec<u8> {
        self.get_bytes_file("stderr")
    }

    fn get_bytes_file(&self, name: &str) -> Vec<u8> {
        match fs::read(self.dir.join(name)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                debug!(
                    "Failed to read {} from uncompressed cache entry: {}",
                    name, e
                );
                Vec::new()
            }
        }
    }

    /// Restore the requested `objects` into their destinations (reflinking or copying), applying the
    /// original mode from the manifest. Returns reflinked-vs-copied counts.
    pub async fn extract_objects<T>(
        self,
        objects: T,
        pool: &tokio::runtime::Handle,
    ) -> Result<ExtractionStats>
    where
        T: IntoIterator<Item = FileObjectSource> + Send + Sync + 'static,
    {
        pool.spawn_blocking(move || {
            let modes = parse_mode_manifest(&fs::read(self.dir.join(DIR_ENTRY_MARKER))?);
            let objects_dir = self.dir.join(OBJECTS_SUBDIR);
            let mut stats = ExtractionStats::default();
            for FileObjectSource {
                key,
                path,
                optional,
            } in objects
            {
                if is_path_null(&path) {
                    debug!("Skipping output to {}", path.display());
                    continue;
                }
                if let Err(e) = validate_object_key(&key) {
                    if optional {
                        continue;
                    }
                    return Err(e);
                }
                let src = objects_dir.join(&key);
                if !src.exists() {
                    if optional {
                        continue;
                    }
                    bail!(
                        "Required object `{}` not found in uncompressed cache entry",
                        key
                    );
                }
                let dir = match path.parent() {
                    Some(d) => d,
                    None => bail!("Output file without a parent directory!"),
                };
                if let Err(e) = fs::create_dir_all(dir) {
                    if optional {
                        continue;
                    }
                    return Err(e).with_context(|| {
                        format!("failed to create output directory {}", dir.display())
                    });
                }
                let mode = modes.get(&key).copied();
                let outcome = match crate::reflink::reflink_or_copy_atomic(&src, &path, mode) {
                    Ok(outcome) => outcome,
                    Err(_) => match crate::reflink::reflink_or_copy_direct(&src, &path, mode) {
                        Ok(outcome) => outcome,
                        Err(e) => {
                            if optional {
                                continue;
                            }
                            return Err(anyhow::Error::from(e)).with_context(|| {
                                format!("failed to restore object `{}` to {}", key, path.display())
                            });
                        }
                    },
                };
                stats.record(outcome);
            }
            Ok(stats)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_extract_object_to_devnull_works() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let pool = runtime.handle();

        let cache_data = CacheWrite::new();
        let cache_read =
            CacheRead::from(std::io::Cursor::new(cache_data.finish().unwrap())).unwrap();

        let objects = vec![FileObjectSource {
            key: "test_key".to_string(),
            path: PathBuf::from("/dev/null"),
            optional: false,
        }];

        let result = runtime.block_on(cache_read.extract_objects(objects, pool));
        assert!(result.is_ok(), "Extracting to /dev/null should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn test_extract_object_to_dev_fd_something() {
        // Open a pipe, write to `/dev/fd/{fd}` and check the other end that the correct data was written.
        use std::os::fd::AsRawFd;
        use tokio::io::AsyncReadExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let pool = runtime.handle();
        let mut cache_data = CacheWrite::new();
        let data = b"test data";
        cache_data.put_bytes("test_key", data).unwrap();
        let cache_read =
            CacheRead::from(std::io::Cursor::new(cache_data.finish().unwrap())).unwrap();
        runtime.block_on(async {
            let (sender, mut receiver) = tokio::net::unix::pipe::pipe().unwrap();
            let sender_fd = sender.into_blocking_fd().unwrap();
            let raw_fd = sender_fd.as_raw_fd();
            let fd_path = PathBuf::from(format!("/dev/fd/{raw_fd}"));
            let objects = vec![FileObjectSource {
                key: "test_key".to_string(),
                path: fd_path.clone(),
                optional: false,
            }];
            // On FreeBSD, `/dev/fd/{fd}` does not always exist (i.e. without mounting `fdescfs`), so we skip this test if we get `ENOENT`.
            if ! fd_path.exists() {
                info!("Skipping test_extract_object_to_dev_fd_something because /dev/fd/{raw_fd} does not exist");
                return;
            }
            let result = cache_read.extract_objects(objects, pool).await;
            assert!(
                result.is_ok(),
                "Extracting to /dev/fd/{raw_fd} should succeed"
            );
            let mut buf = vec![0; data.len()];
            let n = receiver.read_exact(&mut buf).await.unwrap();
            assert_eq!(n, data.len(), "Read the correct number of bytes");
            assert_eq!(buf, data, "Read the correct data from /dev/fd/{raw_fd}");
        });
    }

    #[test]
    fn test_extract_object_to_non_writable_path() {
        // See `test_extract_object_to_dev_fd_something`: we still cannot cover all platforms by the other tests. Here we test a more portable case of creating a file and making its parent directory non-writable, in which case we should still be able to extract the object successfully.

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let pool = runtime.handle();

        let mut cache_data = CacheWrite::new();
        cache_data.put_bytes("test_key", b"real_test_data").unwrap();
        let cache_read =
            CacheRead::from(std::io::Cursor::new(cache_data.finish().unwrap())).unwrap();

        let tmpdir = tempfile::tempdir().unwrap();
        let target_path = tmpdir.path().join("test_file");
        std::fs::write(&target_path, b"test").unwrap();
        // The current Rust fs permissions API is kind of awkward...
        let mut perm = tmpdir.path().metadata().unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(tmpdir.path(), perm.clone()).unwrap();
        // Note that this doesn't guarantee that the a new file cannot be created anymore.
        // For example, as documented in `std::fs::Permissions::set_readonly`, the
        // `FILE_ATTRIBUTE_READONLY` attribute on Windows is entirely ignored for directories.
        // std::fs::File::create(tmpdir.path().join("another_file")).unwrap_err();

        let objects = vec![FileObjectSource {
            key: "test_key".to_string(),
            path: target_path.clone(),
            optional: false,
        }];

        let result = runtime.block_on(cache_read.extract_objects(objects, pool));
        assert!(
            result.is_ok(),
            "Extracting to the target path should succeed"
        );
        // Test the content; make sure the old content is overwritten
        let content = std::fs::read(&target_path).unwrap();
        assert_eq!(
            content, b"real_test_data",
            "Extracted content should be correct"
        );

        // `tempfile` needs us to reset permissions for cleanup to work
        #[allow(
            clippy::permissions_set_readonly_false,
            reason = "The affected directory is immediately deleted with no security implications"
        )]
        perm.set_readonly(false);
        std::fs::set_permissions(tmpdir.path(), perm).unwrap();
        tmpdir.close().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn test_extract_object_to_nul_works() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let pool = runtime.handle();

        let cache_data = CacheWrite::new();
        let cache_read =
            CacheRead::from(std::io::Cursor::new(cache_data.finish().unwrap())).unwrap();

        let objects = vec![FileObjectSource {
            key: "test_key".to_string(),
            path: PathBuf::from("NUL"),
            optional: false,
        }];

        let result = runtime.block_on(cache_read.extract_objects(objects, pool));
        assert!(result.is_ok(), "Extracting to NUL should succeed");
    }

    fn current_thread_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap()
    }

    fn make_uncompressed_entry(objects: &[(&str, &[u8], u32)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let objects_dir = dir.path().join(OBJECTS_SUBDIR);
        std::fs::create_dir(&objects_dir).unwrap();
        let mut manifest = Vec::new();
        for (name, contents, mode) in objects {
            std::fs::write(objects_dir.join(name), contents).unwrap();
            manifest.push(((*name).to_string(), *mode));
        }
        std::fs::write(
            dir.path().join(DIR_ENTRY_MARKER),
            serialize_mode_manifest(&manifest),
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_validate_object_key() {
        for ok in ["obj", "d", "stdout", "stderr", "output.rlib", "a.b.c"] {
            assert!(validate_object_key(ok).is_ok(), "{ok:?} should be valid");
        }
        for bad in ["", ".", "..", "a/b", "/a", "a/", "a\0b"] {
            assert!(
                validate_object_key(bad).is_err(),
                "{bad:?} should be invalid"
            );
        }
        #[cfg(windows)]
        assert!(validate_object_key("a\\b").is_err());
    }

    #[test]
    fn test_mode_manifest_roundtrip() {
        let modes = vec![
            ("obj".to_string(), 0o100644u32),
            ("weird key with spaces".to_string(), 0o100755u32),
        ];
        let parsed = parse_mode_manifest(&serialize_mode_manifest(&modes));
        assert_eq!(parsed.get("obj"), Some(&0o100644));
        assert_eq!(parsed.get("weird key with spaces"), Some(&0o100755));
        assert!(parse_mode_manifest(b"").is_empty());
        assert!(parse_mode_manifest(b"garbage").is_empty());
        assert!(parse_mode_manifest(b"notanumber\0key\0").is_empty());
    }

    #[test]
    fn test_uncompressed_extract_required_create_dir_fails() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"data", 0o100644)]);
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let out_dir = tempfile::tempdir().unwrap();
        // `blocker` is a regular file, so `blocker/sub` can't be created as a directory.
        let blocker = out_dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let dest = blocker.join("sub").join("out.o");

        let result = runtime.block_on(entry.extract_objects(
            vec![FileObjectSource {
                key: "obj".to_string(),
                path: dest,
                optional: false,
            }],
            runtime.handle(),
        ));
        assert!(
            result.is_err(),
            "required object with un-creatable dest dir must error"
        );
    }

    #[test]
    fn test_uncompressed_extract_double_failure_required_errors_optional_skips() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"data", 0o100644)]);

        let out_dir = tempfile::tempdir().unwrap();
        // Destination path is an existing directory: both restore paths fail to write to it.
        let dest = out_dir.path().join("dest_is_a_dir");
        std::fs::create_dir(&dest).unwrap();

        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());
        let required = vec![FileObjectSource {
            key: "obj".to_string(),
            path: dest.clone(),
            optional: false,
        }];
        assert!(
            runtime
                .block_on(entry.extract_objects(required, runtime.handle()))
                .is_err(),
            "required object that can't be restored (both attempts fail) must error"
        );

        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());
        let optional = vec![FileObjectSource {
            key: "obj".to_string(),
            path: dest.clone(),
            optional: true,
        }];
        let stats = runtime
            .block_on(entry.extract_objects(optional, runtime.handle()))
            .unwrap();
        assert_eq!(stats, ExtractionStats::default());
        assert!(
            dest.is_dir(),
            "optional double-failure leaves dest untouched"
        );
    }

    #[test]
    fn test_uncompressed_extract_roundtrip() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"object-bytes", 0o100644)]);
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("restored.o");
        let objects = vec![FileObjectSource {
            key: "obj".to_string(),
            path: out_path.clone(),
            optional: false,
        }];

        let stats = runtime
            .block_on(entry.extract_objects(objects, runtime.handle()))
            .unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), b"object-bytes");
        assert_eq!(stats.objects_reflinked + stats.objects_copied, 1);
    }

    #[test]
    fn test_uncompressed_extract_reflinks_on_cow() {
        let out_dir = tempfile::tempdir().unwrap();
        if !crate::reflink::is_reflink_supported(out_dir.path()) {
            return; // non-CoW filesystem: covered by the FS-agnostic test above.
        }
        // The cache entry must live on the same filesystem as the destination to reflink.
        let entry_dir = tempfile::tempdir_in(out_dir.path()).unwrap();
        let objects_dir = entry_dir.path().join(OBJECTS_SUBDIR);
        std::fs::create_dir(&objects_dir).unwrap();
        let data = vec![7u8; 256 * 1024];
        std::fs::write(objects_dir.join("obj"), &data).unwrap();
        std::fs::write(
            entry_dir.path().join(DIR_ENTRY_MARKER),
            serialize_mode_manifest(&[("obj".to_string(), 0o100644)]),
        )
        .unwrap();
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let runtime = current_thread_runtime();
        let out_path = out_dir.path().join("restored.o");
        let stats = runtime
            .block_on(entry.extract_objects(
                vec![FileObjectSource {
                    key: "obj".to_string(),
                    path: out_path.clone(),
                    optional: false,
                }],
                runtime.handle(),
            ))
            .unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), data);
        assert_eq!(
            stats.objects_reflinked, 1,
            "should reflink on a CoW filesystem"
        );
        assert_eq!(stats.objects_copied, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_uncompressed_extract_to_devnull() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"data", 0o100644)]);
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let objects = vec![FileObjectSource {
            key: "obj".to_string(),
            path: PathBuf::from("/dev/null"),
            optional: false,
        }];
        let stats = runtime
            .block_on(entry.extract_objects(objects, runtime.handle()))
            .unwrap();
        assert_eq!(stats, ExtractionStats::default());
    }

    #[test]
    fn test_uncompressed_extract_missing_optional_is_skipped() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"data", 0o100644)]);
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let out_dir = tempfile::tempdir().unwrap();
        let objects = vec![FileObjectSource {
            key: "missing".to_string(),
            path: out_dir.path().join("missing.d"),
            optional: true,
        }];
        let stats = runtime
            .block_on(entry.extract_objects(objects, runtime.handle()))
            .unwrap();
        assert_eq!(stats, ExtractionStats::default());
        assert!(!out_dir.path().join("missing.d").exists());
    }

    #[test]
    fn test_uncompressed_extract_missing_required_errors() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"data", 0o100644)]);
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let out_dir = tempfile::tempdir().unwrap();
        let objects = vec![FileObjectSource {
            key: "missing".to_string(),
            path: out_dir.path().join("missing.o"),
            optional: false,
        }];
        let result = runtime.block_on(entry.extract_objects(objects, runtime.handle()));
        assert!(result.is_err(), "missing required object should error");
    }

    #[test]
    fn test_uncompressed_extract_rejects_bad_key() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"data", 0o100644)]);
        let out_dir = tempfile::tempdir().unwrap();

        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());
        let required = vec![FileObjectSource {
            key: "../escape".to_string(),
            path: out_dir.path().join("escape"),
            optional: false,
        }];
        assert!(
            runtime
                .block_on(entry.extract_objects(required, runtime.handle()))
                .is_err()
        );

        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());
        let optional = vec![FileObjectSource {
            key: "../escape".to_string(),
            path: out_dir.path().join("escape"),
            optional: true,
        }];
        let stats = runtime
            .block_on(entry.extract_objects(optional, runtime.handle()))
            .unwrap();
        assert_eq!(stats, ExtractionStats::default());
    }

    #[test]
    fn test_uncompressed_extract_to_non_writable_dir() {
        let runtime = current_thread_runtime();
        let entry_dir = make_uncompressed_entry(&[("obj", b"restored-content", 0o100644)]);
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let out_dir = tempfile::tempdir().unwrap();
        let target = out_dir.path().join("out.o");
        std::fs::write(&target, b"stale").unwrap();
        let mut perm = out_dir.path().metadata().unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(out_dir.path(), perm.clone()).unwrap();

        let result = runtime.block_on(entry.extract_objects(
            vec![FileObjectSource {
                key: "obj".to_string(),
                path: target.clone(),
                optional: false,
            }],
            runtime.handle(),
        ));

        // Reset permissions so the tempdir can be cleaned up regardless of outcome.
        #[allow(
            clippy::permissions_set_readonly_false,
            reason = "directory is deleted immediately; no security implication"
        )]
        perm.set_readonly(false);
        std::fs::set_permissions(out_dir.path(), perm).unwrap();

        assert!(
            result.is_ok(),
            "extract to a non-writable dir should succeed"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"restored-content");
    }

    #[cfg(unix)]
    #[test]
    fn test_uncompressed_extract_restores_output_mode_from_manifest() {
        use std::os::unix::fs::PermissionsExt;
        let runtime = current_thread_runtime();
        // Manifest records the original 0755 output mode even though the cache object on disk is
        // written 0600 by the real write path; restore must reproduce 0755.
        let entry_dir = make_uncompressed_entry(&[("bin", b"#!/bin/sh\n", 0o100755)]);
        std::fs::set_permissions(
            entry_dir.path().join(OBJECTS_SUBDIR).join("bin"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let entry = UncompressedCacheEntry::new(entry_dir.path().to_path_buf());

        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("restored.sh");
        let objects = vec![FileObjectSource {
            key: "bin".to_string(),
            path: out_path.clone(),
            optional: false,
        }];
        runtime
            .block_on(entry.extract_objects(objects, runtime.handle()))
            .unwrap();
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "restored output reproduces the original mode");
    }
}
