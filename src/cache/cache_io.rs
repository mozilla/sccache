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
use fs_err as fs;
use std::fmt;
use std::io::{Cursor, Read, Seek, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

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
    /// Result was found in cache.
    Hit(CacheRead),
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
    ) -> Result<()>
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
                let dir = match path.parent() {
                    Some(d) => d,
                    None => bail!("Output file without a parent directory!"),
                };
                // Write the cache entry to a tempfile and then atomically
                // move it to its final location so that other rustc invocations
                // happening in parallel don't see a partially-written file.
                let mut tmp = NamedTempFile::new_in(dir)?;
                match (self.get_object(&key, &mut tmp), optional) {
                    (Ok(mode), _) => {
                        tmp.persist(&path)?;
                        if let Some(mode) = mode {
                            set_file_mode(&path, mode)?;
                        }
                    }
                    (Err(e), false) => return Err(e),
                    // skip if no object found and it's optional
                    (Err(_), true) => continue,
                }
            }
            Ok(())
        })
        .await?
    }
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
