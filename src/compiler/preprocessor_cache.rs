// Copyright 2023 Mozilla Foundation
//
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

//! The preprocessor cache entry is a description of all information needed
//! to cache pre-processor output in C-family languages for a given input file.
//! The current implementation is very much inspired from the "manifest"
//! that `ccache` uses for its "direct mode", though the on-disk format is
//! different.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::Metadata,
    hash::Hash,
    io::Write,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use chrono::Datelike;
use serde::{Deserialize, Serialize};

use crate::{
    config::PreprocessorCacheModeConfig,
    util::{
        Digest, HashToDigest, MetadataCtimeExt, TimeMacroFinder, Timestamp, encode_path,
        strip_basedirs,
    },
};

use super::Language;
use super::c::hash_arguments;

/// The current format is 1 header byte for the version + bincode encoding
/// of the [`PreprocessorCacheEntry`] struct.
const FORMAT_VERSION: u8 = 1;
const MAX_PREPROCESSOR_CACHE_ENTRIES: usize = 100;
const MAX_PREPROCESSOR_CACHE_FILE_INFO_ENTRIES: usize = 10000;

#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct PreprocessorCacheEntry {
    /// A counter of the overall number of [`IncludeEntry`] in this
    /// preprocessor cache entry, as an optimization when checking
    /// we're not ballooning in size.
    number_of_entries: usize,
    /// The digest of a result is computed by hashing the output of the
    /// C preprocessor. Entries correspond to the included files during the
    /// preprocessing step.
    results: BTreeMap<String, Vec<IncludeEntry>>,
}

impl PreprocessorCacheEntry {
    pub fn new() -> Self {
        Default::default()
    }

    /// Tries to deserialize a preprocessor cache entry from `contents`
    pub fn read(contents: &[u8]) -> Result<Self, Error> {
        if contents.is_empty() {
            Ok(Self {
                number_of_entries: 0,
                results: Default::default(),
            })
        } else if contents[0] != FORMAT_VERSION {
            Err(Error::UnknownFormat(contents[0]))
        } else {
            Ok(bincode::deserialize(&contents[1..])?)
        }
    }

    /// Serialize the preprocessor cache entry to `buf`
    pub fn serialize_to(&self, mut buf: impl Write) -> Result<(), Error> {
        // Add the starting byte for version check since `bincode` doesn't
        // support it.
        buf.write_all(&[FORMAT_VERSION])?;
        bincode::serialize_into(buf, self)?;
        Ok(())
    }

    /// Insert the full compilation key and included files for a given source file.
    ///
    /// There can be more than one result at once for a source file if one
    /// or more of the include files has changed but not the source file.
    pub fn add_result(
        &mut self,
        compilation_time_start: SystemTime,
        result_key: &str,
        included_files: impl IntoIterator<Item = (String, PathBuf)>,
    ) {
        if self.results.len() > MAX_PREPROCESSOR_CACHE_ENTRIES {
            // Normally, there shouldn't be many result entries in the
            // preprocessor cache entry since new entries are added only if
            // an include file has changed but not the source file, and you
            // typically change source files more often than header files.
            // However, it's certainly possible to imagine cases where the
            // preprocessor cache entry will grow large (for instance,
            // a generated header file that changes for every build), and this
            // must be taken care of since processing an ever growing
            // preprocessor cache entry eventually will take too much time.
            // A good way of solving this would be to maintain the
            // result entries in LRU order and discarding the old ones.
            // An easy way is to throw away all entries when there are too many.
            // Let's do that for now.
            debug!(
                "Too many entries in preprocessor cache entry file ({}/{}), starting over",
                self.results.len(),
                MAX_PREPROCESSOR_CACHE_ENTRIES
            );
            self.results.clear();
            self.number_of_entries = 0;
        }
        let includes: Result<Vec<_>, std::io::Error> = included_files
            .into_iter()
            .map(|(digest, path)| {
                let meta = std::fs::symlink_metadata(&path)?;
                let mtime: Option<Timestamp> = meta.modified().ok().map(|t| t.into());
                let ctime = meta.ctime_or_creation().ok();

                let should_cache_time = match (mtime, ctime) {
                    (Some(mtime), Some(ctime)) => {
                        Timestamp::from(compilation_time_start) > mtime.max(ctime)
                    }
                    _ => false,
                };
                Ok(IncludeEntry {
                    path: path.into_os_string(),
                    digest,
                    file_size: meta.len(),
                    mtime: if should_cache_time { mtime } else { None },
                    ctime: if should_cache_time { ctime } else { None },
                })
            })
            .collect();
        match includes {
            Ok(includes) => {
                let new_number_of_entries = includes.len() + self.number_of_entries;
                if new_number_of_entries > MAX_PREPROCESSOR_CACHE_FILE_INFO_ENTRIES {
                    // Rarely, entries can grow large in pathological cases
                    // where many included files change, but the main file
                    // does not. This also puts an upper bound on the number
                    // of entries.
                    debug!(
                        "Too many include entries in preprocessor cache entry file ({}/{}), starting over",
                        new_number_of_entries, MAX_PREPROCESSOR_CACHE_FILE_INFO_ENTRIES
                    );
                    self.results.clear();
                }
                match self.results.entry(result_key.to_string()) {
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        self.number_of_entries -= entry.get().len();
                        self.number_of_entries += includes.len();
                        *entry.get_mut() = includes;
                    }
                    std::collections::btree_map::Entry::Vacant(vacant) => {
                        self.number_of_entries += includes.len();
                        vacant.insert(includes);
                    }
                }
                debug!("Added result key {result_key} to preprocessor cache entry");
            }
            Err(e) => {
                debug!("Could not add result key {result_key} to preprocessor cache entry: {e}");
            }
        }
    }

    /// Returns the digest of the first result whose expected included files
    /// are already on disk and have not changed.
    pub fn lookup_result_digest(
        &mut self,
        config: PreprocessorCacheModeConfig,
        updated: &mut bool,
    ) -> Option<String> {
        // Check newest result first since it's more likely to match.
        for (digest, includes) in self.results.iter_mut().rev() {
            let result_matches = Self::result_matches(digest, includes, config, updated);
            if result_matches {
                return Some(digest.clone());
            }
        }
        None
    }

    /// A result matches if all of its include files exist on disk and have not changed.
    fn result_matches(
        digest: &str,
        includes: &mut [IncludeEntry],
        config: PreprocessorCacheModeConfig,
        updated: &mut bool,
    ) -> bool {
        for include in includes {
            let path = Path::new(include.path.as_os_str());
            let meta = match std::fs::symlink_metadata(path) {
                Ok(meta) => {
                    if meta.len() != include.file_size {
                        return false;
                    }
                    meta
                }
                Err(e) => {
                    debug!(
                        "{} is in a preprocessor cache entry but can't be read ({})",
                        path.display(),
                        e
                    );
                    return false;
                }
            };

            if config.file_stat_matches {
                match (include.mtime, include.ctime) {
                    (Some(mtime), Some(ctime)) if config.use_ctime_for_stat => {
                        let mtime_matches = meta.modified().map(Into::into).ok() == Some(mtime);
                        let ctime_matches = meta.ctime_or_creation().ok() == Some(ctime);
                        if mtime_matches && ctime_matches {
                            trace!("mtime+ctime hit for {}", path.display());
                            continue;
                        } else {
                            trace!("mtime+ctime miss for {}", path.display());
                        }
                    }
                    (Some(mtime), None) => {
                        let mtime_matches = meta.modified().map(Into::into).ok() == Some(mtime);
                        if mtime_matches {
                            trace!("mtime hit for {}", path.display());
                            continue;
                        } else {
                            trace!("mtime miss for {}", path.display());
                        }
                    }
                    _ => { /* Nothing was recorded, fall back to contents comparison */ }
                }
            }

            let (new_digest, finder) = match file_digest(path, Some(&meta)) {
                Ok(digest) => digest,
                Err(e) => {
                    debug!(
                        "{} is in a preprocessor cache entry but can't be read ({:#})",
                        path.display(),
                        e
                    );
                    return false;
                }
            };

            if config.ignore_time_macros {
                if include.digest != new_digest {
                    return false;
                }
            } else {
                if !finder.found_time_macros() && include.digest != new_digest {
                    return false;
                }
                if finder.found_time() {
                    // We don't know for sure that the program actually uses the __TIME__ macro,
                    // but we have to assume it anyway and hash the time stamp. However, that's
                    // not very useful since the chance that we get a cache hit later the same
                    // second should be quite slim... So, just signal back to the caller that
                    // __TIME__ has been found so that the preprocessor cache mode can be disabled.
                    debug!("Found __TIME__ in {}", path.display());
                    return false;
                }

                // __DATE__ or __TIMESTAMP__ found. We now make sure that the digest changes
                // if the (potential) expansion of those macros changes by computing a new
                // digest comprising the file digest and time information that represents the
                // macro expansions.
                let mut new_digest = Digest::new();
                new_digest.update(digest.as_bytes());

                if finder.found_date() {
                    debug!("found __DATE__ in {}", path.display());
                    new_digest.delimiter(b"date");
                    let date = chrono::Local::now().date_naive();
                    new_digest.update(&date.year().to_le_bytes());
                    new_digest.update(&date.month().to_le_bytes());
                    new_digest.update(&date.day().to_le_bytes());

                    // If the compiler has support for it, the expansion of __DATE__ will change
                    // according to the value of SOURCE_DATE_EPOCH. Note: We have to hash both
                    // SOURCE_DATE_EPOCH and the current date since we can't be sure that the
                    // compiler honors SOURCE_DATE_EPOCH.
                    if let Ok(source_date_epoch) = std::env::var("SOURCE_DATE_EPOCH") {
                        new_digest.update(source_date_epoch.as_bytes());
                    }
                }

                if finder.found_timestamp() {
                    debug!("found __TIMESTAMP__ in {}", path.display());
                    let meta = match std::fs::symlink_metadata(path) {
                        Ok(meta) => meta,
                        Err(e) => {
                            debug!(
                                "{} is in a preprocessor cache entry but can't be read ({})",
                                path.display(),
                                e
                            );
                            return false;
                        }
                    };
                    let mtime = match meta.modified() {
                        Ok(mtime) => mtime,
                        Err(_) => {
                            debug!(
                                "Couldn't get mtime of {} which contains __TIMESTAMP__",
                                path.display()
                            );
                            return false;
                        }
                    };
                    let mtime: chrono::DateTime<chrono::Local> = chrono::DateTime::from(mtime);
                    new_digest.delimiter(b"timestamp");
                    new_digest.update(&mtime.naive_local().and_utc().timestamp().to_le_bytes());
                    include.digest = new_digest.finish();
                    // Signal that the preprocessor cache entry has been updated and needs to be
                    // written to disk.
                    *updated = true;
                }
            }
        }
        true
    }
}

/// Environment variables that are factored into the preprocessor cache entry cached key.
static CACHED_ENV_VARS: LazyLock<HashSet<&'static OsStr>> = LazyLock::new(|| {
    [
        // SCCACHE_C_CUSTOM_CACHE_BUSTER has no particular meaning behind it,
        // serving as a way for the user to factor custom data into the hash.
        // One can set it to different values for different invocations
        // to prevent cache reuse between them.
        "SCCACHE_C_CUSTOM_CACHE_BUSTER",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "OBJCPLUS_INCLUDE_PATH",
    ]
    .iter()
    .map(OsStr::new)
    .collect()
});

/// Compute the hash key of compiler preprocessing `input` with `args`.
#[allow(clippy::too_many_arguments)]
pub fn preprocessor_cache_entry_hash_key(
    compiler_digest: &str,
    language: Language,
    arguments: &[OsString],
    extra_hashes: &[String],
    assembler_digest: Option<&str>,
    env_vars: &[(OsString, OsString)],
    input_file: &Path,
    plusplus: bool,
    multiarch: bool,
    config: PreprocessorCacheModeConfig,
    basedirs: &[Vec<u8>],
) -> anyhow::Result<Option<String>> {
    // If you change any of the inputs to the hash, you should change `FORMAT_VERSION`.
    let mut m = Digest::new();
    m.update(compiler_digest.as_bytes());
    // clang and clang++ have different behavior despite being byte-for-byte identical binaries, so
    // we have to incorporate that into the hash as well.
    m.update(&[plusplus as u8]);
    m.update(&[FORMAT_VERSION]);
    m.update(language.as_str().as_bytes());
    // Multi-arch compilations used to be preprocessed in a single pass that
    // missed the code only one architecture sees: don't reuse those entries.
    if multiarch {
        m.update(b"multiarch-per-pass");
    }
    hash_arguments(&mut m, arguments, basedirs);
    for hash in extra_hashes {
        m.update(hash.as_bytes());
    }
    // A hit on a preprocessor cache entry hands back the object cache key that
    // was stored in it, so everything the object key is made of has to be here
    // too or the assembler would be forgotten on that path.
    if let Some(assembler_digest) = assembler_digest {
        m.update(assembler_digest.as_bytes());
    }

    for (var, val) in env_vars.iter() {
        if CACHED_ENV_VARS.contains(var.as_os_str()) {
            var.hash(&mut HashToDigest { digest: &mut m });
            m.update(&b"="[..]);
            val.hash(&mut HashToDigest { digest: &mut m });
        }
    }

    // Hash the input file otherwise:
    // - a/r.h exists.
    // - a/x.c has #include "r.h".
    // - b/x.c is identical to a/x.c.
    // - Compiling a/x.c records a/r.h in the preprocessor cache entry.
    // - Compiling b/x.c results in a false cache hit since a/x.c and b/x.c
    // share preprocessor cache entries and a/r.h exists.
    let mut buf = vec![];
    encode_path(&mut buf, input_file)?;

    // Strip basedirs from the input file path if configured
    let buf_to_hash = strip_basedirs(&buf, basedirs);
    m.update(&buf_to_hash);
    let (digest, finder) = file_digest(input_file, None)
        .with_context(|| format!("while hashing the input file '{}'", input_file.display()))?;
    if !config.ignore_time_macros && finder.found_time() {
        // Disable preprocessor cache mode
        debug!("Found __TIME__ in {}", input_file.display());
        return Ok(None);
    }
    m.update(digest.as_bytes());
    Ok(Some(m.finish()))
}

/// Digests of the files hashed for the preprocessor cache, kept for the life of
/// the process. The server is long-lived, and without this every direct-mode
/// cache hit re-reads and re-hashes the source file and every header it
/// includes, which is most of the server's work on such a hit.
///
/// Unix only: on Windows there is no inode number, and the creation time that
/// stands in for the ctime does not change when a file is rewritten.
static FILE_DIGESTS: LazyLock<Mutex<HashMap<PathBuf, CachedFileDigest>>> =
    LazyLock::new(Default::default);

/// Bound on the files remembered in [`FILE_DIGESTS`]; it is cleared when reached.
const MAX_CACHED_FILE_DIGESTS: usize = 100_000;

/// How old a file's mtime and ctime must be for its digest to be remembered.
/// File timestamps come from a coarse clock, so a file rewritten right after
/// being hashed can keep the timestamps it was hashed with.
const MIN_CACHED_FILE_AGE: Duration = Duration::from_secs(2);

/// What has to be unchanged for a remembered digest to be reused.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStat {
    len: u64,
    mtime: Option<Timestamp>,
    ctime: Option<Timestamp>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileStat {
    fn new(meta: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        FileStat {
            len: meta.len(),
            mtime: meta.modified().ok().map(Into::into),
            ctime: meta.ctime_or_creation().ok(),
            #[cfg(unix)]
            dev: meta.dev(),
            #[cfg(unix)]
            ino: meta.ino(),
        }
    }

    /// Whether the file was last changed long enough before `now` for its
    /// timestamps to tell any later change apart.
    fn is_settled(&self, now: SystemTime) -> bool {
        if !cfg!(unix) {
            return false;
        }
        let Some(limit) = now.checked_sub(MIN_CACHED_FILE_AGE) else {
            return false;
        };
        matches!((self.mtime, self.ctime), (Some(mtime), Some(ctime)) if mtime.max(ctime) < limit.into())
    }
}

#[derive(Debug)]
struct CachedFileDigest {
    stat: FileStat,
    digest: String,
    found_date: bool,
    found_time: bool,
    found_timestamp: bool,
}

/// Digest of the contents of `path`, and the time macros found in it.
/// `lstat` is the caller's `symlink_metadata` of `path`, if it has one: unless
/// `path` is a symlink, it saves stat-ing the file again.
fn file_digest(path: &Path, lstat: Option<&Metadata>) -> anyhow::Result<(String, TimeMacroFinder)> {
    file_digest_at(path, lstat, SystemTime::now())
}

/// The digest remembered for `path`, if the file has not changed since.
fn remembered_file_digest(
    path: &Path,
    lstat: Option<&Metadata>,
) -> Option<(String, TimeMacroFinder)> {
    if !cfg!(unix) {
        return None;
    }
    // A stat of the path is enough to reuse a digest: it describes the file as
    // it is now, which is what the digest has to match.
    let target_meta;
    let meta = match lstat {
        Some(meta) if !meta.file_type().is_symlink() => meta,
        _ => {
            target_meta = std::fs::metadata(path).ok()?;
            &target_meta
        }
    };
    let stat = FileStat::new(meta);
    let digests = FILE_DIGESTS.lock().unwrap_or_else(|e| e.into_inner());
    let cached = digests.get(path).filter(|cached| cached.stat == stat)?;
    let finder =
        TimeMacroFinder::with_found(cached.found_date, cached.found_time, cached.found_timestamp);
    Some((cached.digest.clone(), finder))
}

/// [`file_digest`], with `now` deciding whether the file is old enough to be
/// remembered.
fn file_digest_at(
    path: &Path,
    lstat: Option<&Metadata>,
    now: SystemTime,
) -> anyhow::Result<(String, TimeMacroFinder)> {
    if let Some(cached) = remembered_file_digest(path, lstat) {
        return Ok(cached);
    }

    let file = std::fs::File::open(path)?;
    // From the open file rather than the path, so that it describes what is read.
    let stat = FileStat::new(&file.metadata()?);
    let (digest, finder) = Digest::reader_sync_time_macros(&file)?;
    // Not remembered if it changed while being read.
    if stat.is_settled(now) && FileStat::new(&file.metadata()?) == stat {
        let mut digests = FILE_DIGESTS.lock().unwrap_or_else(|e| e.into_inner());
        if digests.len() >= MAX_CACHED_FILE_DIGESTS {
            digests.clear();
        }
        digests.insert(
            path.to_owned(),
            CachedFileDigest {
                stat,
                digest: digest.clone(),
                found_date: finder.found_date(),
                found_time: finder.found_time(),
                found_timestamp: finder.found_timestamp(),
            },
        );
    }
    Ok((digest, finder))
}

/// Corresponds to a cached include file used in the pre-processor stage
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct IncludeEntry {
    /// Its absolute path
    #[serde(deserialize_with = "deserialize_os_string")]
    path: OsString,
    /// The hash of its contents
    digest: String,
    /// Its file size, in bytes
    file_size: u64,
    /// Its modification time, `None` if not recorded.
    mtime: Option<Timestamp>,
    /// Its status change time, `None` if not recorded.
    ctime: Option<Timestamp>,
}

/// Reads an `OsString` in serde's own encoding of it, an enum with a `Unix`
/// variant holding bytes and a `Windows` one holding UTF-16 code units. serde
/// decodes those bytes one at a time, which made up a noticeable part of
/// reading an entry with hundreds of includes on each direct-mode lookup;
/// bincode encodes a byte buffer exactly like a sequence of bytes, so read
/// them as one buffer instead.
fn deserialize_os_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<OsString, D::Error> {
    // The other platform's variant is only read to be rejected.
    #[allow(dead_code)]
    #[derive(Deserialize)]
    enum OsStringRepr {
        Unix(Bytes),
        Windows(Vec<u16>),
    }

    match OsStringRepr::deserialize(deserializer)? {
        #[cfg(unix)]
        OsStringRepr::Unix(Bytes(bytes)) => Ok(std::os::unix::ffi::OsStringExt::from_vec(bytes)),
        #[cfg(windows)]
        OsStringRepr::Windows(wide) => Ok(std::os::windows::ffi::OsStringExt::from_wide(&wide)),
        _ => Err(serde::de::Error::custom(
            "cannot deserialize an OsString from another platform",
        )),
    }
}

/// A `Vec<u8>` read as a byte buffer rather than as a sequence of bytes.
// Only `Unix` paths are made of bytes; elsewhere they are only read to be rejected.
#[cfg_attr(not(unix), allow(dead_code))]
struct Bytes(Vec<u8>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Bytes;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Bytes, A::Error> {
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                Ok(Bytes(bytes))
            }
        }

        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Deserialization(bincode::Error),
    UnknownFormat(u8),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Self::Deserialization(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => e.fmt(f),
            Error::Deserialization(e) => e.fmt(f),
            Error::UnknownFormat(format) => f.write_fmt(format_args!(
                "Unknown preprocessor cache entry format {:x}",
                format
            )),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod test {
    use crate::util::{HASH_BUFFER_SIZE, MAX_TIME_MACRO_HAYSTACK_LEN};

    use super::*;

    #[test]
    fn test_find_time_macros_empty_file() {
        let buf: Vec<u8> = vec![];
        let hash = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().0;
        assert_eq!(hash, Digest::new().finish());
    }

    #[test]
    fn test_find_time_macros_small_file_no_match() {
        let buf = b"This is a small file, which doesn't contain any time macros.";
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(!finder.found_time_macros());
    }

    #[test]
    fn test_find_time_macros_small_file_match() {
        let buf = b"__TIME__";
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(!finder.found_date());
        let buf = b"__DATE__";
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(!finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(finder.found_date());
        let buf = b"__TIMESTAMP__";
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(!finder.found_time());
        assert!(finder.found_timestamp());
        assert!(!finder.found_date());
    }

    #[test]
    fn test_find_time_macros_small_file_match_multiple() {
        let buf = b"__TIMESTAMP____DATE____TIME__";
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(finder.found_time());
        assert!(finder.found_timestamp());
        assert!(finder.found_date());
    }

    #[test]
    fn test_find_time_macros_large_file_no_match() {
        let buf = vec![0; HASH_BUFFER_SIZE * 2];
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(!finder.found_time_macros());
        assert!(!finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(!finder.found_date());
    }

    #[test]
    fn test_find_time_macros_large_file_match_no_overlap() {
        let mut buf = vec![0; HASH_BUFFER_SIZE * 2];
        buf.extend(b"__TIMESTAMP____DATE____TIME__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(finder.found_time());
        assert!(finder.found_timestamp());
        assert!(finder.found_date());
    }
    #[test]
    fn test_find_time_macros_large_file_match_overlap() {
        let mut buf = vec![0; HASH_BUFFER_SIZE * 2];
        // Make the pattern overlap two buffer chunks to make sure we account for this
        let start = HASH_BUFFER_SIZE - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__TIMESTAMP__".len()].copy_from_slice(b"__TIMESTAMP__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(!finder.found_time());
        assert!(finder.found_timestamp());
        assert!(!finder.found_date());

        let mut buf = vec![0; HASH_BUFFER_SIZE * 2];
        // Make the pattern overlap two buffer chunks to make sure we account for this
        let start = HASH_BUFFER_SIZE - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__TIME__".len()].copy_from_slice(b"__TIME__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(!finder.found_date());

        let mut buf = vec![0; HASH_BUFFER_SIZE * 2];
        // Make the pattern overlap two buffer chunks to make sure we account for this
        let start = HASH_BUFFER_SIZE - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__DATE__".len()].copy_from_slice(b"__DATE__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(!finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(finder.found_date());
    }

    #[test]
    fn test_find_time_macros_large_file_match_overlap_multiple_pages() {
        let mut buf = vec![0; HASH_BUFFER_SIZE * 3];
        // Make the patterns overlap buffer chunks twice to make sure we account for this
        let start = HASH_BUFFER_SIZE - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__TIME__".len()].copy_from_slice(b"__TIME__");
        let start = HASH_BUFFER_SIZE * 2 - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__DATE__".len()].copy_from_slice(b"__DATE__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(finder.found_date());
    }

    #[test]
    fn test_find_time_macros_large_file_match_overlap_multiple_pages_tiny() {
        let mut buf = vec![0; HASH_BUFFER_SIZE * 3];
        // Make the patterns overlap buffer chunks twice to make sure we account for this
        let start = HASH_BUFFER_SIZE - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__TIME__".len()].copy_from_slice(b"__TIME__");
        let start = HASH_BUFFER_SIZE * 2 - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__DATE__".len()].copy_from_slice(b"__DATE__");
        // Test overlap with the last chunk being less than the haystack
        buf.extend([0; MAX_TIME_MACRO_HAYSTACK_LEN / 2 + 1]);
        let start = HASH_BUFFER_SIZE * 3 - MAX_TIME_MACRO_HAYSTACK_LEN / 2;
        buf[start..][..b"__TIMESTAMP__".len()].copy_from_slice(b"__TIMESTAMP__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(finder.found_time_macros());
        assert!(finder.found_time());
        assert!(finder.found_timestamp());
        assert!(finder.found_date());
    }

    #[test]
    fn test_find_time_macros_ghost_pattern() {
        // Check the (unlikely) case of a pattern being spread between the
        // start of a chunk and its end.
        let mut buf = vec![0; HASH_BUFFER_SIZE * 3];
        buf[HASH_BUFFER_SIZE..HASH_BUFFER_SIZE + b"__TI".len()].copy_from_slice(b"__TI");
        buf[HASH_BUFFER_SIZE * 2 - "ME__".len()..HASH_BUFFER_SIZE * 2].copy_from_slice(b"ME__");
        let finder = Digest::reader_sync_time_macros(buf.as_slice()).unwrap().1;
        assert!(!finder.found_time_macros());
        assert!(!finder.found_time());
        assert!(!finder.found_timestamp());
        assert!(!finder.found_date());
    }

    #[test]
    fn test_preprocessor_cache_result_checks_all_includes_when_ignoring_time_macros() {
        use std::fs;

        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let first_path = dir.path().join("first.h");
        let second_path = dir.path().join("second.h");
        let first_contents = b"first\n";
        let second_contents = b"old2\n";

        fs::write(&first_path, first_contents).unwrap();
        fs::write(&second_path, second_contents).unwrap();

        let mut includes = vec![
            IncludeEntry {
                path: first_path.into_os_string(),
                digest: Digest::reader_sync(first_contents.as_slice()).unwrap(),
                file_size: first_contents.len() as u64,
                mtime: None,
                ctime: None,
            },
            IncludeEntry {
                path: second_path.clone().into_os_string(),
                digest: Digest::reader_sync(second_contents.as_slice()).unwrap(),
                file_size: second_contents.len() as u64,
                mtime: None,
                ctime: None,
            },
        ];

        fs::write(second_path, b"new2\n").unwrap();

        let config = PreprocessorCacheModeConfig {
            ignore_time_macros: true,
            ..PreprocessorCacheModeConfig::activated()
        };
        let mut updated = false;

        assert!(!PreprocessorCacheEntry::result_matches(
            "result-digest",
            &mut includes,
            config,
            &mut updated
        ));
    }

    #[test]
    fn test_preprocessor_cache_entry_hash_key_basedirs() {
        #[cfg(target_os = "windows")]
        use crate::util::normalize_win_path;
        use std::fs;
        use tempfile::TempDir;

        // Create two different base directories
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let dirs = [&dir1, &dir2]
            .iter()
            .map(|dir| {
                let bytes = dir.path().to_string_lossy().into_owned().into_bytes();
                #[cfg(target_os = "windows")]
                return normalize_win_path(&bytes);
                #[cfg(not(target_os = "windows"))]
                bytes
            })
            .collect::<Vec<_>>();

        // Create identical files with the same relative path in each directory
        let file1_path = dir1.path().join("test.c");
        let file2_path = dir2.path().join("test.c");

        let content = b"int main() { return 0; }";
        fs::write(&file1_path, content).unwrap();
        fs::write(&file2_path, content).unwrap();

        let config = PreprocessorCacheModeConfig::activated();

        // Test 1: With basedirs, hashes should be the same
        let hash1_with_basedirs = preprocessor_cache_entry_hash_key(
            "test_digest",
            Language::C,
            &[],
            &[],
            None,
            &[],
            &file1_path,
            false,
            false,
            config,
            &dirs,
        )
        .unwrap()
        .unwrap();

        let hash2_with_basedirs = preprocessor_cache_entry_hash_key(
            "test_digest",
            Language::C,
            &[],
            &[],
            None,
            &[],
            &file2_path,
            false,
            false,
            config,
            &dirs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            hash1_with_basedirs, hash2_with_basedirs,
            "Hashes should be equal when using basedirs with identical files in different directories"
        );

        // Test 2: With basedir1 for first, and basedir2 for second, hashes should be the same
        let hash1_with_basedirs = preprocessor_cache_entry_hash_key(
            "test_digest",
            Language::C,
            &[],
            &[],
            None,
            &[],
            &file1_path,
            false,
            false,
            config,
            &dirs[..1],
        )
        .unwrap()
        .unwrap();

        let hash2_with_basedirs = preprocessor_cache_entry_hash_key(
            "test_digest",
            Language::C,
            &[],
            &[],
            None,
            &[],
            &file2_path,
            false,
            false,
            config,
            &dirs[1..],
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            hash1_with_basedirs, hash2_with_basedirs,
            "Hashes should be equal when using basedirs with identical files in different directories"
        );

        // Test 3: Without basedirs, hashes should be different
        let hash1_no_basedirs = preprocessor_cache_entry_hash_key(
            "test_digest",
            Language::C,
            &[],
            &[],
            None,
            &[],
            &file1_path,
            false,
            false,
            config,
            &[],
        )
        .unwrap()
        .unwrap();

        let hash2_no_basedirs = preprocessor_cache_entry_hash_key(
            "test_digest",
            Language::C,
            &[],
            &[],
            None,
            &[],
            &file2_path,
            false,
            false,
            config,
            &[],
        )
        .unwrap()
        .unwrap();

        assert_ne!(
            hash1_no_basedirs, hash2_no_basedirs,
            "Hashes should be different without basedirs for files in different directories"
        );
    }

    #[test]
    fn test_preprocessor_cache_entry_hash_key_multiarch() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.c");
        std::fs::write(&file, b"int main() { return 0; }").unwrap();
        let basedir = dir.path().to_string_lossy().into_owned().into_bytes();
        #[cfg(target_os = "windows")]
        let basedir = crate::util::normalize_win_path(&basedir);
        let key = |arguments: &[&str], multiarch: bool| {
            let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
            preprocessor_cache_entry_hash_key(
                "test_digest",
                Language::C,
                &arguments,
                &[],
                None,
                &[],
                &file,
                false,
                multiarch,
                PreprocessorCacheModeConfig::activated(),
                std::slice::from_ref(&basedir),
            )
            .unwrap()
            .unwrap()
        };

        let fat = ["-arch", "x86_64", "-arch", "arm64"];
        assert_ne!(key(&fat, true), key(&fat, false));
    }

    fn is_digest_cached(path: &Path) -> bool {
        FILE_DIGESTS.lock().unwrap().contains_key(path)
    }

    #[test]
    #[cfg(unix)]
    fn test_file_digest_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("header.h");
        std::fs::write(&path, b"#define A __DATE__\n").unwrap();
        // Far enough ahead for the file to count as settled.
        let later = SystemTime::now() + Duration::from_secs(60);

        let (digest, finder) = file_digest_at(&path, None, later).unwrap();
        assert!(is_digest_cached(&path));
        assert!(finder.found_date() && !finder.found_time());

        let (cached_digest, cached_finder) = file_digest_at(&path, None, later).unwrap();
        assert_eq!(digest, cached_digest);
        assert!(cached_finder.found_date() && !cached_finder.found_time());

        // Same size, different contents, mtime put back: the ctime still
        // changes. Wait for the coarse clock file timestamps come from to tick.
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&path, b"#define B __TIME__\n").unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(mtime)).unwrap();

        let (new_digest, new_finder) = file_digest_at(&path, None, later).unwrap();
        assert_ne!(digest, new_digest);
        assert_eq!(
            new_digest,
            Digest::reader_sync(&b"#define B __TIME__\n"[..]).unwrap()
        );
        assert!(new_finder.found_time() && !new_finder.found_date());
    }

    #[test]
    fn test_file_digest_recent_file_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("header.h");
        std::fs::write(&path, b"int x;\n").unwrap();

        let (digest, _) = file_digest(&path, None).unwrap();
        assert_eq!(digest, Digest::reader_sync(&b"int x;\n"[..]).unwrap());
        assert!(!is_digest_cached(&path));
    }

    #[test]
    #[cfg(unix)]
    fn test_file_digest_cache_through_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.h");
        let link = dir.path().join("link.h");
        std::fs::write(&target, b"int a;\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let later = SystemTime::now() + Duration::from_secs(60);

        let lstat = std::fs::symlink_metadata(&link).unwrap();
        let (digest, _) = file_digest_at(&link, Some(&lstat), later).unwrap();
        assert!(is_digest_cached(&link));

        // The link itself is untouched, so its lstat is the same: only the
        // target's stat can tell that the contents changed.
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&target, b"int b;\n").unwrap();
        let lstat = std::fs::symlink_metadata(&link).unwrap();
        let (new_digest, _) = file_digest_at(&link, Some(&lstat), later).unwrap();
        assert_ne!(digest, new_digest);
        assert_eq!(new_digest, Digest::reader_sync(&b"int b;\n"[..]).unwrap());
    }

    #[test]
    fn test_deserialize_os_string_matches_serde_encoding() {
        #[derive(Deserialize)]
        struct Path(#[serde(deserialize_with = "deserialize_os_string")] OsString);

        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut paths = vec![
            OsString::new(),
            OsString::from("/usr/include/stdio.h"),
            OsString::from("/home/\u{e9}t\u{e9}/header with spaces.h"),
        ];
        #[cfg(unix)]
        paths.push(std::os::unix::ffi::OsStringExt::from_vec(vec![
            b'/', 0xff, 0xfe, b'x',
        ]));
        for path in paths {
            let encoded = bincode::serialize(&path).unwrap();
            let decoded: Path = bincode::deserialize(&encoded).unwrap();
            assert_eq!(decoded.0, path);
        }
    }

    #[test]
    fn test_preprocessor_cache_entry_roundtrip() {
        let mut entry = PreprocessorCacheEntry::new();
        let includes = (0..300)
            .map(|i| IncludeEntry {
                path: OsString::from(format!("/usr/include/c++/14/header{i}.h")),
                digest: format!("digest{i}"),
                file_size: i,
                mtime: Some(Timestamp::from(SystemTime::UNIX_EPOCH)),
                ctime: None,
            })
            .collect();
        entry.number_of_entries = 300;
        entry.results.insert("result".to_owned(), includes);

        let mut buf = vec![];
        entry.serialize_to(&mut buf).unwrap();
        assert_eq!(PreprocessorCacheEntry::read(&buf).unwrap(), entry);
    }
}
