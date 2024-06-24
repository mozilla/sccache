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
    collections::{BTreeMap, HashSet},
    ffi::{OsStr, OsString},
    hash::Hash,
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::Context;
use chrono::Datelike;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::{
    cache::PreprocessorCacheModeConfig,
    util::{encode_path, Digest, HashToDigest, MetadataCtimeExt, Timestamp},
};

use super::Language;

/// The current format is 1 header byte for the version + bincode encoding
/// of the [`PreprocessorCacheEntry`] struct.
const FORMAT_VERSION: u8 = 0;
const MAX_PREPROCESSOR_CACHE_ENTRIES: usize = 100;
const MAX_PREPROCESSOR_CACHE_FILE_INFO_ENTRIES: usize = 10000;

#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
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
                };
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
                return Some(digest.to_string());
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
                        let ctime_matches =
                            meta.ctime_or_creation().map(Into::into).ok() == Some(ctime);
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

            let file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(e) => {
                    debug!(
                        "{} is in a preprocessor cache entry but can't be opened ({})",
                        path.display(),
                        e
                    );
                    return false;
                }
            };

            if config.ignore_time_macros {
                match Digest::reader_sync(file) {
                    Ok(new_digest) => return include.digest == new_digest,
                    Err(e) => {
                        debug!(
                            "{} is in a preprocessor cache entry but can't be read ({})",
                            path.display(),
                            e
                        );
                        return false;
                    }
                }
            } else {
                let (new_digest, finder): (String, _) = match Digest::reader_sync_time_macros(file)
                {
                    Ok((new_digest, finder)) => (new_digest, finder),
                    Err(e) => {
                        debug!(
                            "{} is in a preprocessor cache entry but can't be read ({})",
                            path.display(),
                            e
                        );
                        return false;
                    }
                };
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
                        new_digest.update(source_date_epoch.as_bytes())
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
static CACHED_ENV_VARS: Lazy<HashSet<&'static OsStr>> = Lazy::new(|| {
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
    env_vars: &[(OsString, OsString)],
    input_file: &Path,
    plusplus: bool,
    config: PreprocessorCacheModeConfig,
) -> anyhow::Result<Option<String>> {
    // If you change any of the inputs to the hash, you should change `FORMAT_VERSION`.
    let mut m = Digest::new();
    m.update(compiler_digest.as_bytes());
    // clang and clang++ have different behavior despite being byte-for-byte identical binaries, so
    // we have to incorporate that into the hash as well.
    m.update(&[plusplus as u8]);
    m.update(&[FORMAT_VERSION]);
    m.update(language.as_str().as_bytes());
    for arg in arguments {
        arg.hash(&mut HashToDigest { digest: &mut m });
    }
    for hash in extra_hashes {
        m.update(hash.as_bytes());
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
    m.update(&buf);
    let reader = std::fs::File::open(input_file)
        .with_context(|| format!("while hashing the input file '{}'", input_file.display()))?;

    let digest = if config.ignore_time_macros {
        Digest::reader_sync(reader)?
    } else {
        let (digest, finder) = Digest::reader_sync_time_macros(reader)?;
        if finder.found_time() {
            // Disable preprocessor cache mode
            debug!("Found __TIME__ in {}", input_file.display());
            return Ok(None);
        }
        digest
    };
    m.update(digest.as_bytes());
    Ok(Some(m.finish()))
}

/// Corresponds to a cached include file used in the pre-processor stage
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct IncludeEntry {
    /// Its absolute path
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
}
