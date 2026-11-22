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

#[cfg(test)]
mod test {
    use std::path::{Path, PathBuf};

    use crate::{
        PreprocessorCacheEntry,
        cache::{
            Cache, CacheMode, CacheStorage, CacheWrite, PreprocessorCacheStorage as _,
            disk::DiskCache,
            utils::{make_key_path, preprocessor_key_path},
        },
        config::PreprocessorCacheModeConfig,
    };

    #[test]
    fn test_disk_cache_type_name() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let disk = DiskCache::new(
            tempdir.path(),
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        );

        assert_eq!(disk.cache_type_name(), "disk");
    }

    const KEY: &str = "0123456789abcdef";

    fn disk_cache(root: &Path, runtime: &tokio::runtime::Runtime, rw_mode: CacheMode) -> DiskCache {
        DiskCache::new(
            root,
            1024 * 1024,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            rw_mode,
            vec![],
        )
    }

    pub(in crate::cache) enum Stored {
        CompileEntry,
        PreprocessorEntry,
    }

    /// A cache directory holding one entry under `KEY`, written by a read-write
    /// cache and then backdated, so that any refresh of its times by a later
    /// read is visible.
    pub struct ReadOnlyFixture {
        dir: tempfile::TempDir,
        runtime: tokio::runtime::Runtime,
        entry: PathBuf,
        old: filetime::FileTime,
    }

    pub fn read_only_fixture(stored: Stored) -> ReadOnlyFixture {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let writer = disk_cache(dir.path(), &runtime, CacheMode::ReadWrite);
        let entry = match stored {
            Stored::CompileEntry => {
                runtime
                    .block_on(writer.put(KEY, CacheWrite::new()))
                    .unwrap();
                dir.path().join(make_key_path(KEY))
            }
            Stored::PreprocessorEntry => {
                runtime
                    .block_on(
                        writer.put_preprocessor_cache_entry(KEY, PreprocessorCacheEntry::new()),
                    )
                    .unwrap();
                dir.path()
                    .join("preprocessor")
                    .join(preprocessor_key_path(KEY))
            }
        };
        let old = filetime::FileTime::from_unix_time(1_000_000_000, 0);
        filetime::set_file_times(&entry, old, old).unwrap();
        ReadOnlyFixture {
            dir,
            runtime,
            entry,
            old,
        }
    }

    impl ReadOnlyFixture {
        pub(in crate::cache) fn reader(&self) -> DiskCache {
            disk_cache(self.dir.path(), &self.runtime, CacheMode::ReadOnly)
        }

        pub(in crate::cache) fn assert_untouched(&self) {
            let metadata = std::fs::metadata(&self.entry).unwrap();
            assert_eq!(
                filetime::FileTime::from_last_modification_time(&metadata),
                self.old
            );
        }
    }

    #[test]
    fn test_read_only_get_leaves_entry_untouched() {
        let f = read_only_fixture(Stored::CompileEntry);
        let hit = f.runtime.block_on(f.reader().get(KEY)).unwrap();
        assert!(matches!(hit, Cache::Hit(_)));
        f.assert_untouched();
    }

    #[test]
    fn test_read_only_get_raw_leaves_entry_untouched() {
        let f = read_only_fixture(Stored::CompileEntry);
        let reader = f.reader();
        let data = f.runtime.block_on(reader.get_raw(KEY)).unwrap();
        assert_eq!(data.as_deref(), Some(&std::fs::read(&f.entry).unwrap()[..]));
        let (hit, _) = f.runtime.block_on(reader.get_with_raw(KEY)).unwrap();
        assert!(matches!(hit, Cache::Hit(_)));
        f.assert_untouched();
    }

    #[test]
    fn test_read_only_preprocessor_entry_leaves_entry_untouched() {
        let f = read_only_fixture(Stored::PreprocessorEntry);
        let found = f
            .runtime
            .block_on(f.reader().get_preprocessor_cache_entry(KEY))
            .unwrap();
        assert!(found.is_some());
        f.assert_untouched();
    }

    #[test]
    fn test_preprocessor_entry_written_by_another_cache_is_found() {
        // A second cache on the same directory loads its index from disk, as an sccache
        // server started later does.
        let f = read_only_fixture(Stored::PreprocessorEntry);
        let reader = disk_cache(f.dir.path(), &f.runtime, CacheMode::ReadWrite);
        let found = f
            .runtime
            .block_on(reader.get_preprocessor_cache_entry(KEY))
            .unwrap();
        assert!(found.is_some());
    }
}
