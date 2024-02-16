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

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::cache::{Cache, CacheMode, CacheWrite, Storage};
use crate::compiler::PreprocessorCacheEntry;
use crate::errors::*;

use super::PreprocessorCacheModeConfig;

pub struct ReadOnlyStorage(pub Arc<dyn Storage>);

#[async_trait]
impl Storage for ReadOnlyStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        self.0.get(key).await
    }

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
        Err(anyhow!("Cannot write to read-only storage"))
    }

    /// Check the cache capability.
    ///
    /// The ReadOnlyStorage cache is always read-only.
    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadOnly)
    }

    /// Get the storage location.
    fn location(&self) -> String {
        self.0.location()
    }

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>> {
        self.0.current_size().await
    }

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>> {
        self.0.max_size().await
    }

    /// Return the config for preprocessor cache mode if applicable
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.0.preprocessor_cache_mode_config()
    }

    /// Return the preprocessor cache entry for a given preprocessor key,
    /// if it exists.
    /// Only applicable when using preprocessor cache mode.
    fn get_preprocessor_cache_entry(
        &self,
        _key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        self.0.get_preprocessor_cache_entry(_key)
    }

    /// Insert a preprocessor cache entry at the given preprocessor key,
    /// overwriting the entry if it exists.
    /// Only applicable when using preprocessor cache mode.
    fn put_preprocessor_cache_entry(
        &self,
        _key: &str,
        _preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        Err(anyhow!("Cannot write to read-only storage"))
    }
}

#[cfg(test)]
mod test {
    use futures::FutureExt;

    use super::*;
    use crate::test::mock_storage::MockStorage;

    #[test]
    fn readonly_storage_is_readonly() {
        let storage = ReadOnlyStorage(Arc::new(MockStorage::new(None, false)));
        assert_eq!(
            storage.check().now_or_never().unwrap().unwrap(),
            CacheMode::ReadOnly
        );
    }

    #[test]
    fn readonly_storage_forwards_preprocessor_cache_mode_config() {
        let storage_no_preprocessor_cache =
            ReadOnlyStorage(Arc::new(MockStorage::new(None, false)));
        assert!(
            !storage_no_preprocessor_cache
                .preprocessor_cache_mode_config()
                .use_preprocessor_cache_mode
        );

        let storage_with_preprocessor_cache =
            ReadOnlyStorage(Arc::new(MockStorage::new(None, true)));
        assert!(
            storage_with_preprocessor_cache
                .preprocessor_cache_mode_config()
                .use_preprocessor_cache_mode
        );
    }

    #[test]
    fn readonly_storage_put_err() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let storage = ReadOnlyStorage(Arc::new(MockStorage::new(None, true)));
        runtime.block_on(async move {
            assert_eq!(
                storage
                    .put("test1", CacheWrite::default())
                    .await
                    .unwrap_err()
                    .to_string(),
                "Cannot write to read-only storage"
            );
            assert_eq!(
                storage
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .unwrap_err()
                    .to_string(),
                "Cannot write to read-only storage"
            );
        });
    }
}
