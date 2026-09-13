// Copyright 2026 Mozilla Foundation
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

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::cache::multilevel::MultiLevelStats;
use crate::cache::{Cache, CacheMode, CacheWrite, GetPathResult, Storage};
use crate::compiler::PreprocessorCacheEntry;
use crate::config::PreprocessorCacheModeConfig;
use crate::errors::*;

struct BasedirsStorage {
    inner: Arc<dyn Storage>,
    basedirs: Vec<Vec<u8>>,
}

pub(crate) fn with_basedirs(storage: Arc<dyn Storage>, basedirs: Vec<Vec<u8>>) -> Arc<dyn Storage> {
    if storage.basedirs() == basedirs {
        storage
    } else {
        Arc::new(BasedirsStorage {
            inner: storage,
            basedirs,
        })
    }
}

#[async_trait]
impl Storage for BasedirsStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        self.inner.get(key).await
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        self.inner.put(key, entry).await
    }

    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        self.inner.get_raw(key).await
    }

    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        self.inner.put_raw(key, data).await
    }

    async fn check(&self) -> Result<CacheMode> {
        self.inner.check().await
    }

    fn location(&self) -> String {
        self.inner.location()
    }

    fn cache_type_name(&self) -> &'static str {
        self.inner.cache_type_name()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        self.inner.current_size().await
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        self.inner.max_size().await
    }

    fn multilevel_stats(&self) -> Option<MultiLevelStats> {
        self.inner.multilevel_stats()
    }

    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        self.inner.preprocessor_cache_mode_config()
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }

    async fn get_path(&self, key: &str) -> GetPathResult {
        self.inner.get_path(key).await
    }

    async fn get_preprocessor_cache_entry(
        &self,
        key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        self.inner.get_preprocessor_cache_entry(key).await
    }

    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        self.inner.put_preprocessor_cache_entry(key, entry).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::disk::DiskCache;
    use crate::cache::readonly::ReadOnlyStorage;

    #[tokio::test]
    async fn request_view_preserves_storage_capabilities() -> Result<()> {
        let tempdir = tempfile::tempdir()?;

        let fallback = vec![b"/configured/".to_vec()];
        let storage: Arc<dyn Storage> = Arc::new(DiskCache::new(
            tempdir.path(),
            1024 * 1024,
            &tokio::runtime::Handle::current(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            fallback.clone(),
        ));

        let unchanged = with_basedirs(Arc::clone(&storage), fallback.clone());
        assert!(Arc::ptr_eq(&unchanged, &storage));

        let request_basedirs = vec![b"/request/".to_vec()];
        let view = with_basedirs(Arc::clone(&storage), request_basedirs.clone());
        assert!(!Arc::ptr_eq(&view, &storage));
        assert_eq!(view.basedirs(), request_basedirs);
        assert_eq!(storage.basedirs(), fallback);
        assert_eq!(view.location(), storage.location());
        assert_eq!(view.cache_type_name(), storage.cache_type_name());

        let key = "0123456789abcdef";
        let raw: Bytes = CacheWrite::default().finish()?.into();

        view.put_raw(key, raw.clone()).await?;
        assert_eq!(view.get_raw(key).await?.as_deref(), Some(raw.as_ref()));
        assert!(matches!(view.get_path(key).await, GetPathResult::Found(_)));

        let entry_key = "fedcba9876543210";
        view.put(entry_key, CacheWrite::default()).await?;
        assert!(matches!(view.get(entry_key).await?, Cache::Hit(_)));

        let preprocessor_key = "preprocessor";
        view.put_preprocessor_cache_entry(preprocessor_key, PreprocessorCacheEntry::default())
            .await?;
        assert!(
            view.get_preprocessor_cache_entry(preprocessor_key)
                .await?
                .is_some()
        );
        assert_eq!(
            view.preprocessor_cache_mode_config(),
            storage.preprocessor_cache_mode_config()
        );
        assert_eq!(view.current_size().await?, storage.current_size().await?);
        assert_eq!(view.max_size().await?, storage.max_size().await?);

        let read_only: Arc<dyn Storage> = Arc::new(ReadOnlyStorage(Arc::clone(&storage)));
        let read_only_view = with_basedirs(read_only, vec![b"/read-only-request/".to_vec()]);
        assert_eq!(read_only_view.check().await?, CacheMode::ReadOnly);

        Ok(())
    }
}
