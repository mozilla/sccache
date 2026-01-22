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
use crate::errors::*;

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
}

#[cfg(test)]
mod test {
    use futures::FutureExt;

    use super::*;
    use crate::test::mock_storage::MockStorage;

    #[test]
    fn readonly_storage_is_readonly() {
        let storage = ReadOnlyStorage(Arc::new(MockStorage::new(None)));
        assert_eq!(
            storage.check().now_or_never().unwrap().unwrap(),
            CacheMode::ReadOnly
        );
    }

    #[test]
    fn readonly_storage_put_err() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        let storage = ReadOnlyStorage(Arc::new(MockStorage::new(None)));
        runtime.block_on(async move {
            assert_eq!(
                storage
                    .put("test1", CacheWrite::default())
                    .await
                    .unwrap_err()
                    .to_string(),
                "Cannot write to read-only storage"
            );
        });
    }
}
