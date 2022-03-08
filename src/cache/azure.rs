// Copyright 2018 Benjamin Bader
// Copyright 2016 Mozilla Foundation
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

use crate::azure::BlobContainer;
use crate::azure::*;
use crate::cache::{Cache, CacheRead, CacheWrite, Storage};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::errors::*;

pub struct AzureBlobCache<ConcreteBlobContainer: BlobContainer> {
    container: Arc<ConcreteBlobContainer>,
    credentials: AzureCredentials,
    key_prefix: String,
}

impl AzureBlobCache<HttpBlobContainer> {
    pub fn new(credentials: AzureCredentials, key_prefix: &str) -> Result<Self> {
        let container = match HttpBlobContainer::new(
            credentials.azure_blob_endpoint(),
            credentials.blob_container_name(),
        ) {
            Ok(container) => container,
            Err(e) => bail!("Error instantiating BlobContainer: {:?}", e),
        };

        Ok(Self {
            container: Arc::new(container),
            credentials,
            key_prefix: key_prefix.to_owned(),
        })
    }
}

impl<ConcreteBlobContainer: BlobContainer> AzureBlobCache<ConcreteBlobContainer> {
    fn normalize_key(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", &self.key_prefix, key)
        }
    }
}

#[async_trait]
impl<ConcreteBlobContainer: BlobContainer> Storage for AzureBlobCache<ConcreteBlobContainer> {
    async fn get(&self, key: &str) -> Result<Cache> {
        let key = self.normalize_key(key);
        match self.container.get(&key, &self.credentials).await {
            Ok(data) => {
                let hit = CacheRead::from(io::Cursor::new(data))?;
                Ok(Cache::Hit(hit))
            }
            Err(e) => {
                warn!("Got Azure error: {:?}", e);
                Ok(Cache::Miss)
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let start = Instant::now();
        let data = entry.finish()?;
        let key = self.normalize_key(key);

        let _ = self
            .container
            .put(&key, data, &self.credentials)
            .await
            .context("Failed to put cache entry in Azure")?;

        Ok(start.elapsed())
    }

    fn location(&self) -> String {
        format!(
            "Azure, container: {}, key_prefix: {}",
            self.container,
            if self.key_prefix.is_empty() {
                "(none)"
            } else {
                &self.key_prefix
            },
        )
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::cell::RefCell;
    use std::fmt;
    use std::sync::Mutex;

    struct MockBlobContainer {
        last_key: Mutex<RefCell<String>>,
    }

    impl MockBlobContainer {
        pub fn new() -> Self {
            Self {
                last_key: Mutex::new(RefCell::new(String::new())),
            }
        }

        pub fn get_last_key(&self) -> String {
            let cell_guard = self.last_key.lock().unwrap();
            let last_key = cell_guard.borrow();
            last_key.clone()
        }

        pub fn set_last_key(&self, key: String) {
            let last_key = self.last_key.lock().unwrap();
            last_key.replace(key);
        }
    }

    impl fmt::Display for MockBlobContainer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockBlobContainer")
        }
    }

    #[async_trait]
    impl BlobContainer for MockBlobContainer {
        async fn get(&self, key: &str, _creds: &AzureCredentials) -> Result<Vec<u8>> {
            self.set_last_key(key.to_owned());
            Err(BadHttpStatusError(http::StatusCode::NOT_FOUND).into())
        }

        async fn put(&self, key: &str, _content: Vec<u8>, _creds: &AzureCredentials) -> Result<()> {
            self.set_last_key(key.to_owned());
            Ok(())
        }
    }

    #[test]
    fn normalize_key() {
        let credentials = AzureCredentials::new(
            "blob endpoint",
            "account name",
            None,
            String::from("container name"),
        );

        let cache = AzureBlobCache::new(credentials.clone(), "").unwrap();
        assert_eq!(cache.normalize_key("key"), String::from("key"));

        let cache = AzureBlobCache::new(credentials, "prefix").unwrap();
        assert_eq!(cache.normalize_key("key"), String::from("prefix/key"));
    }

    #[test]
    fn location() {
        let credentials = AzureCredentials::new(
            "blob endpoint",
            "account name",
            None,
            String::from("container name"),
        );

        let cache = AzureBlobCache::new(credentials.clone(), "").unwrap();
        assert_eq!(
            cache.location(),
            String::from("Azure, container: BlobContainer(url=blob endpoint/container name/), key_prefix: (none)")
        );

        let cache = AzureBlobCache::new(credentials, "prefix").unwrap();
        assert_eq!(
            cache.location(),
            String::from("Azure, container: BlobContainer(url=blob endpoint/container name/), key_prefix: prefix")
        );
    }

    #[tokio::test]
    async fn get_with_key_prefix() -> Result<()> {
        let credentials = AzureCredentials::new(
            "endpoint",
            "account name",
            None,
            String::from("container name"),
        );
        let container = Arc::new(MockBlobContainer::new());
        let cache = AzureBlobCache {
            container: container.clone(),
            credentials,
            key_prefix: String::from("prefix"),
        };

        let result = cache.get("foo/bar").await;
        assert!(result.is_ok());
        match result.unwrap() {
            Cache::Miss => (),
            x => bail!("Result {:?} is not Cache::Miss", x),
        }
        assert_eq!(container.get_last_key(), "prefix/foo/bar");

        Ok(())
    }

    #[tokio::test]
    async fn put_with_key_prefix() -> Result<()> {
        let credentials = AzureCredentials::new(
            "endpoint",
            "account name",
            None,
            String::from("container name"),
        );
        let container = Arc::new(MockBlobContainer::new());
        let cache = AzureBlobCache {
            container: container.clone(),
            credentials,
            key_prefix: String::from("prefix"),
        };

        let result = cache.put("foo/bar", CacheWrite::new()).await;
        assert!(result.is_ok());
        assert_eq!(container.get_last_key(), "prefix/foo/bar");

        Ok(())
    }
}
