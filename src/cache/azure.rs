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

pub struct AzureBlobCache {
    container: Arc<BlobContainer>,
    credentials: AzureCredentials,
    key_prefix: String,
}

impl AzureBlobCache {
    pub fn new(credentials: Option<AzureCredentials>, key_prefix: &str) -> Result<AzureBlobCache> {
        let credentials = match credentials {
            Some(creds) => creds,
            None => match EnvironmentProvider.provide_credentials() {
                Ok(creds) => creds,
                Err(err) => bail!(
                    "Could not find Azure credentials in the environment: {}",
                    err
                ),
            },
        };

        let container = match BlobContainer::new(
            credentials.azure_blob_endpoint(),
            credentials.blob_container_name(),
        ) {
            Ok(container) => container,
            Err(e) => bail!("Error instantiating BlobContainer: {:?}", e),
        };

        Ok(AzureBlobCache {
            container: Arc::new(container),
            credentials,
            key_prefix: key_prefix.to_owned(),
        })
    }

    fn normalize_key(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", &self.key_prefix, key)
        }
    }
}

#[async_trait]
impl Storage for AzureBlobCache {
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

#[test]
fn normalize_key() {
    let credentials = AzureCredentials::new(
        "blob endpoint",
        "account name",
        None,
        String::from("container name"),
    );

    let cache = AzureBlobCache::new(Some(credentials.clone()), "").unwrap();
    assert_eq!(cache.normalize_key("key"), String::from("key"));

    let cache = AzureBlobCache::new(Some(credentials), "prefix").unwrap();
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

    let cache = AzureBlobCache::new(Some(credentials.clone()), "").unwrap();
    assert_eq!(
        cache.location(),
        String::from("Azure, container: BlobContainer(url=blob endpoint/container name/), (none)")
    );

    let cache = AzureBlobCache::new(Some(credentials), "prefix").unwrap();
    assert_eq!(
        cache.location(),
        String::from("Azure, container: BlobContainer(url=blob endpoint/container name/), prefix")
    );
}
