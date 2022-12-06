// Copyright 2022 Bitski Inc.
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

use std::io;
use std::time::{Duration, Instant};

use gha_toolkit::cache::*;

use crate::cache::{Cache, CacheRead, CacheWrite, Storage};
use crate::errors::*;

/// A cache that stores entries in Amazon S3.
pub struct GHACache {
    client: CacheClient,
}

impl GHACache {
    /// Create a new `GHACache` storing data in `bucket`.
    pub fn new(
        url: &str,
        token: &str,
        cache_to: Option<String>,
        cache_from: Option<String>,
    ) -> Result<GHACache> {
        let mut builder = CacheClient::builder(url, token);
        if let Some(key) = cache_to {
            builder = builder.cache_to(key);
        }
        if let Some(cache_from) = cache_from {
            builder = builder.cache_from(
                cache_from
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty()),
            );
        }
        let client = builder.build()?;
        Ok(GHACache { client })
    }
}

#[async_trait]
impl Storage for GHACache {
    async fn get(&self, key: &str) -> Result<Cache> {
        let entry = self.client.entry(key).await?;
        if let Some(ArtifactCacheEntry {
            archive_location: Some(url),
            ..
        }) = entry
        {
            let data = self.client.get(&url).await?;
            let hit = CacheRead::from(io::Cursor::new(data))?;
            Ok(Cache::Hit(hit))
        } else {
            Ok(Cache::Miss)
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let start = Instant::now();
        let data = entry.finish()?;
        self.client.put(key, io::Cursor::new(data)).await?;
        Ok(start.elapsed())
    }

    fn location(&self) -> String {
        format!(
            "GHA, url: {}, cache_to: {:?}, cache_from: {:?}",
            self.client.base_url(),
            self.client.cache_to(),
            self.client.cache_from()
        )
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}
