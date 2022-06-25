// Copyright 2016 Mozilla Foundation
// Copyright 2016 Felix Obenhuber <felix@obenhuber.de>
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

use crate::cache::{Cache, CacheRead, CacheWrite, Storage};
use crate::errors::*;
use redis::aio::Connection;
use redis::{cmd, Client, InfoDict};
use std::collections::HashMap;
use std::io::Cursor;
use std::time::{Duration, Instant};
use url::Url;

/// A cache that stores entries in a Redis.
#[derive(Clone)]
pub struct RedisCache {
    display_url: String, // for display only: password (if any) will be masked
    client: Client,
}

impl RedisCache {
    /// Create a new `RedisCache`.
    pub fn new(url: &str) -> Result<RedisCache> {
        let mut parsed = Url::parse(url)?;
        // If the URL has a password set, mask it when displaying.
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("*****"));
        }
        Ok(RedisCache {
            display_url: parsed.to_string(),
            client: Client::open(url)?,
        })
    }

    /// Returns a connection with configured read and write timeouts.
    async fn connect(&self) -> Result<Connection> {
        Ok(self.client.get_async_connection().await?)
    }
}

#[async_trait]
impl Storage for RedisCache {
    /// Open a connection and query for a key.
    async fn get(&self, key: &str) -> Result<Cache> {
        let mut c = self.connect().await?;
        let d: Vec<u8> = cmd("GET").arg(key).query_async(&mut c).await?;
        if d.is_empty() {
            Ok(Cache::Miss)
        } else {
            CacheRead::from(Cursor::new(d)).map(Cache::Hit)
        }
    }

    /// Open a connection and store a object in the cache.
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let start = Instant::now();
        let mut c = self.connect().await?;
        let d = entry.finish()?;
        cmd("SET").arg(key).arg(d).query_async(&mut c).await?;
        Ok(start.elapsed())
    }

    /// Returns the cache location.
    fn location(&self) -> String {
        format!("Redis: {}", self.display_url)
    }

    /// Returns the current cache size. This value is acquired via
    /// the Redis INFO command (used_memory).
    async fn current_size(&self) -> Result<Option<u64>> {
        let mut c = self.connect().await?;
        let v: InfoDict = cmd("INFO").query_async(&mut c).await?;
        Ok(v.get("used_memory"))
    }

    /// Returns the maximum cache size. This value is read via
    /// the Redis CONFIG command (maxmemory). If the server has no
    /// configured limit, the result is None.
    async fn max_size(&self) -> Result<Option<u64>> {
        let mut c = self.connect().await?;
        let result: redis::RedisResult<HashMap<String, usize>> = cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory")
            .query_async(&mut c)
            .await;
        match result {
            Ok(h) => Ok(h
                .get("maxmemory")
                .and_then(|&s| if s != 0 { Some(s as u64) } else { None })),
            Err(_) => Ok(None),
        }
    }
}
