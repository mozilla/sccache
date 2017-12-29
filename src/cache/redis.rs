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

use cache::{
    Cache,
    CacheRead,
    CacheWrite,
    Storage,
};
use errors::*;
use futures_cpupool::CpuPool;
use redis::{
    cmd,
    Client,
    Commands,
    Connection,
    InfoDict,
};
use std::collections::HashMap;
use std::io::Cursor;
use std::time::{
    Duration,
    Instant,
};

/// A cache that stores entries in a Redis.
#[derive(Clone)]
pub struct RedisCache {
    url: String,
    client: Client,
    pool: CpuPool,
}

impl RedisCache {
    /// Create a new `RedisCache`.
    pub fn new(url: &str, pool: &CpuPool) -> Result<RedisCache> {
        Ok(RedisCache {
            url: url.to_owned(),
            client: Client::open(url)?,
            pool: pool.clone(),
        })
    }

    /// Returns a connection with configured read and write timeouts.
    fn connect(&self) -> Result<Connection> {
        self.client.get_connection()
            .map_err(|e| e.into())
            .and_then(|c| {
                c.set_read_timeout(Some(Duration::from_millis(10_000)))?;
                c.set_write_timeout(Some(Duration::from_millis(10_000)))?;
                Ok(c)
            })
    }
}

impl Storage for RedisCache {
    /// Open a connection and query for a key.
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = key.to_owned();
        let me = self.clone();
        Box::new(self.pool.spawn_fn(move || {
            let c = me.connect()?;
            let d = c.get::<&str, Vec<u8>>(&key)?;
            if d.is_empty() {
                Ok(Cache::Miss)
            } else {
                CacheRead::from(Cursor::new(d))
                    .map(Cache::Hit)
            }
        }))
    }

    /// Open a connection and store a object in the cache.
    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = key.to_owned();
        let me = self.clone();
        Box::new(self.pool.spawn_fn(move || {
            let start = Instant::now();
            let c = me.connect()?;
            let d = entry.finish()?;
            c.set::<&str, Vec<u8>, ()>(&key, d)?;
            Ok(start.elapsed())
        }))
    }

    /// Returns the cache location.
    fn location(&self) -> String {
        format!("Redis: {}", self.url)
    }

    /// Returns the current cache size. This value is aquired via
    /// the Redis INFO command (used_memory).
    fn current_size(&self) -> Option<u64> {
        self.connect().ok()
            .and_then(|c| cmd("INFO").query(&c).ok())
            .and_then(|i: InfoDict| i.get("used_memory"))
    }

    /// Returns the maximum cache size. This value is read via
    /// the Redis CONFIG command (maxmemory). If the server has no
    /// configured limit, the result is None.
    fn max_size(&self) -> Option<u64> {
        self.connect().ok()
            .and_then(|c| cmd("CONFIG").arg("GET").arg("maxmemory").query(&c).ok())
            .and_then(|h: HashMap<String, usize>| h.get("maxmemory").map(|s| *s))
            .and_then(|s| {
                if s != 0 {
                    Some(s as u64)
                } else {
                    None
                }
            })
    }
}
