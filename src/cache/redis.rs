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
use futures::{future, Future};
use redis::{
    cmd,
    Client,
    InfoDict,
};
use redis::async::Connection;
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
}

impl RedisCache {
    /// Create a new `RedisCache`.
    pub fn new(url: &str) -> Result<RedisCache> {
        Ok(RedisCache {
            url: url.to_owned(),
            client: Client::open(url)?,
        })
    }

    /// Returns a connection with configured read and write timeouts.
    fn connect(&self) -> impl Future<Item = Connection, Error = Error> {
        self.client.get_async_connection()
            .map_err(|e| e.into())
    }
}

impl Storage for RedisCache {
    /// Open a connection and query for a key.
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = key.to_owned();
        let me = self.clone();
        Box::new(
            me.connect()
                .and_then(|c| {
                    cmd("GET").arg(key).query_async(c).from_err()
                })
                .and_then(|(_, d): (_, Vec<u8>)| {
                    if d.is_empty() {
                        Ok(Cache::Miss)
                    } else {
                        CacheRead::from(Cursor::new(d))
                            .map(Cache::Hit)
                    }
                })
        )
    }

    /// Open a connection and store a object in the cache.
    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = key.to_owned();
        let me = self.clone();
        let start = Instant::now();
        Box::new(
            me.connect()
                .and_then(move |c| {
                    future::result(entry.finish()).and_then(|d| {
                        cmd("SET").arg(key).arg(d).query_async(c).from_err()
                    })
                })
                .map(move |(_, ())| start.elapsed())
        )
    }

    /// Returns the cache location.
    fn location(&self) -> String {
        format!("Redis: {}", self.url)
    }

    /// Returns the current cache size. This value is aquired via
    /// the Redis INFO command (used_memory).
    fn current_size(&self) -> SFuture<Option<u64>> {
        Box::new(
            self.connect()
                .and_then(|c| cmd("INFO").query_async(c).from_err())
                .map(|(_, v)| v)
                .map(|i: InfoDict| i.get("used_memory"))
        )
    }

    /// Returns the maximum cache size. This value is read via
    /// the Redis CONFIG command (maxmemory). If the server has no
    /// configured limit, the result is None.
    fn max_size(&self) -> SFuture<Option<u64>> {
        Box::new(
            self.connect()
                .and_then(|c| cmd("CONFIG").arg("GET").arg("maxmemory").query_async(c).from_err())
                .map(|(_, v)| v)
                .map(|h: HashMap<String, usize>| {
                    h.get("maxmemory").and_then(|&s| {
                        if s != 0 {
                            Some(s as u64)
                        } else {
                            None
                        }
                    })
                })
        )
    }
}
