// Copyright 2016 Mozilla Foundation
// Copyright 2017 David Michael Barr <b@rr-dav.id.au>
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
use memcached::client::Client;
use memcached::proto::NoReplyOperation;
use memcached::proto::Operation;
use memcached::proto::ProtoType::Binary;
use std::cell::RefCell;
use std::io::Cursor;
use std::time::{Duration, Instant};

thread_local! {
    static CLIENT: RefCell<Option<Client>> = RefCell::default();
}

#[derive(Clone)]
pub struct MemcachedCache {
    url: String,
    pool: tokio::runtime::Handle,
}

impl MemcachedCache {
    pub fn new(url: &str, pool: &tokio::runtime::Handle) -> Result<MemcachedCache> {
        Ok(MemcachedCache {
            url: url.to_owned(),
            pool: pool.clone(),
        })
    }

    fn parse(&self) -> Vec<(&str, usize)> {
        self.url.split_whitespace().map(|w| (w, 1usize)).collect()
    }

    fn exec<U, F>(&self, f: F) -> U
    where
        F: FnOnce(&mut Client) -> U,
    {
        CLIENT.with(|rc| {
            match *rc.borrow_mut() {
                ref mut opt @ Some(_) => opt,
                ref mut opt @ None => {
                    *opt = Some(Client::connect(&self.parse(), Binary).unwrap());
                    opt
                }
            }
            .as_mut()
            .map(f)
            .unwrap()
        })
    }
}

#[async_trait]
impl Storage for MemcachedCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        let key = key.to_owned();
        let me = self.clone();

        self.pool
            .spawn_blocking(move || {
                me.exec(|c| c.get(key.as_bytes()))
                    .map(|(d, _)| CacheRead::from(Cursor::new(d)).map(Cache::Hit))
                    .unwrap_or(Ok(Cache::Miss))
            })
            .await?
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let key = key.to_owned();
        let me = self.clone();

        self.pool
            .spawn_blocking(move || {
                let start = Instant::now();
                let d = entry.finish()?;
                me.exec(|c| c.set_noreply(key.as_bytes(), &d, 0, 0))?;
                Ok(start.elapsed())
            })
            .await?
    }

    fn location(&self) -> String {
        format!("Memcached: {}", self.url)
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}
