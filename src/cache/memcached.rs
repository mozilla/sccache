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

use cache::{
    Cache,
    CacheRead,
    CacheWrite,
    Storage,
};
use errors::*;
use futures_cpupool::CpuPool;
use memcached::client::Client;
use memcached::proto::Operation;
use memcached::proto::NoReplyOperation;
use memcached::proto::ProtoType::Binary;
use std::cell::RefCell;
use std::io::Cursor;
use std::time::{
    Duration,
    Instant,
};

thread_local! {
    static CLIENT: RefCell<Option<Client>> = RefCell::default();
}

#[derive(Clone)]
pub struct MemcachedCache {
    url: String,
    pool: CpuPool,
}

impl MemcachedCache {
    pub fn new(url: &str, pool: &CpuPool) -> Result<MemcachedCache> {
        Ok(MemcachedCache {
            url: url.to_owned(),
            pool: pool.clone(),
        })
    }

    fn parse(&self) -> Vec<(&str, usize)> {
        self.url.split_whitespace().map(|w| (w, 1usize)).collect()
    }

    fn exec<U, F>(&self, f: F) -> U
        where F: FnOnce(&mut Client) -> U
    {
        CLIENT.with(|rc| match *rc.borrow_mut() {
            ref mut opt @ Some(_) => opt,
            ref mut opt @ None => {
                *opt = Some(Client::connect(&self.parse(), Binary).unwrap());
                opt
            }
        }.as_mut().map(f).unwrap())
    }
}

impl Storage for MemcachedCache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = key.to_owned();
        let me = self.clone();
        Box::new(self.pool.spawn_fn(move || {
            me.exec(|c| c.get(&key.as_bytes()))
            .map(|(d, _)| CacheRead::from(Cursor::new(d)).map(Cache::Hit))
            .unwrap_or(Ok(Cache::Miss))
        }))
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = key.to_owned();
        let me = self.clone();
        Box::new(self.pool.spawn_fn(move || {
            let start = Instant::now();
            let d = entry.finish()?;
            me.exec(|c| c.set_noreply(&key.as_bytes(), &d, 0, 0))?;
            Ok(start.elapsed())
        }))
    }

    fn location(&self) -> String {
        format!("Memcached: {}", self.url)
    }

    fn current_size(&self) -> SFuture<Option<u64>> { f_ok(None) }
    fn max_size(&self) -> SFuture<Option<u64>> { f_ok(None) }
}
