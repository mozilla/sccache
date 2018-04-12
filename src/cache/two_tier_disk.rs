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

use cache::{
    Cache,
    CacheWrite,
    Storage,
};
use cache::disk::DiskCache;
use futures;
use futures::future::Future;
use std::sync::Arc;
use std::time::{Duration};

use errors::*;

/// A cache that stores entries on disk but can fetch from remote cache or disk.
pub struct TwoTierDiskCache {
    /// Remote Cache
    remote: Arc<Storage>,
    /// Disk cache
    disk: Arc<DiskCache>
}

impl TwoTierDiskCache {
    pub fn new(remote_cache: Arc<Storage>, disk_cache: Arc<DiskCache>) -> TwoTierDiskCache {
        TwoTierDiskCache {
            remote: remote_cache,
            disk: disk_cache,
        }
    }
}

impl Storage for TwoTierDiskCache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        let disk_lookup = Box::new(self.disk.get(&key).then(|disk_result| {
            match disk_result {
                Ok(data) => {
                    match data {
                        Cache::Hit(_) => Ok(data),
                        _ => Ok(Cache::Miss),
                    }
                }
                Err(e) => {
                    warn!("Got disk error: {:?}", e);
                     Ok(Cache::Miss)
                }
            }
        })).wait();
        let remote_lookup = match disk_lookup {
            Ok(Cache::Hit(_)) => Box::new(futures::done(disk_lookup)),
            _ => self.remote.get(&key)
        };
        let cache_status = remote_lookup.wait();
        let new_cache_status = match cache_status {
            Ok(Cache::Hit(mut entry)) => {
                self.put(&key, entry.to_write()).wait();
                Ok(Cache::Hit(entry))
            }
            Ok(c) => Ok(c),
            Err(e) => Err(e)
        };
        Box::new(futures::done(new_cache_status))
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        self.disk.put(key, entry)
    }

    fn location(&self) -> String {
        format!("Local: {} - Remote: {}", self.disk.location(), self.remote.location())
    }

    fn current_size(&self) -> Option<u64> { self.disk.current_size() }
    fn max_size(&self) -> Option<u64> { self.disk.max_size() }
}
