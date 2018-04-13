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
    CacheRead,
};
use cache::disk::DiskCache;
use futures;
use futures::future::Future;
use std::sync::Arc;
use std::time::{Duration};

use errors;
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

    // To get good lifetimes we need to take disk and remote out of self
    fn _get(&self, key: String, disk: Arc<Storage>, remote: Arc<Storage>) -> SFuture<Cache> {
        Box::new(
            disk.get(&key)
                .then(move |disk_result| {
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
                })
                .and_then(move |disk_status| {
                    if let Cache::Hit(_) = disk_status {
                        return Box::new(futures::future::result(Ok(disk_status)))
                            as Box<futures::Future<Error=errors::Error, Item=Cache>>;
                    }

                    Box::new(remote.get(&key)
                        .then(move |remote_status| {
                            match remote_status {
                                Ok(Cache::Hit(mut entry)) => {
                                    {
                                        trace!("cache hit but need to push back into primary cache");
                                        // We really don't care if this succeeds or not
                                        // we just need to try it
                                        disk.put(&key, entry.to_write());
                                        Ok(Cache::Hit(entry))
                                    }
                                }
                                _ => remote_status,
                            }
                        }))
                })
        )
    }
}

impl Storage for TwoTierDiskCache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        self._get(String::from(key), self.disk.clone(), self.remote.clone())
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
