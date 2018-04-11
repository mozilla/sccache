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
use cache::s3::S3Cache;
use futures;
use futures::future::Future;
use std::time::{Duration};

use errors::*;

/// A cache that stores entries on disk but can fetch from Amazon S3 or disk.
pub struct S3DiskCache {
    /// S3 Cache
    s3: S3Cache,
    /// Disk cache
    disk: DiskCache
}

impl S3DiskCache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(s3_cache: S3Cache, disk_cache: DiskCache) -> S3DiskCache {
        S3DiskCache {
            s3: s3_cache,
            disk: disk_cache,
        }
    }
}

impl Storage for S3DiskCache {
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
                    warn!("Got s3disk error: {:?}", e);
                     Ok(Cache::Miss)
                }
            }
        })).wait();
        match disk_lookup {
            Ok(Cache::Hit(_)) => Box::new(futures::done(disk_lookup)),
            _ => Box::new(self.s3.get(&key))
        }
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        self.disk.put(key, entry)
    }

    fn location(&self) -> String {
        format!("Local: {} - S3, bucket: {}", self.disk.location(), self.s3.location())
    }

    fn current_size(&self) -> Option<u64> { self.disk.current_size() }
    fn max_size(&self) -> Option<u64> { self.disk.max_size() }
}
