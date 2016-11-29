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
    CacheRead,
    CacheWrite,
    CacheWriteFuture,
    Storage,
};
use futures::{self,Future};
use lru_disk_cache::LruDiskCache;
use lru_disk_cache::Error as LruError;
use std::ffi::OsStr;
use std::io;
use std::path::{Path,PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

/// A cache that stores entries at local disk paths.
#[derive(Clone)]
pub struct DiskCache {
    /// `LruDiskCache` does all the real work here.
    lru: Arc<Mutex<LruDiskCache>>,
}

impl DiskCache {
    /// Create a new `DiskCache` rooted at `root`, with `max_size` as the maximum cache size on-disk, in bytes.
    pub fn new<T: AsRef<OsStr>>(root: &T, max_size: usize) -> DiskCache {
        DiskCache {
            //TODO: change this function to return a Result
            lru: Arc::new(Mutex::new(LruDiskCache::new(root, max_size).expect("Couldn't instantiate disk cache!"))),
        }
    }
}

/// Make a path to the cache entry with key `key`.
fn make_key_path(key: &str) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key)
}

impl Storage for DiskCache {
    fn get(&self, key: &str) -> Cache {
        trace!("DiskCache::get({})", key);
        match self.lru.lock().unwrap().get(make_key_path(key)) {
            Err(LruError::FileNotInCache) => Cache::Miss,
            Err(LruError::Io(e)) => Cache::Error(e),
            Ok(f) => {
                match CacheRead::from(f) {
                    Err(e) => Cache::Error(e),
                    Ok(cache_read) => Cache::Hit(cache_read),
                }
            }
            Err(_) => panic!("Unexpected error!"),
        }
    }

    fn start_put(&self, key: &str) -> io::Result<CacheWrite> {
        trace!("DiskCache::start_put({})", key);
        Ok(CacheWrite::new())
    }

    fn finish_put(&self, key: &str, entry: CacheWrite) -> CacheWriteFuture {
        // We should probably do this on a background thread if we're going to buffer
        // everything in memory...
        trace!("DiskCache::finish_put({})", key);
        let (complete, promise) = futures::oneshot();
        let lru = self.lru.clone();
        let key = make_key_path(key);
        thread::spawn(move || {
            let start = Instant::now();
            complete.complete(entry.finish()
                              .map_err(|e| format!("{}", e))
                              .and_then(|v| {
                                  lru.lock().unwrap().insert_bytes(key, &v)
                                      .map(|_| start.elapsed())
                                      .map_err(|e| format!("{}", e))
                              }));
        });
        promise.boxed()
    }

    fn location(&self) -> String {
        format!("Local disk: {:?}", self.lru.lock().unwrap().path())
    }

    fn current_size(&self) -> Option<usize> { Some(self.lru.lock().unwrap().size()) }
    fn max_size(&self) -> Option<usize> { Some(self.lru.lock().unwrap().capacity()) }
}
