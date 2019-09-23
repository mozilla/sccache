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

use crate::cache::{
    Cache,
    CacheRead,
    CacheWrite,
    Storage,
};
use futures::future;
use futures::future::Future;
use crate::simples3::{
    AutoRefreshingProvider,
    Bucket,
    ChainProvider,
    ProvideAwsCredentials,
};
use std::rc::Rc;
use std::time::{Instant, Duration};
use std::io;

use crate::errors::*;

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The S3 bucket.
    bucket: Rc<Bucket>,
    /// Credentials provider.
    provider: AutoRefreshingProvider<ChainProvider>,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(bucket: &str, endpoint: &str) -> Result<S3Cache> {
        let provider = AutoRefreshingProvider::new(ChainProvider::new())?;
        let bucket = Rc::new(Bucket::new(bucket, endpoint)?);
        Ok(S3Cache {
            bucket,
            provider,
        })
    }
}

fn normalize_key(key: &str) -> String {
    format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key)
}

impl Storage for S3Cache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = normalize_key(key);
        let credentials = self.provider.credentials().chain_err(|| {
            "failed to get S3 credentials"
        });

        let bucket = self.bucket.clone();
        Box::new(credentials.then(move |credentials| {
            let credentials = credentials.ok();
            bucket.get(&key, &credentials).then(|result| {
                match result {
                    Ok(data) => {
                        let hit = CacheRead::from(io::Cursor::new(data))?;
                        Ok(Cache::Hit(hit))
                    }
                    Err(e) => {
                        warn!("Got S3 error: {:?}", e);
                        Ok(Cache::Miss)
                    }
                }
            })
        }))
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = normalize_key(key);
        let start = Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return f_err(e),
        };
        let credentials = self.provider.credentials().chain_err(|| {
            "failed to get S3 credentials"
        });

        let bucket = self.bucket.clone();
        let response = credentials.then(move |credentials| {
            let credentials = credentials.ok();
            bucket.put(&key, data, &credentials).chain_err(|| {
                "failed to put cache entry in s3"
            })
        });

        Box::new(response.map(move |_| start.elapsed()))
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }

    fn current_size(&self) -> SFuture<Option<u64>> { Box::new(future::ok(None)) }
    fn max_size(&self) -> SFuture<Option<u64>> { Box::new(future::ok(None)) }
}
