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
    Storage,
};
use futures::future::Future;
use simples3::{
    AutoRefreshingProvider,
    Bucket,
    ChainProvider,
    ProfileProvider,
    ProvideAwsCredentials,
    Ssl,
};
use std::env;
use std::io;
use std::rc::Rc;
use std::time::{Instant, Duration};
use tokio_core::reactor::Handle;

use errors::*;

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The S3 bucket.
    bucket: Rc<Bucket>,
    /// Credentials provider.
    provider: AutoRefreshingProvider<ChainProvider>,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(bucket: &str, endpoint: &str, handle: &Handle) -> Result<S3Cache> {
        let home = env::home_dir().ok_or("Couldn't find home directory")?;
        let profile_providers = vec![
            ProfileProvider::with_configuration(home.join(".aws").join("credentials"), "default"),
            //TODO: this is hacky, this is where our mac builders store their
            // credentials. We should either match what boto does more directly
            // or make those builders put their credentials in ~/.aws/credentials
            ProfileProvider::with_configuration(home.join(".boto"), "Credentials"),
        ];
        let provider = AutoRefreshingProvider::new(ChainProvider::with_profile_providers(profile_providers, handle));
        //TODO: configurable SSL
        let bucket = Rc::new(Bucket::new(bucket, endpoint, Ssl::No, handle)?);
        Ok(S3Cache {
            bucket: bucket,
            provider: provider,
        })
    }
}

fn normalize_key(key: &str) -> String {
    let normalized = format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key);
    if let Ok(s3_prefix) = env::var("SCCACHE_BUCKET_PREFIX") {
        return format!("{}/{}", s3_prefix, normalized);
    }
    normalized
}

impl Storage for S3Cache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = normalize_key(key);
        Box::new(self.bucket.get(&key).then(|result| {
            match result {
                Ok(data) => {
                    let hit = CacheRead::from(io::Cursor::new(data))?;
                    Ok(Cache::Hit(hit))
                }
                Err(e) => {
                    warn!("Got AWS error: {:?}", e);
                    Ok(Cache::Miss)
                }
            }
        }))
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = normalize_key(&key);
        let start = Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return f_err(e),
        };
        let credentials = self.provider.credentials().chain_err(|| {
            "failed to get AWS credentials"
        });

        let bucket = self.bucket.clone();
        let response = credentials.and_then(move |credentials| {
            bucket.put(&key, data, &credentials).chain_err(|| {
                "failed to put cache entry in s3"
            })
        });

        Box::new(response.map(move |_| start.elapsed()))
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }

    fn current_size(&self) -> Option<u64> { None }
    fn max_size(&self) -> Option<u64> { None }
}
