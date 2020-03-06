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

use crate::cache::{Cache, CacheRead, CacheWrite, Storage};
use crate::simples3::{
    AutoRefreshingProvider, Bucket, ChainProvider, ProfileProvider, ProvideAwsCredentials, Ssl,
};
use directories::UserDirs;
use futures::future;
use futures::future::Future;
use std::io;
use std::rc::Rc;
use std::time::{Duration, Instant};

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
    pub fn new(bucket: &str, endpoint: &str, use_ssl: bool) -> Result<S3Cache> {
        let user_dirs = UserDirs::new().ok_or("Couldn't get user directories")?;
        let home = user_dirs.home_dir();

        let profile_providers = vec![
            ProfileProvider::with_configuration(home.join(".aws").join("credentials"), "default"),
            //TODO: this is hacky, this is where our mac builders store their
            // credentials. We should either match what boto does more directly
            // or make those builders put their credentials in ~/.aws/credentials
            ProfileProvider::with_configuration(home.join(".boto"), "Credentials"),
        ];
        let provider =
            AutoRefreshingProvider::new(ChainProvider::with_profile_providers(profile_providers));
        let ssl_mode = if use_ssl { Ssl::Yes } else { Ssl::No };
        let bucket = Rc::new(Bucket::new(bucket, endpoint, ssl_mode)?);
        Ok(S3Cache { bucket, provider })
    }
}

fn normalize_key(key: &str) -> String {
    format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key)
}

impl Storage for S3Cache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = normalize_key(key);

        let result_cb = |result| match result {
            Ok(data) => {
                let hit = CacheRead::from(io::Cursor::new(data))?;
                Ok(Cache::Hit(hit))
            }
            Err(e) => {
                warn!("Got AWS error: {:?}", e);
                Ok(Cache::Miss)
            }
        };

        let bucket = self.bucket.clone();
        let response = self
            .provider
            .credentials()
            .then(move |credentials| match credentials {
                Ok(creds) => bucket.get(&key, Some(&creds)),
                Err(e) => {
                    debug!("Could not load AWS creds: {}", e);
                    bucket.get(&key, None)
                }
            })
            .then(result_cb);
        Box::new(response)
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = normalize_key(&key);
        let start = Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return f_err(e),
        };
        let credentials = self
            .provider
            .credentials()
            .chain_err(|| "failed to get AWS credentials");

        let bucket = self.bucket.clone();
        let response = credentials.and_then(move |credentials| {
            bucket
                .put(&key, data, &credentials)
                .chain_err(|| "failed to put cache entry in s3")
        });

        Box::new(response.map(move |_| start.elapsed()))
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }

    fn current_size(&self) -> SFuture<Option<u64>> {
        Box::new(future::ok(None))
    }
    fn max_size(&self) -> SFuture<Option<u64>> {
        Box::new(future::ok(None))
    }
}
