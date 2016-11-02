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
    CacheWriteWriter,
    Storage,
};
use futures::{self,Future};
use simples3::{
    AutoRefreshingProviderSync,
    Bucket,
    ChainProvider,
    DefaultCredentialsProviderSync,
    ProfileProvider,
    ProvideAwsCredentials,
    Ssl,
};
use std::env;
use std::io::{
    self,
    Error,
    ErrorKind,
};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// A cache that stores entries in Amazon S3.
#[derive(Clone)]
pub struct S3Cache {
    /// The S3 bucket.
    bucket: Arc<Bucket>,
    /// Credentials provider.
    provider: Option<Arc<DefaultCredentialsProviderSync>>,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(bucket: &str) -> io::Result<S3Cache> {
        //TODO: this is hacky, this is where our mac builders store their
        // credentials. Maybe fetch this from a configuration file when
        // we have one?
        let provider = env::home_dir().and_then(|home| AutoRefreshingProviderSync::with_mutex(ChainProvider::with_profile_provider(ProfileProvider::with_configuration(home.join(".boto"), "Credentials"))).ok().map(Arc::new));
        //TODO: configurable SSL
        let bucket = Arc::new(Bucket::new(bucket, Ssl::No));
        Ok(S3Cache {
            bucket: bucket,
            provider: provider,
        })
    }
}

fn normalize_key(key: &str) -> String {
    format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key)
}

impl Storage for S3Cache {
    fn get(&self, key: &str) -> Cache {
        let key = normalize_key(key);
        match self.bucket.get(&key) {
            Ok(data) => {
                CacheRead::from(io::Cursor::new(data))
                    .map(Cache::Hit)
                    // This should only happen if the cached data
                    // is bad.
                    .unwrap_or_else(Cache::Error)
            }
            Err(e) => {
                warn!("Got AWS error: {:?}", e);
                Cache::Miss
            }
        }
    }

    fn start_put(&self, _key: &str) -> io::Result<CacheWrite> {
        // Just hand back an in-memory buffer.
        Ok(CacheWrite::new(io::Cursor::new(vec!())))
    }

    fn finish_put(&self, key: &str, entry: CacheWrite) -> CacheWriteFuture {
        let (complete, promise) = futures::oneshot();
        let this = self.clone();
        let key = key.to_owned();
        thread::spawn(move || {
            let start = Instant::now();
            complete.complete(entry.finish()
                              .and_then(|writer| {
                                  match writer {
                                      // This should never happen.
                                      CacheWriteWriter::File(_) => Err(Error::new(ErrorKind::Other, "Bad CacheWrite?")),
                                      CacheWriteWriter::Cursor(c) => {
                                          this.provider
                                              .as_ref()
                                              .ok_or(Error::new(ErrorKind::Other, "No AWS credential provider available!"))
                                              .and_then(|provider| provider.credentials().or(Err(Error::new(ErrorKind::Other, "Couldn't get AWS credentials!"))))
                                              .and_then(|credentials| {
                                                  let data = c.into_inner();
                                                  let key = normalize_key(&key);
                                                  this.bucket.put(&key, &data, &credentials)
                                                      .map_err(|e| Error::new(ErrorKind::Other, format!("Error putting cache entry to S3: {:?}", e)))
                                              })
                                              .map(|_| start.elapsed())
                                      }
                                  }
                              }).map_err(|e| format!("{}", e)));
        });
        promise.boxed()
    }

    fn get_location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }
}
