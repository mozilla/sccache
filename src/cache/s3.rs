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
use futures::future::{self, Future};
use simples3::{
    AutoRefreshingProvider,
    Bucket,
    ChainProvider,
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
use std::rc::Rc;
use std::time::Instant;
use tokio_core::reactor::Handle;

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The S3 bucket.
    bucket: Rc<Bucket>,
    /// Credentials provider.
    provider: AutoRefreshingProvider<ChainProvider>,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(bucket: &str, endpoint: &str, handle: &Handle) -> io::Result<S3Cache> {
        let home = try!(env::home_dir().ok_or(Error::new(ErrorKind::Other, "Couldn't find home directory")));
        let profile_providers = vec![
            ProfileProvider::with_configuration(home.join(".aws").join("credentials"), "default"),
            //TODO: this is hacky, this is where our mac builders store their
            // credentials. We should either match what boto does more directly
            // or make those builders put their credentials in ~/.aws/credentials
            ProfileProvider::with_configuration(home.join(".boto"), "Credentials"),
        ];
        let provider = AutoRefreshingProvider::new(ChainProvider::with_profile_providers(profile_providers, handle));
        //TODO: configurable SSL
        let bucket = Rc::new(Bucket::new(bucket, endpoint, Ssl::No, handle));
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
    fn get(&self, key: &str) -> Box<Future<Item=Cache, Error=io::Error>> {
        let key = normalize_key(key);
        Box::new(self.bucket.get(&key).then(|result| {
            match result {
                Ok(data) => {
                    CacheRead::from(io::Cursor::new(data)).map(Cache::Hit)
                }
                Err(e) => {
                    warn!("Got AWS error: {:?}", e);
                    Ok(Cache::Miss)
                }
            }
        }))
    }

    fn start_put(&self, _key: &str) -> io::Result<CacheWrite> {
        // Just hand back an in-memory buffer.
        Ok(CacheWrite::new())
    }

    fn finish_put(&self, key: &str, entry: CacheWrite) -> CacheWriteFuture {
        let key = normalize_key(&key);
        let start = Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return future::err(e.to_string()).boxed(),
        };
        let credentials = self.provider.credentials().map_err(|e| {
            Error::new(ErrorKind::Other, format!("couldn't get AWS credentials: {}", e))
        });

        let bucket = self.bucket.clone();
        let response = credentials.and_then(move |credentials| {
            bucket.put(&key, data, &credentials).map_err(|e| {
                Error::new(ErrorKind::Other, format!("Error putting cache entry to S3: {:?}", e))
            })
        });

        Box::new(response.map(move |_| start.elapsed())
                         .map_err(|e| e.to_string()))
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }

    fn current_size(&self) -> Option<usize> { None }
    fn max_size(&self) -> Option<usize> { None }
}
