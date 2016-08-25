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
    CacheWriteWriter,
    Storage,
};
use simples3::{
    Bucket,
    DefaultCredentialsProviderSync,
    ProvideAwsCredentials,
    Ssl,
};
use std::io::{
    self,
    Error,
    ErrorKind,
};

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The S3 bucket.
    bucket: Bucket,
    /// Credentials provider.
    provider: Option<DefaultCredentialsProviderSync>,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(bucket: &str) -> io::Result<S3Cache> {
        let provider = DefaultCredentialsProviderSync::new().ok();
        //TODO: configurable SSL
        let bucket = Bucket::new(bucket, Ssl::No);
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

    fn finish_put(&self, key: &str, entry: CacheWrite) -> io::Result<()> {
        let writer = try!(entry.finish());
        match writer {
            // This should never happen.
            CacheWriteWriter::File(_) => Err(Error::new(ErrorKind::Other, "Bad CacheWrite?")),
            CacheWriteWriter::Cursor(c) => {
                self.provider
                    .as_ref()
                    .ok_or(Error::new(ErrorKind::Other, "No AWS credential provider available!"))
                    .and_then(|provider| provider.credentials().or(Err(Error::new(ErrorKind::Other, "Couldn't get AWS credentials!"))))
                    .and_then(|credentials| {
                        let data = c.into_inner();
                        let key = normalize_key(key);
                        self.bucket.put(&key, &data, &credentials).or(Err(Error::new(ErrorKind::Other, "Error putting cache entry to S3")))
                    })
            }
        }
    }

    fn get_location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }
}
