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
use rusoto::{DefaultCredentialsProviderSync, Region};
use rusoto::s3::{
    CannedAcl,
    GetObjectOutput,
    PutObjectRequest,
    S3Helper,
};
use std::io::{
    self,
    Error,
    ErrorKind,
};
use std::str::FromStr;

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The S3 client.
    s3: S3Helper<DefaultCredentialsProviderSync>,
    /// The S3 region in use.
    region: String,
    /// The S3 bucket in use.
    bucket: String,
}

impl S3Cache {
    /// Create a new `S3Cache` in AWS region `region` (i.e. 'us-east-1'), storing data in `bucket`.
    pub fn new(region: &str, bucket: &str) -> io::Result<S3Cache> {
        let r = try!(Region::from_str(region).or_else(|e| Err(Error::new(ErrorKind::Other, e))));
        let provider = try!(DefaultCredentialsProviderSync::new().or_else(|e| Err(Error::new(ErrorKind::Other, e))));
        let s3 = S3Helper::new(provider, r);
        Ok(S3Cache {
            s3: s3,
            region: region.to_owned(),
            bucket: bucket.to_owned(),
        })
    }
}

fn normalize_key(key: &str) -> String {
    format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key[3..])
}

impl Storage for S3Cache {
    fn get(&self, key: &str) -> Cache {
        let key = normalize_key(key);
        match self.s3.get_object(&self.bucket, &key) {
            Ok(GetObjectOutput { body, .. }) => {
                CacheRead::from(io::Cursor::new(body))
                    .map(Cache::Hit)
                    // This should only happen if the cached data
                    // is bad.
                    .unwrap_or_else(Cache::Error)
            }
            Err(e) => {
                // rusoto doesn't provide a way to discern between
                // 404 and other errors, so just log it and consider
                // it a cache miss.
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
                let data = c.into_inner();
                let mut request = PutObjectRequest {
                    key: normalize_key(key),
                    bucket: self.bucket.clone(),
                    body: Some(&data),
                    storage_class: Some(String::from("REDUCED_REDUNDANCY")),
                    acl: Some(CannedAcl::PublicRead),
                    // XXX: put_object_request doesn't handle cache_control
                    // https://github.com/rusoto/rusoto/issues/303
                    // two weeks
                    cache_control: Some(String::from("max-age=1296000")),
                    .. Default::default()
                };
                try!(self.s3.put_object_with_request(&mut request).or(Err(Error::new(ErrorKind::Other, "Error putting cache entry to S3"))));
                Ok(())
            }
        }
    }

    fn get_location(&self) -> String {
        format!("S3, region: {}, bucket: {}", self.region, self.bucket)
    }
}
