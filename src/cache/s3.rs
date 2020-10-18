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
use futures::future;
use futures::future::Future;
use futures_03::{compat::Compat as _, future::TryFutureExt as _};
use hyperx::header::CacheDirective;
use rusoto_core::{self, Client, HttpClient, Region};
use rusoto_s3::{GetObjectOutput, GetObjectRequest, PutObjectRequest, S3Client, S3 as _};
use std::io;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio_02::io::AsyncReadExt as _;

use crate::errors::*;

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The name of the bucket.
    bucket_name: String,
    /// The S3 client to be used for the Get and Put requests.
    client: S3Client,
    /// Prefix to be used for bucket keys.
    key_prefix: String,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(
        bucket: &str,
        region: Option<&str>,
        endpoint: Option<&str>,
        key_prefix: &str,
        public: bool,
    ) -> Result<S3Cache> {
        let region = match endpoint {
            Some(endpoint) => Region::Custom {
                name: region
                    .map(ToOwned::to_owned)
                    .unwrap_or(Region::default().name().to_owned()),
                endpoint: endpoint.to_owned(),
            },
            None => region
                .map(FromStr::from_str)
                .unwrap_or_else(|| Ok(Region::default()))?,
        };

        //we could define our own Annonymous StaticProvider here, but we'd have to verify that the DefaultCredentialsProvider would fail first.
        let client = if public {
            let client = Client::new_not_signing(
                HttpClient::new().expect("failed to create request dispatcher"),
            );
            S3Client::new_with_client(client, region)
        } else {
            S3Client::new(region)
        };

        Ok(S3Cache {
            bucket_name: bucket.to_owned(),
            client,
            key_prefix: key_prefix.to_owned(),
        })
    }

    async fn get_object(client: S3Client, request: GetObjectRequest) -> Result<Cache> {
        let result = client.get_object(request).await;
        match result {
            Ok(output) => Self::read_object_output(output).await,
            Err(rusoto_core::RusotoError::Service(rusoto_s3::GetObjectError::NoSuchKey(_))) => {
                Ok(Cache::Miss)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn read_object_output(output: GetObjectOutput) -> Result<Cache> {
        let body = output.body.context("no HTTP body")?;
        let mut body_reader = body.into_async_read();
        let mut body = Vec::new();
        body_reader
            .read_to_end(&mut body)
            .await
            .context("failed to read HTTP body")?;
        let hit = CacheRead::from(io::Cursor::new(body))?;
        Ok(Cache::Hit(hit))
    }

    async fn put_object(client: S3Client, request: PutObjectRequest) -> Result<()> {
        client
            .put_object(request)
            .await
            .map(|_| ())
            .context("failed to put cache entry in s3")
            .into()
    }

    fn normalize_key(&self, key: &str) -> String {
        format!(
            "{}{}/{}/{}/{}",
            &self.key_prefix,
            &key[0..1],
            &key[1..2],
            &key[2..3],
            &key
        )
    }
}

impl Storage for S3Cache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        let key = self.normalize_key(key);

        let client = self.client.clone();
        let request = GetObjectRequest {
            bucket: self.bucket_name.clone(),
            key,
            ..Default::default()
        };

        Box::new(Box::pin(Self::get_object(client, request)).compat())
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let key = self.normalize_key(&key);
        let start = Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return f_err(e),
        };
        let data_length = data.len();

        let client = self.client.clone();
        let request = PutObjectRequest {
            bucket: self.bucket_name.clone(),
            body: Some(data.into()),
            // Two weeks
            cache_control: Some(CacheDirective::MaxAge(1_296_000).to_string()),
            content_length: Some(data_length as i64),
            content_type: Some("application/octet-stream".to_owned()),
            key,
            ..Default::default()
        };

        Box::new(
            Box::pin(Self::put_object(client, request))
                .compat()
                .then(move |_| future::ok(start.elapsed())),
        )
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.bucket_name)
    }

    fn current_size(&self) -> SFuture<Option<u64>> {
        Box::new(future::ok(None))
    }
    fn max_size(&self) -> SFuture<Option<u64>> {
        Box::new(future::ok(None))
    }
}
