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
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::errors::*;

/// A cache that stores entries in Amazon S3.
pub struct S3Cache {
    /// The S3 bucket.
    bucket: Arc<Bucket>,
    /// Credentials provider.
    provider: AutoRefreshingProvider<ChainProvider>,
    /// Prefix to be used for bucket keys.
    key_prefix: String,
}

impl S3Cache {
    /// Create a new `S3Cache` storing data in `bucket`.
    pub fn new(bucket: &str, endpoint: &str, use_ssl: bool, key_prefix: &str) -> Result<S3Cache> {
        let user_dirs = UserDirs::new().context("Couldn't get user directories")?;
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
        let bucket = Arc::new(Bucket::new(bucket, endpoint, ssl_mode)?);
        Ok(S3Cache {
            bucket,
            provider,
            key_prefix: key_prefix.to_owned(),
        })
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

#[async_trait]
impl Storage for S3Cache {
    async fn get(&self, key: &str) -> Result<Cache> {
        let key = self.normalize_key(key);

        let credentials = self.provider.credentials().await;
        let result = match credentials {
            Ok(creds) => self.bucket.get(&key, Some(&creds)).await,
            Err(e) => {
                debug!("Could not load AWS creds: {}", e);
                self.bucket.get(&key, None).await
            }
        };

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
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let key = self.normalize_key(key);
        let start = Instant::now();
        let data = entry.finish()?;

        let credentials = self
            .provider
            .credentials()
            .await
            .context("failed to get AWS credentials")?;

        let bucket = self.bucket.clone();
        let _ = bucket
            .put(&key, data, &credentials)
            .await
            .context("failed to put cache entry in s3")?;

        Ok(start.elapsed())
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.bucket)
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}
