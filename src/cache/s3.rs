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

use opendal::services::s3;
use opendal::Operator;

use crate::cache::{Cache, CacheRead, CacheWrite, Storage};
use std::convert::TryInto;
use std::io;
use std::time::{Duration, Instant};

use crate::errors::*;

pub struct S3Cache {
    client: Operator,
}

impl S3Cache {
    pub async fn new(
        bucket: &str,
        region: Option<&str>,
        key_prefix: &str,
        no_credentials: bool,
        endpoint: Option<&str>,
        use_ssl: Option<bool>,
    ) -> Result<S3Cache> {
        let mut builder = s3::Builder::default();
        builder.bucket(bucket);
        if let Some(region) = region {
            builder.region(region);
        }
        builder.root(key_prefix);
        if no_credentials {
            builder.disable_credential_loader();
        }
        if let Some(endpoint) = endpoint {
            builder.endpoint(&endpoint_resolver(endpoint, use_ssl)?);
        }

        Ok(S3Cache {
            client: builder.build()?.into(),
        })
    }
}

#[async_trait]
impl Storage for S3Cache {
    async fn get(&self, key: &str) -> Result<Cache> {
        match self.client.object(&normalize_key(key)).read().await {
            Ok(res) => {
                let hit = CacheRead::from(io::Cursor::new(res))?;
                Ok(Cache::Hit(hit))
            }
            Err(e) => {
                warn!("Got AWS error: {:?}", e);
                Ok(Cache::Miss)
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let start = Instant::now();

        self.client
            .object(&normalize_key(key))
            .write(entry.finish()?)
            .await?;

        Ok(start.elapsed())
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.client.metadata().name())
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

fn normalize_key(key: &str) -> String {
    format!("{}/{}/{}/{}", &key[0..1], &key[1..2], &key[2..3], &key)
}

/// Resolve given endpoint along with use_ssl settings.
fn endpoint_resolver(endpoint: &str, use_ssl: Option<bool>) -> Result<String> {
    let endpoint_uri: http::Uri = endpoint
        .try_into()
        .map_err(|err| anyhow!("input endpoint {endpoint} is invalid: {:?}", err))?;
    let mut parts = endpoint_uri.into_parts();
    match use_ssl {
        Some(true) => {
            parts.scheme = Some(http::uri::Scheme::HTTPS);
        }
        Some(false) => {
            parts.scheme = Some(http::uri::Scheme::HTTP);
        }
        None => {
            if parts.scheme.is_none() {
                parts.scheme = Some(http::uri::Scheme::HTTP);
            }
        }
    }
    // path_and_query is required when scheme is set
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
    }

    Ok(http::Uri::from_parts(parts)?.to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_normalize_key() {
        assert_eq!(
            normalize_key("0123456789abcdef0123456789abcdef"),
            "0/1/2/0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_endpoint_resolver() -> Result<()> {
        let cases = vec![
            (
                "no scheme without use_ssl",
                "s3-us-east-1.amazonaws.com",
                None,
                "http://s3-us-east-1.amazonaws.com/",
            ),
            (
                "http without use_ssl",
                "http://s3-us-east-1.amazonaws.com",
                None,
                "http://s3-us-east-1.amazonaws.com/",
            ),
            (
                "https without use_ssl",
                "https://s3-us-east-1.amazonaws.com",
                None,
                "https://s3-us-east-1.amazonaws.com/",
            ),
            (
                "no scheme with use_ssl",
                "s3-us-east-1.amazonaws.com",
                Some(true),
                "https://s3-us-east-1.amazonaws.com/",
            ),
            (
                "http with use_ssl",
                "http://s3-us-east-1.amazonaws.com",
                Some(true),
                "https://s3-us-east-1.amazonaws.com/",
            ),
            (
                "https with use_ssl",
                "https://s3-us-east-1.amazonaws.com",
                Some(true),
                "https://s3-us-east-1.amazonaws.com/",
            ),
            (
                "no scheme with not use_ssl",
                "s3-us-east-1.amazonaws.com",
                Some(false),
                "http://s3-us-east-1.amazonaws.com/",
            ),
            (
                "http with not use_ssl",
                "http://s3-us-east-1.amazonaws.com",
                Some(false),
                "http://s3-us-east-1.amazonaws.com/",
            ),
            (
                "https with not use_ssl",
                "https://s3-us-east-1.amazonaws.com",
                Some(false),
                "http://s3-us-east-1.amazonaws.com/",
            ),
        ];

        for (name, endpoint, use_ssl, expected) in cases {
            let actual = endpoint_resolver(endpoint, use_ssl)?;
            assert_eq!(actual, expected, "{}", name);
        }

        Ok(())
    }
}
