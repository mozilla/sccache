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

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::middleware::DefaultMiddleware;
use aws_sdk_s3::operation::{GetObject, PutObject};
use aws_sdk_s3::output::{GetObjectOutput, PutObjectOutput};
use aws_sdk_s3::{Config, Endpoint, Region};
use aws_sig_auth::signer::{OperationSigningConfig, SigningRequirements};
use aws_smithy_client::erase::DynConnector;

use crate::cache::{Cache, CacheRead, CacheWrite, Storage};
use std::convert::TryInto;
use std::io;
use std::time::{Duration, Instant};

use crate::errors::*;

pub struct S3Cache {
    client: S3Client,
    no_credentials: bool,
    key_prefix: String,
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
        Ok(S3Cache {
            key_prefix: key_prefix.to_owned(),
            no_credentials,
            client: S3Client::new(bucket, region, endpoint, use_ssl).await?,
        })
    }
}

#[async_trait]
impl Storage for S3Cache {
    async fn get(&self, key: &str) -> Result<Cache> {
        let response = self
            .client
            .get_object(&normalize_key(&self.key_prefix, key), self.no_credentials)
            .await;

        match response {
            Ok(res) => {
                let hit = CacheRead::from(io::Cursor::new(res.body.collect().await?.into_bytes()))?;
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
            .put_object(&normalize_key(&self.key_prefix, key), entry.finish()?)
            .await?;

        Ok(start.elapsed())
    }

    fn location(&self) -> String {
        format!("S3, bucket: {}", self.client.bucket)
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

fn normalize_key(prefix: &str, key: &str) -> String {
    format!(
        "{}{}/{}/{}/{}",
        prefix,
        &key[0..1],
        &key[1..2],
        &key[2..3],
        &key
    )
}

fn endpoint_resolver(endpoint: &str, use_ssl: Option<bool>) -> Endpoint {
    let endpoint_uri: http::Uri = endpoint.try_into().unwrap();
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
    Endpoint::mutable(http::Uri::from_parts(parts).unwrap())
}

struct S3Client {
    client: aws_smithy_client::Client<DynConnector, DefaultMiddleware>,
    bucket: String,
    config: Config,
}

impl S3Client {
    async fn new(
        bucket: &str,
        region: Option<&str>,
        endpoint: Option<&str>,
        use_ssl: Option<bool>,
    ) -> Result<S3Client> {
        let region_provider =
            RegionProviderChain::first_try(region.map(|r| Region::new(r.to_owned())))
                .or_default_provider();

        let shared_config = aws_config::from_env().region(region_provider).load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared_config);
        if let Some(endpoint) = endpoint {
            builder = builder.endpoint_resolver(endpoint_resolver(endpoint, use_ssl));
        }
        let config = builder.build();

        // Keep the client around for connection reuse
        let client = aws_smithy_client::Builder::new()
            .dyn_https_connector(
                aws_smithy_client::http_connector::ConnectorSettings::builder().build(),
            )
            .middleware(DefaultMiddleware::new())
            .build();

        Ok(S3Client {
            client,
            bucket: bucket.to_owned(),
            config,
        })
    }

    async fn get_object(&self, key: &str, no_credentials: bool) -> Result<GetObjectOutput> {
        let mut op = GetObject::builder()
            .bucket(&self.bucket)
            .key(key)
            .build()
            .unwrap()
            .make_operation(&self.config)
            .await?;

        if no_credentials {
            let mut signing_config = OperationSigningConfig::default_config();
            signing_config.signing_requirements = SigningRequirements::Disabled;
            op.properties_mut().insert(signing_config);
        }

        Ok(self.client.call(op).await?)
    }

    async fn put_object(&self, key: &str, data: Vec<u8>) -> Result<PutObjectOutput> {
        let op = PutObject::builder()
            .bucket(&self.bucket)
            .key(key)
            .body(data.into())
            .build()
            .unwrap()
            .make_operation(&self.config)
            .await?;

        Ok(self.client.call(op).await?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_normalize_key() {
        assert_eq!(
            normalize_key("prefix", "0123456789abcdef0123456789abcdef"),
            "prefix0/1/2/0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            normalize_key("prefix/", "0123456789abcdef0123456789abcdef"),
            "prefix/0/1/2/0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_endpoint_resolver() {
        let endpoint = endpoint_resolver("s3-us-east-1.amazonaws.com", None);
        assert_eq!(endpoint.uri().scheme_str(), Some("http"));

        let endpoint = endpoint_resolver("s3-us-east-1.amazonaws.com", Some(true));
        assert_eq!(endpoint.uri().scheme_str(), Some("https"));

        let endpoint = endpoint_resolver("s3-us-east-1.amazonaws.com", Some(false));
        assert_eq!(endpoint.uri().scheme_str(), Some("http"));
    }
}
