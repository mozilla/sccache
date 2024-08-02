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

use opendal::layers::LoggingLayer;
use opendal::raw::HttpClient;
use opendal::services::S3;
use opendal::Operator;
use reqwest::ClientBuilder;

use crate::errors::*;

pub struct S3Cache;

impl S3Cache {
    pub fn build(
        bucket: &str,
        region: Option<&str>,
        key_prefix: &str,
        no_credentials: bool,
        endpoint: Option<&str>,
        use_ssl: Option<bool>,
        server_side_encryption: Option<bool>,
    ) -> Result<Operator> {
        let mut builder = S3::default()
            .http_client(set_user_agent())
            .bucket(bucket)
            .root(key_prefix);

        if let Some(region) = region {
            builder = builder.region(region);
        }

        if no_credentials {
            builder = builder
                .disable_config_load()
                // Disable EC2 metadata to avoid OpenDAL trying to load
                // credentials from EC2 metadata.
                //
                // A.k.a, don't try to visit `http://169.254.169.254`
                .disable_ec2_metadata()
                // Allow anonymous access to S3 so that OpenDAL will not
                // throw error when no credentials are provided.
                .allow_anonymous();
        }

        if let Some(endpoint) = endpoint {
            builder = builder.endpoint(&endpoint_resolver(endpoint, use_ssl)?);
        }

        if server_side_encryption.unwrap_or_default() {
            builder = builder.server_side_encryption_with_s3_key();
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}

/// Set the user agent (helps with monitoring on the server side)
fn set_user_agent() -> HttpClient {
    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let client_builder = ClientBuilder::new().user_agent(user_agent);
    HttpClient::build(client_builder).unwrap()
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
