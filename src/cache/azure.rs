// Copyright 2018 Benjamin Bader
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

use opendal::Operator;

use opendal::layers::{HttpClientLayer, LoggingLayer};
use opendal::services::Azblob;
use opendal::services::Http;

use crate::errors::*;

use super::http_client::set_user_agent;

pub struct AzureBlobCache;

/// Parse the `BlobEndpoint` value from an Azure Storage connection string.
fn blob_endpoint_from_connection_string(connection_string: &str) -> Result<String> {
    for part in connection_string.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("BlobEndpoint=") {
            return Ok(value.to_string());
        }
    }
    bail!("connection string does not contain a BlobEndpoint")
}

impl AzureBlobCache {
    pub fn build(
        connection_string: &str,
        container: &str,
        key_prefix: &str,
        no_credentials: bool,
    ) -> Result<Operator> {
        if no_credentials {
            Self::build_http_readonly(connection_string, container, key_prefix)
        } else {
            Self::build_azblob(connection_string, container, key_prefix)
        }
    }

    /// Build an operator using the OpenDAL Azblob service (authenticated).
    fn build_azblob(
        connection_string: &str,
        container: &str,
        key_prefix: &str,
    ) -> Result<Operator> {
        let builder = Azblob::from_connection_string(connection_string)?
            .container(container)
            .root(key_prefix);

        let op = Operator::new(builder)?
            .layer(HttpClientLayer::new(set_user_agent()))
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }

    /// Build an operator using the OpenDAL HTTP service for anonymous
    /// read-only access. The endpoint is constructed from the connection
    /// string's `BlobEndpoint` value plus the container name, so that
    /// reads go directly to
    /// `https://<account>.blob.core.windows.net/<container>/<key>`.
    fn build_http_readonly(
        connection_string: &str,
        container: &str,
        key_prefix: &str,
    ) -> Result<Operator> {
        let blob_endpoint = blob_endpoint_from_connection_string(connection_string)?;
        let endpoint = format!("{}/{}", blob_endpoint.trim_end_matches('/'), container);

        let builder = Http::default().endpoint(&endpoint).root(key_prefix);

        let op = Operator::new(builder)?
            .layer(HttpClientLayer::new(set_user_agent()))
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_blob_endpoint() {
        let cs = "BlobEndpoint=https://myaccount.blob.core.windows.net";
        assert_eq!(
            blob_endpoint_from_connection_string(cs).unwrap(),
            "https://myaccount.blob.core.windows.net"
        );
    }

    #[test]
    fn test_parse_blob_endpoint_from_full_connection_string() {
        let cs = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123;BlobEndpoint=https://myaccount.blob.core.windows.net";
        assert_eq!(
            blob_endpoint_from_connection_string(cs).unwrap(),
            "https://myaccount.blob.core.windows.net"
        );
    }

    #[test]
    fn test_parse_blob_endpoint_missing() {
        let cs = "DefaultEndpointsProtocol=https;AccountName=myaccount";
        assert!(blob_endpoint_from_connection_string(cs).is_err());
    }
}
