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

use std::env::*;

use crate::errors::*;

#[derive(Clone, Debug)]
pub struct AzureCredentials {
    blob_endpoint: String,
    account_name: String,
    /// Account key can be omitted to enable anonymous reads.
    account_key: Option<String>,
    container_name: String,
}

impl AzureCredentials {
    pub fn new(
        blob_endpoint: &str,
        account_name: &str,
        account_key: Option<String>,
        container_name: String,
    ) -> AzureCredentials {
        let endpoint = if blob_endpoint.ends_with('/') {
            blob_endpoint.to_owned()
        } else {
            blob_endpoint.to_owned() + "/"
        };

        AzureCredentials {
            blob_endpoint: endpoint,
            account_name: account_name.to_owned(),
            account_key,
            container_name,
        }
    }

    pub fn azure_blob_endpoint(&self) -> &str {
        &self.blob_endpoint
    }

    pub fn azure_account_name(&self) -> &str {
        &self.account_name
    }

    pub fn azure_account_key(&self) -> &Option<String> {
        &self.account_key
    }

    pub fn blob_container_name(&self) -> &str {
        &self.container_name
    }
}

pub fn credentials_from_environment() -> Result<AzureCredentials> {
    let env_conn_str = var("SCCACHE_AZURE_CONNECTION_STRING")
        .context("No SCCACHE_AZURE_CONNECTION_STRING in environment")?;

    let container_name = var("SCCACHE_AZURE_BLOB_CONTAINER")
        .context("No SCCACHE_AZURE_BLOB_CONTAINER in environment")?;

    parse_connection_string(&env_conn_str, container_name)
}

fn parse_connection_string(conn: &str, container_name: String) -> Result<AzureCredentials> {
    let mut blob_endpoint = String::default();
    let mut default_endpoint_protocol: String = "https".to_owned();
    let mut account_name = String::default();
    let mut account_key = None;
    let mut endpoint_suffix = String::default();

    let split = conn.split(';');
    for part in split {
        if part.starts_with("BlobEndpoint=") {
            blob_endpoint = substr(part, "BlobEndpoint=".len()).to_owned();
            continue;
        }

        if part.starts_with("DefaultEndpointsProtocol=") {
            default_endpoint_protocol = substr(part, "DefaultEndpointsProtocol=".len()).to_owned();
            continue;
        }

        if part.starts_with("AccountName=") {
            account_name = substr(part, "AccountName=".len()).to_owned();
            continue;
        }

        if part.starts_with("AccountKey=") {
            account_key = Some(substr(part, "AccountKey=".len()).to_owned());
            continue;
        }

        if part.starts_with("EndpointSuffix=") {
            endpoint_suffix = substr(part, "EndpointSuffix=".len()).to_owned();
        }
    }

    if blob_endpoint.is_empty() {
        if !endpoint_suffix.is_empty() && !account_name.is_empty() {
            let protocol = if default_endpoint_protocol.is_empty() {
                "https".to_owned()
            } else {
                default_endpoint_protocol.clone()
            };

            blob_endpoint = format!("{}://{}.blob.{}/", protocol, account_name, endpoint_suffix);
        } else {
            bail!("Can not infer blob endpoint; connection string is missing BlobEndpoint, AccountName, and/or EndpointSuffix.");
        }
    }

    if blob_endpoint.is_empty() || account_name.is_empty() {
        bail!("Azure connection string missing at least one of BlobEndpoint (or DefaultEndpointProtocol and EndpointSuffix), or AccountName.");
    }

    if !blob_endpoint.starts_with("http") {
        blob_endpoint = format!("{}://{}", default_endpoint_protocol, blob_endpoint);
    }

    Ok(AzureCredentials::new(
        &blob_endpoint,
        &account_name,
        account_key,
        container_name,
    ))
}

fn substr(text: &str, to_skip: usize) -> &str {
    // This isn't a proper character-aware substring, but since
    // we always know that connection-strings are ASCII (we _do_ know that,
    // right?), we can get away with assuming that one char == one byte.
    &text[to_skip..]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_connection_string() {
        let conn = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;";

        let creds = parse_connection_string(conn, "container".to_string()).unwrap();
        assert_eq!(
            "http://127.0.0.1:10000/devstoreaccount1/",
            creds.azure_blob_endpoint()
        );
        assert_eq!("devstoreaccount1", creds.azure_account_name());
        assert_eq!("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==", creds.azure_account_key().as_ref().unwrap());
        assert_eq!("container", creds.blob_container_name());
    }

    #[test]
    fn test_parse_connection_string_without_account_key() {
        let conn = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;";

        let creds = parse_connection_string(conn, "container".to_string()).unwrap();
        assert_eq!(
            "http://127.0.0.1:10000/devstoreaccount1/",
            creds.azure_blob_endpoint()
        );
        assert_eq!("devstoreaccount1", creds.azure_account_name());
        assert!(creds.azure_account_key().is_none());
        assert_eq!("container", creds.blob_container_name());
    }

    #[test]
    fn conn_str_with_endpoint_suffix_only() {
        let conn = "DefaultEndpointsProtocol=https;AccountName=foo;EndpointSuffix=core.windows.net;AccountKey=bar;";
        let creds = parse_connection_string(conn, "container".to_string()).unwrap();

        assert_eq!(
            "https://foo.blob.core.windows.net/",
            creds.azure_blob_endpoint()
        );
        assert_eq!("foo", creds.azure_account_name());
        assert_eq!("bar", creds.azure_account_key().as_ref().unwrap());
    }

    #[test]
    fn conn_str_with_empty_endpoints_protocol() {
        let conn = "DefaultEndpointsProtocol=;AccountName=foo;EndpointSuffix=core.windows.net;AccountKey=bar;";
        let creds = parse_connection_string(conn, "container".to_string()).unwrap();

        assert_eq!(
            "https://foo.blob.core.windows.net/",
            creds.azure_blob_endpoint()
        );
        assert_eq!("foo", creds.azure_account_name());
        assert_eq!("bar", creds.azure_account_key().as_ref().unwrap());
    }

    #[test]
    fn conn_str_without_blob_endpoint_and_endpoint_suffix_and_account_name() {
        let conn = "";
        let err = parse_connection_string(conn, "container".to_string()).unwrap_err();
        assert_eq!("Can not infer blob endpoint; connection string is missing BlobEndpoint, AccountName, and/or EndpointSuffix.", err.to_string());
    }

    #[test]
    fn conn_str_without_account_name() {
        let conn =
            "DefaultEndpointsProtocol=http;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;";
        let err = parse_connection_string(conn, "container".to_string()).unwrap_err();
        assert_eq!("Azure connection string missing at least one of BlobEndpoint (or DefaultEndpointProtocol and EndpointSuffix), or AccountName.", err.to_string());
    }

    #[test]
    fn conn_str_blob_endpoint_non_http() {
        let conn = "DefaultEndpointsProtocol=ws;AccountName=devstoreaccount1;BlobEndpoint=127.0.0.1:10000/devstoreaccount1;";
        let creds = parse_connection_string(conn, "container".to_string()).unwrap();

        assert_eq!(
            "ws://127.0.0.1:10000/devstoreaccount1/",
            creds.azure_blob_endpoint()
        );
        assert_eq!("devstoreaccount1", creds.azure_account_name());
    }
}
