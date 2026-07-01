// Copyright 2017 Mozilla Foundation
// Copyright 2017 Google Inc.
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

use crate::cache::CacheMode;
use crate::errors::*;
use opendal::Operator;
use opendal::{
    layers::{HttpClientLayer, LoggingLayer},
    services::Gcs,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use url::Url;

use super::http_client::set_user_agent;

fn rw_to_scope(mode: CacheMode) -> &'static str {
    match mode {
        CacheMode::ReadOnly => "https://www.googleapis.com/auth/devstorage.read_only",
        CacheMode::ReadWrite => "https://www.googleapis.com/auth/devstorage.read_write",
    }
}

/// A cache that stores entries in Google Cloud Storage
pub struct GCSCache;

impl GCSCache {
    /// Create a new `GCSCache` storing data in `bucket`
    pub fn build(
        bucket: &str,
        key_prefix: &str,
        cred_path: Option<&str>,
        service_account: Option<&str>,
        rw_mode: CacheMode,
        credential_url: Option<&str>,
    ) -> Result<Operator> {
        let mut builder = Gcs::default()
            .bucket(bucket)
            .root(key_prefix)
            .scope(rw_to_scope(rw_mode));

        if let Some(service_account) = service_account {
            builder = builder.service_account(service_account);
        }

        if let Some(path) = cred_path {
            if let Some(token) = load_authorized_user_token(path)? {
                builder = builder.token(token);
            } else {
                builder = builder.credential_path(path);
            }
        }

        if let Some(cred_url) = credential_url {
            let _ = Url::parse(cred_url)
                .map_err(|err| anyhow!("gcs credential url is invalid: {err:?}"))?;

            // For TaskCluster integration, fetch token directly and provide it to OpenDAL
            let token = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| anyhow!("Failed to create runtime for token fetch: {e}"))?
                .block_on(fetch_taskcluster_token(cred_url, rw_to_scope(rw_mode)))
                .map_err(|e| anyhow!("Failed to fetch TaskCluster token: {e}"))?;
            builder = builder.token(token);
        }

        let op = Operator::new(builder)?
            .layer(HttpClientLayer::new(set_user_agent()))
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}

fn load_authorized_user_token(path: &str) -> Result<Option<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read gcs credential file {path:?}"))?;

    let credential: GoogleCredentialFile = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse gcs credential file {path:?}"))?;

    let GoogleCredentialFile::AuthorizedUser {
        client_id,
        client_secret,
        refresh_token,
        token_uri,
    } = credential
    else {
        return Ok(None);
    };

    let token_uri = token_uri
        .as_deref()
        .unwrap_or("https://oauth2.googleapis.com/token");

    debug!("gcs: loading access token from authorized_user credential");
    let token = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("Failed to create runtime for Google ADC token fetch: {e}"))?
        .block_on(fetch_authorized_user_token(
            token_uri,
            &client_id,
            &client_secret,
            &refresh_token,
        ))
        .map_err(|e| anyhow!("Failed to fetch Google ADC access token: {e}"))?;

    Ok(Some(token))
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum GoogleCredentialFile {
    #[serde(rename = "authorized_user")]
    AuthorizedUser {
        client_id: String,
        client_secret: String,
        refresh_token: String,
        token_uri: Option<String>,
    },
    #[serde(other)]
    Other,
}

async fn fetch_authorized_user_token(
    token_uri: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<String> {
    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let client = Client::builder().user_agent(user_agent).build()?;

    let res = client
        .post(token_uri)
        .form(&AuthorizedUserTokenRequest {
            client_id,
            client_secret,
            refresh_token,
            grant_type: "refresh_token",
        })
        .send()
        .await?;

    if res.status().is_success() {
        let resp = res.json::<AuthorizedUserToken>().await?;
        debug!("gcs: authorized_user token load succeeded");
        Ok(resp.access_token)
    } else {
        let status_code = res.status();
        let content = res.text().await?;
        Err(anyhow!(
            "authorized_user token load failed: code: {status_code}, {content}"
        ))
    }
}

#[derive(Serialize)]
struct AuthorizedUserTokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    refresh_token: &'a str,
    grant_type: &'a str,
}

#[derive(Deserialize)]
struct AuthorizedUserToken {
    access_token: String,
}

/// Fetch token from TaskCluster for GCS authentication
///
/// This feature is required to run [mozilla's CI](https://searchfox.org/mozilla-central/source/build/mozconfig.cache#67-84):
///
/// ```txt
/// export SCCACHE_GCS_CREDENTIALS_URL=http://taskcluster/auth/v1/gcp/credentials/$SCCACHE_GCS_PROJECT/${bucket}@$SCCACHE_GCS_PROJECT.iam.gserviceaccount.com"
/// ```
///
/// Reference: [gcpCredentials](https://docs.taskcluster.net/docs/reference/platform/auth/api#gcpCredentials)
async fn fetch_taskcluster_token(url: &str, scope: &str) -> Result<String> {
    debug!("gcs: start to load token from: {}", url);

    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let client = Client::builder().user_agent(user_agent).build()?;
    let res = client.get(url).send().await?;

    if res.status().is_success() {
        let resp = res.json::<TaskClusterToken>().await?;
        debug!("gcs: token load succeeded for scope: {}", scope);
        Ok(resp.access_token)
    } else {
        let status_code = res.status();
        let content = res.text().await?;
        Err(anyhow!(
            "token load failed for: code: {status_code}, {content}"
        ))
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all(deserialize = "camelCase"))]
struct TaskClusterToken {
    access_token: String,
    expire_time: String,
}
