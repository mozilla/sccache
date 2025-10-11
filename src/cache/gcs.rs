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
use serde::Deserialize;
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
            builder = builder.credential_path(path);
        }

        if let Some(cred_url) = credential_url {
            let _ = Url::parse(cred_url)
                .map_err(|err| anyhow!("gcs credential url is invalid: {err:?}"))?;

            // For TaskCluster integration, fetch token directly and provide it to OpenDAL
            let token = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(fetch_taskcluster_token(cred_url, rw_to_scope(rw_mode)))
            })
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

/// TaskClusterTokenLoeader is used to load tokens from [TaskCluster](https://taskcluster.net/)
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
