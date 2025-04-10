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

use crate::cache::{CacheMode, TimestampUpdater, normalize_key};
use crate::errors::*;
use async_trait::async_trait;
use opendal::Operator;
use opendal::{layers::LoggingLayer, services::Gcs};
use reqsign::{GoogleCredentialLoader,
              GoogleToken,
              GoogleTokenLoad,
              GoogleTokenLoader,
              GoogleSigner,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
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
            .scope(rw_to_scope(rw_mode))
            .http_client(set_user_agent());

        if let Some(service_account) = service_account {
            builder = builder.service_account(service_account);
        }

        if let Some(path) = cred_path {
            builder = builder.credential_path(path);
        }

        if let Some(cred_url) = credential_url {
            let _ = Url::parse(cred_url)
                .map_err(|err| anyhow!("gcs credential url is invalid: {err:?}"))?;

            builder = builder.customized_token_loader(Box::new(TaskClusterTokenLoader {
                scope: rw_to_scope(rw_mode).to_string(),
                url: cred_url.to_string(),
            }));
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }

}

/// An updater that updates entries in Google Cloud Storage with a custom
/// timestamp.
pub struct GCSCustomTimeUpdater {
    bucket: String,
    key_prefix: String,
    cred_path: Option<String>,
    service_account: Option<String>,
    rw_mode: CacheMode,
    credential_url: Option<String>,

    client: reqwest::Client,
    signer: GoogleSigner,
    token: Option<GoogleToken>,
    token_last_loaded_at: Option<chrono::DateTime<chrono::Utc>>
}

impl GCSCustomTimeUpdater {
    pub fn new (
        bucket: &str,
        key_prefix: &str,
        cred_path: Option<&str>,
        service_account: Option<&str>,
        rw_mode: CacheMode,
        credential_url: Option<&str>,
    ) -> Self {
        GCSCustomTimeUpdater {
            bucket: bucket.to_string(),
            key_prefix: key_prefix.to_string(),
            cred_path: cred_path.map(|s| s.to_string()),
            service_account: service_account.map(|s| s.to_string()),
            rw_mode,
            credential_url: credential_url.map(|s| s.to_string()),

            client: reqwest::Client::new(),
            signer: GoogleSigner::new("storage"),
            token: None,
            token_last_loaded_at: None,
        }
    }

    /// Initializes the request token that will be used to update the cache
    /// hits, as the API requires authenticated requests.
    pub async fn init(&mut self) -> Result<()> {
        match self.load_token().await {
            Ok(t) => {
                self.token = Some(t);
                self.token_last_loaded_at = Some(chrono::Utc::now());
            }
            Err(err) => {
                error!("failed to load token: {err}");
                return Err(anyhow!("gcs: failed to load token"));
            }
        }

        Ok(())
    }

    /// Loads a new token using the Google Cloud API for the timestamp update
    /// requests.
    async fn load_token(&mut self) -> Result<GoogleToken> {
        if let Some(cred_url) = &self.credential_url {
            let _ = Url::parse(cred_url)
                .map_err(|err| anyhow!("gcs credential url is invalid: {err:?}"))?;

            let tc_loader = TaskClusterTokenLoader {
                scope: rw_to_scope(self.rw_mode).to_string(),
                url: cred_url.to_string(),
            };

            if let Ok(Some(tok)) = tc_loader.load(self.client.clone()).await {
                return Ok(tok)
            }
        }

        if let Some(cred_path) = &self.cred_path {
            let cred_loader = GoogleCredentialLoader::default()
                .with_disable_env()
                .with_disable_well_known_location()
                .with_path(cred_path);
            let creds = cred_loader.load()?.unwrap();

            let mut token_loader = GoogleTokenLoader::new(
                    // devstorage.full_control is required to use the metadata PATCH
                    "https://www.googleapis.com/auth/devstorage.full_control",
                    Client::new())
                .with_credentials(creds);
            if let Some(srv_account) = &self.service_account {
                token_loader = token_loader.with_service_account(srv_account);
            }

            if let Some(token_) = token_loader.load().await? {
                return Ok(token_);
            }
        }

        error!("failed to load credential token: no valid cases");
        Err(anyhow!("gcs: failed to load credential token: no valid cases"))
    }
}

/// In raw API requests, `/` in paths must be URL-encoded.
fn encode_key_to_api_path(key: String) -> String {
    key.replace("/", "%2F")
}

#[async_trait]
impl TimestampUpdater for GCSCustomTimeUpdater {
    fn can_update(&self) -> bool {
        // Assume no rights to update metadata if the user may only read the
        // cache.
        CacheMode::from(self.rw_mode.clone()) == CacheMode::ReadWrite
    }

    async fn needs_init(&self) -> Result<bool> {
        if !self.can_update() {
            return Ok(false);
        }

        if self.token.is_none() || self.token_last_loaded_at.is_none() {
            debug!("needs initialization because a token was never loaded");
            return Ok(true);
        }

        if (chrono::Utc::now() - self.token_last_loaded_at.as_ref().unwrap())
                .num_seconds() > 3600 {
            // Google Cloud tokens are valid for 3600 seconds by default.
            // Unfortunately, reqsign explicitly forbids querying the otherwise
            // available `expires_in` field from the `Token`...
            debug!("needs reinitialization because the token likely expired");
            return Ok(true);
        }

        Ok(false)
    }

    async fn init(&mut self) -> Result<()> {
        self.init().await
    }

    // Update the `CustomTime` timestamp for an object in the cache through
    // [the API](https://cloud.google.com/storage/docs/metadata#custom-time).
    //
    // `CustomTime` can only grow incrementally. In case an error is reported
    // because someone else set a time ahead of us, the error is silently
    // ignored.
    async fn update(&self, key: &str) -> Result<()> {
        if !self.can_update() {
            return Err(anyhow!("gcs: update timestamp is not supported for a read-only cache"));
        }

        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            self.bucket,
            encode_key_to_api_path(self.key_prefix.clone() + &normalize_key(key))
        );
        let payload = json!({
            "customTime": chrono::Utc::now().to_rfc3339(),
        });
        let mut request = self.client.patch(&url).json(&payload).build()?;
        self.signer.sign(&mut request, self.token.as_ref().unwrap())?;

        let resp = self.client.execute(request).await?;
        if !resp.status().is_success() {
            let status_code = resp.status();
            let content = resp.text().await?;

            if status_code == reqwest::StatusCode::BAD_REQUEST &&
                    content.contains("Custom time cannot be decreased.") {
                // Do not report custom time changes as an error, the local
                // clock may be out of sync with another sccache server using
                // the same cache.
                return Ok(());
            }

            return Err(anyhow!(
                "gcs: failed to update timestamp for {key}: code: {status_code}, {content}"
            ));
        }

        Ok(())
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
#[derive(Debug)]
struct TaskClusterTokenLoader {
    scope: String,
    url: String,
}

#[async_trait::async_trait]
impl GoogleTokenLoad for TaskClusterTokenLoader {
    async fn load(&self, client: Client) -> Result<Option<GoogleToken>> {
        debug!("gcs: start to load token from: {}", &self.url);

        let res = client.get(&self.url).send().await?;

        if res.status().is_success() {
            let resp = res.json::<TaskClusterToken>().await?;

            debug!("gcs: token load succeeded for scope: {}", &self.scope);

            // TODO: we can parse expire time instead using hardcode 1 hour.
            Ok(Some(GoogleToken::new(
                &resp.access_token,
                3600,
                &self.scope,
            )))
        } else {
            let status_code = res.status();
            let content = res.text().await?;
            Err(anyhow!(
                "token load failed for: code: {status_code}, {content}"
            ))
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all(deserialize = "camelCase"))]
struct TaskClusterToken {
    access_token: String,
    expire_time: String,
}
