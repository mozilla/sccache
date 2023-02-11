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

use crate::errors::*;
use opendal::Operator;
use opendal::{layers::LoggingLayer, services::Gcs};
use reqsign::{GoogleBuilder, GoogleToken, GoogleTokenLoad};
use url::Url;

#[derive(Copy, Clone)]
pub enum RWMode {
    ReadOnly,
    ReadWrite,
}

impl RWMode {
    fn to_scope(self) -> &'static str {
        match self {
            RWMode::ReadOnly => "https://www.googleapis.com/auth/devstorage.readonly",
            RWMode::ReadWrite => "https://www.googleapis.com/auth/devstorage.read_write",
        }
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
        rw_mode: RWMode,
        credential_url: Option<&str>,
    ) -> Result<Operator> {
        let mut builder = Gcs::default();
        builder.bucket(bucket);
        builder.root(key_prefix);

        let mut signer_builder = GoogleBuilder::default();
        signer_builder.scope(rw_mode.to_scope());
        if let Some(service_account) = service_account {
            signer_builder.service_account(service_account);
        }
        if let Some(path) = cred_path {
            signer_builder.credential_path(path);
        }
        if let Some(cred_url) = credential_url {
            let _ = Url::parse(cred_url)
                .map_err(|err| anyhow!("gcs credential url is invalid: {err:?}"))?;
            signer_builder.customed_token_loader(TaskClusterTokenLoader {
                client: reqwest::blocking::Client::default(),
                scope: rw_mode.to_scope().to_string(),
                url: cred_url.to_string(),
            });
        }
        builder.signer(signer_builder.build()?);

        let op = Operator::create(builder)?
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
#[derive(Debug)]
struct TaskClusterTokenLoader {
    client: reqwest::blocking::Client,
    scope: String,
    url: String,
}

impl GoogleTokenLoad for TaskClusterTokenLoader {
    fn load_token(&self) -> Result<Option<GoogleToken>> {
        let res = self.client.get(&self.url).send()?;

        if res.status().is_success() {
            let resp = res.json::<TaskClusterToken>()?;

            // TODO: we can parse expire time instead using hardcode 1 hour.
            Ok(Some(GoogleToken::new(
                &resp.access_token,
                3600,
                &self.scope,
            )))
        } else {
            let status_code = res.status();
            let content = res.text()?;
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
