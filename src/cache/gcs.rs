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
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use opendal::Operator;
use opendal::{OperationContext, services::Gcs};
use opendal_layer_logging::LoggingLayer;
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

        let env_cred_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
            .ok()
            .filter(|s| !s.is_empty());
        if let Some(path) = cred_path.or(env_cred_path.as_deref()) {
            builder = match credential_with_default_format(path) {
                Some(credential) => builder.credential(&credential),
                None => builder.credential_path(path),
            };
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
            .with_context(OperationContext::new().with_http_transport(set_user_agent()))
            .layer(LoggingLayer::default());
        Ok(op)
    }
}

// Default omitted file/URL formats to text per AIP-4117 until OpenDAL ships
// the reqsign-google fix:
// https://github.com/apache/reqsign/pull/910
fn credential_with_default_format(path: &str) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    let mut credential: serde_json::Value = serde_json::from_slice(&content).ok()?;
    if credential.get("type")?.as_str()? != "external_account" {
        return None;
    }
    let source = credential.get_mut("credential_source")?.as_object_mut()?;
    if source.contains_key("format")
        || source.contains_key("environment_id")
        || !(source.contains_key("file") || source.contains_key("url"))
    {
        return None;
    }
    source.insert("format".to_owned(), serde_json::json!({"type": "text"}));
    Some(BASE64_STANDARD.encode(serde_json::to_vec(&credential).ok()?))
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

#[cfg(test)]
mod tests {
    use super::*;
    use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FederationTransport {
        subject_token: String,
        scope: &'static str,
        exchanges: Arc<AtomicUsize>,
    }

    impl HttpTransport for FederationTransport {
        async fn fetch(
            &self,
            req: http::Request<Buffer>,
        ) -> opendal::Result<http::Response<HttpBody>> {
            let (status, body) = match req.uri().to_string().as_str() {
                "https://issuer.example/token" => {
                    assert_eq!(req.method(), http::Method::GET);
                    assert_eq!(req.headers()["x-test-identity"], "test-identity");
                    (200, self.subject_token.clone())
                }
                "https://sts.googleapis.com/v1/token" => {
                    assert_eq!(req.method(), http::Method::POST);
                    let body = req.body().to_bytes();
                    let form: HashMap<_, _> = url::form_urlencoded::parse(&body).collect();
                    assert_eq!(form["subject_token"], "test-subject-token");
                    assert_eq!(form["scope"], self.scope);
                    assert_eq!(
                        form["grant_type"],
                        "urn:ietf:params:oauth:grant-type:token-exchange"
                    );
                    self.exchanges.fetch_add(1, Ordering::SeqCst);
                    (
                        200,
                        json!({
                            "access_token": "test-access-token",
                            "token_type": "Bearer",
                            "expires_in": 3600
                        })
                        .to_string(),
                    )
                }
                url if url.starts_with("https://storage.googleapis.com/") => {
                    assert_eq!(req.headers()["authorization"], "Bearer test-access-token");
                    (404, String::new())
                }
                url => panic!("unexpected request, including credential fallback: {url}"),
            };
            let size = body.len() as u64;
            let stream = futures::stream::iter([Ok(Buffer::from(body))]);
            Ok(http::Response::builder()
                .status(status)
                .body(HttpBody::new(stream, Some(size)))
                .unwrap())
        }
    }

    async fn check_external_account(
        source_type: &str,
        format: Option<serde_json::Value>,
        credentials_from_env: bool,
    ) {
        for mode in [CacheMode::ReadOnly, CacheMode::ReadWrite] {
            let dir = tempfile::tempdir().unwrap();
            let token_path = dir.path().join("subject-token");
            let subject_token = if format.as_ref().and_then(|f| f["type"].as_str()) == Some("json")
            {
                json!({"id_token": "test-subject-token"}).to_string()
            } else {
                "test-subject-token\n".to_owned()
            };
            std::fs::write(&token_path, &subject_token).unwrap();
            let mut source = match source_type {
                "file" => json!({"file": token_path}),
                "url" => json!({
                    "url": "https://issuer.example/token",
                    "headers": {"x-test-identity": "test-identity"}
                }),
                _ => unreachable!(),
            };
            if let Some(format) = &format {
                source["format"] = format.clone();
            }
            let credential = json!({
                "type": "external_account",
                "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/test/providers/test",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_url": "https://sts.googleapis.com/v1/token",
                "credential_source": source
            })
            .to_string();
            let credential_path = dir.path().join("external-account.json");
            std::fs::write(&credential_path, &credential).unwrap();
            // An explicit credential path must take precedence over the environment.
            let (env_paths, key_path) = if credentials_from_env {
                (vec![Some(credential_path.clone())], None)
            } else {
                (
                    vec![
                        Some(dir.path().join("unused-credentials.json")),
                        Some("".into()),
                        None,
                    ],
                    credential_path.to_str(),
                )
            };
            for env_path in env_paths {
                let exchanges = Arc::new(AtomicUsize::new(0));
                let op = temp_env::with_var("GOOGLE_APPLICATION_CREDENTIALS", env_path, || {
                    GCSCache::build("test-bucket", "", key_path, None, mode, None)
                })
                .unwrap()
                .with_context(
                    OperationContext::new().with_http_transport(HttpTransporter::new(
                        FederationTransport {
                            subject_token: subject_token.clone(),
                            scope: rw_to_scope(mode),
                            exchanges: exchanges.clone(),
                        },
                    )),
                );

                for _ in 0..2 {
                    let err = op.read(".sccache_check").await.unwrap_err();
                    assert_eq!(err.kind(), opendal::ErrorKind::NotFound, "{err:?}");
                }
                // Repeated requests reuse the exchanged access token.
                assert_eq!(exchanges.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[test]
    fn test_credential_with_default_format_leaves_other_credentials_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential.json");
        assert!(credential_with_default_format(path.to_str().unwrap()).is_none());
        for credential in [
            "not json".to_owned(),
            json!({"type": "service_account", "private_key": "unchanged"}).to_string(),
            json!({"type": "authorized_user", "refresh_token": "unchanged"}).to_string(),
            json!({"type": "external_account"}).to_string(),
        ] {
            std::fs::write(&path, credential).unwrap();
            assert!(credential_with_default_format(path.to_str().unwrap()).is_none());
        }
        for source in [
            json!({"file": "token", "format": {"type": "text"}}),
            json!({"url": "https://issuer.example/token", "format": {
                "type": "json", "subject_token_field_name": "id_token"
            }}),
            json!({"file": "token", "format": null}),
            json!({"file": "token", "format": {}}),
            json!({"file": "token", "format": {"type": "invalid"}}),
            json!({"environment_id": "aws1", "url": "http://169.254.169.254"}),
            json!({"executable": {"command": "get-token"}}),
            json!({}),
        ] {
            let credential = json!({
                "type": "external_account",
                "credential_source": source
            });
            std::fs::write(&path, credential.to_string()).unwrap();
            assert!(
                credential_with_default_format(path.to_str().unwrap()).is_none(),
                "{credential}"
            );
        }
    }

    #[tokio::test]
    async fn test_external_account_file_without_format() {
        check_external_account("file", None, false).await;
    }

    #[tokio::test]
    async fn test_external_account_url_without_format() {
        check_external_account("url", None, false).await;
    }

    #[tokio::test]
    async fn test_external_account_file_without_format_from_env() {
        check_external_account("file", None, true).await;
    }

    #[tokio::test]
    async fn test_external_account_url_without_format_from_env() {
        check_external_account("url", None, true).await;
    }

    #[tokio::test]
    async fn test_external_account_explicit_formats() {
        for source_type in ["file", "url"] {
            for format in [
                json!({"type": "text"}),
                json!({"type": "json", "subject_token_field_name": "id_token"}),
            ] {
                for credentials_from_env in [false, true] {
                    check_external_account(source_type, Some(format.clone()), credentials_from_env)
                        .await;
                }
            }
        }
    }
}
