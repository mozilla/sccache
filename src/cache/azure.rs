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

use opendal::OperationContext;
use opendal::services::Azblob;
use opendal_layer_logging::LoggingLayer;

use crate::errors::*;

use super::http_client::set_user_agent;

pub struct AzureBlobCache;

impl AzureBlobCache {
    /// Build an Azure Blob Storage operator.
    ///
    /// Two authentication paths are supported, selected by the presence of a
    /// connection string:
    ///
    /// * **Shared key (connection string)** — when `connection_string` is
    ///   `Some`, the operator is built from it, unchanged from historical
    ///   behavior.
    /// * **Microsoft Entra ID (passwordless)** — when `connection_string` is
    ///   `None`, the operator is built without any account key or SAS token, so
    ///   OpenDAL (via its bundled `reqsign` dependency) resolves credentials
    ///   from the ambient environment and signs each request with an
    ///   `Authorization: Bearer <token>` header. Supported credential sources,
    ///   in the order `reqsign` tries them: a **service principal**
    ///   (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`),
    ///   **workload identity** (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` +
    ///   `AZURE_FEDERATED_TOKEN_FILE`), then a system- or user-assigned
    ///   **managed identity** via IMDS (`AZURE_CLIENT_ID` optionally selects a
    ///   user-assigned identity). This path needs an explicit blob endpoint,
    ///   resolved from `endpoint` (validated and used as-is — for sovereign
    ///   clouds or a custom endpoint) or synthesized from `storage_account` as
    ///   `https://{account}.blob.core.windows.net`.
    pub fn build(
        connection_string: Option<&str>,
        container: &str,
        key_prefix: &str,
        storage_account: Option<&str>,
        endpoint: Option<&str>,
    ) -> Result<Operator> {
        // Normalize empty strings to absent up front so a blank value from a
        // file config (which, unlike the env parser, does not strip empties)
        // behaves like an unset field for BOTH the mutual-exclusivity check and
        // the auth-path selection below.
        let connection_string = connection_string.filter(|s| !s.is_empty());
        let storage_account = storage_account.filter(|s| !s.is_empty());
        let endpoint = endpoint.filter(|s| !s.is_empty());

        let builder = match connection_string {
            Some(connection_string) => {
                // Both the env and file config surfaces flow through here. The
                // env parser rejects this combination too, but a file config
                // bypasses that check, so enforce mutual exclusivity centrally.
                if storage_account.is_some() || endpoint.is_some() {
                    bail!(
                        "Azure cache accepts either a connection string or a storage account / endpoint (Entra ID), not both."
                    );
                }
                Azblob::from_connection_string(connection_string)?
                    .container(container)
                    .root(key_prefix)
            }
            None => {
                // Entra ID / passwordless path. Deliberately leave account_key,
                // sas_token and connection_string unset: OpenDAL then loads
                // Entra credentials (managed identity / workload identity /
                // service principal) from the environment via reqsign.
                let endpoint = resolve_blob_endpoint(endpoint, storage_account)?;
                Azblob::default()
                    .endpoint(&endpoint)
                    .container(container)
                    .root(key_prefix)
            }
        };

        let op = Operator::new(builder)?
            .with_context(OperationContext::new().with_http_transport(set_user_agent()))
            .layer(LoggingLayer::default());
        Ok(op)
    }
}

/// Resolve the Azure Blob endpoint for the Entra ID (passwordless) path.
///
/// OpenDAL's Azblob backend requires an explicit endpoint and does not derive
/// one from the account name, so callers must supply either a full `endpoint`
/// (for sovereign clouds or a custom endpoint) or a `storage_account` name from
/// which the public-cloud endpoint is synthesized. An explicit endpoint takes
/// precedence.
fn resolve_blob_endpoint(endpoint: Option<&str>, storage_account: Option<&str>) -> Result<String> {
    // Callers normalize empty strings to absent, but do so here too so this
    // function is correct in isolation (and unit-testable with blank inputs).
    let endpoint = endpoint.filter(|s| !s.is_empty());
    let storage_account = storage_account.filter(|s| !s.is_empty());
    match (endpoint, storage_account) {
        (Some(endpoint), _) => {
            let endpoint = endpoint.trim_end_matches('/');
            // The endpoint is a trust boundary: the OAuth bearer token is sent to
            // whatever host it resolves to. Validate up front so a malformed or
            // token-redirecting endpoint fails at startup with an actionable
            // message rather than at first cache access, and so the token is never
            // sent in cleartext or to an unintended host. Mirrors the S3 backend's
            // `http::Uri` endpoint validation.
            let uri: http::Uri = endpoint
                .parse()
                .map_err(|err| anyhow!("Azure endpoint `{endpoint}` is not a valid URI: {err}"))?;
            let authority = uri
                .authority()
                .ok_or_else(|| anyhow!("Azure endpoint `{endpoint}` must include a host."))?;
            // Reject `user@host` — the userinfo, not the real host, is what a
            // reader would trust, while the bearer token goes to `host`.
            if authority.as_str().contains('@') {
                bail!("Azure endpoint `{endpoint}` must not contain userinfo (`user@host`).");
            }
            let host = uri.host().unwrap_or_default();
            if host.is_empty() {
                bail!("Azure endpoint `{endpoint}` must include a host.");
            }
            // `http::Uri::host()` returns an IPv6 authority in bracketed form;
            // strip the brackets before parsing so `[::1]` (and expanded forms)
            // are recognised as loopback.
            let host_ip = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            let is_loopback = host.eq_ignore_ascii_case("localhost")
                || host_ip
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            match uri.scheme_str() {
                Some("https") => {}
                Some("http") if is_loopback => {}
                _ => bail!(
                    "Azure endpoint `{endpoint}` must use https (http is allowed only for a loopback host)."
                ),
            }
            Ok(endpoint.to_string())
        }
        (None, Some(storage_account)) => {
            // The account name is interpolated into the endpoint host, so reject
            // anything that is not a bare account name to keep it from altering
            // the host the OAuth bearer token is sent to.
            if !storage_account.chars().all(|c| c.is_ascii_alphanumeric()) {
                bail!(
                    "Azure storage account `{storage_account}` is invalid: expected only ASCII alphanumeric characters."
                );
            }
            Ok(format!("https://{storage_account}.blob.core.windows.net"))
        }
        (None, None) => bail!(
            "Azure Entra ID authentication requires a storage account or blob endpoint \
             (env `SCCACHE_AZURE_STORAGE_ACCOUNT` / `SCCACHE_AZURE_ENDPOINT`, or the \
             `storage_account` / `endpoint` config fields)."
        ),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_resolve_blob_endpoint_from_account() -> Result<()> {
        assert_eq!(
            resolve_blob_endpoint(None, Some("mystorageacct"))?,
            "https://mystorageacct.blob.core.windows.net"
        );
        Ok(())
    }

    #[test]
    fn test_resolve_blob_endpoint_explicit_wins_and_trims() -> Result<()> {
        // An explicit endpoint takes precedence over the account name, and any
        // trailing slash is trimmed (OpenDAL stores the endpoint without one).
        assert_eq!(
            resolve_blob_endpoint(
                Some("https://acct.blob.core.usgovcloudapi.net/"),
                Some("ignored")
            )?,
            "https://acct.blob.core.usgovcloudapi.net"
        );
        assert_eq!(
            resolve_blob_endpoint(Some("http://127.0.0.1:10000/devstoreaccount1"), None)?,
            "http://127.0.0.1:10000/devstoreaccount1"
        );
        Ok(())
    }

    #[test]
    fn test_resolve_blob_endpoint_requires_a_source() {
        assert!(resolve_blob_endpoint(None, None).is_err());
    }

    #[test]
    fn test_resolve_blob_endpoint_rejects_insecure_and_malformed() {
        // http against a non-loopback host would leak the OAuth bearer token in
        // cleartext, and a scheme-less value is not a usable endpoint.
        assert!(resolve_blob_endpoint(Some("http://storage.example.com"), None).is_err());
        assert!(resolve_blob_endpoint(Some("storage.example.com"), None).is_err());
        // Userinfo would send the token to `host`, not the trusted-looking prefix.
        assert!(
            resolve_blob_endpoint(
                Some("https://acct.blob.core.windows.net@evil.example"),
                None
            )
            .is_err()
        );
        // An authority with no host is not a usable endpoint.
        assert!(resolve_blob_endpoint(Some("https://:443"), None).is_err());
    }

    #[test]
    fn test_resolve_blob_endpoint_accepts_loopback_variants() {
        // Azurite / local proxies: http is allowed for every loopback spelling,
        // case-insensitively, including bracketed and expanded IPv6.
        for ep in [
            "http://127.0.0.1:10000/devstoreaccount1",
            "http://localhost:10000/devstoreaccount1",
            "http://LOCALHOST:10000/devstoreaccount1",
            "http://[::1]:10000/devstoreaccount1",
        ] {
            assert!(resolve_blob_endpoint(Some(ep), None).is_ok(), "{ep}");
        }
    }

    #[test]
    fn test_resolve_blob_endpoint_rejects_account_that_alters_host() {
        // A "storage account" carrying path/scheme separators must not be able
        // to redirect where the bearer token is sent.
        assert!(resolve_blob_endpoint(None, Some("acct/../evil")).is_err());
        assert!(resolve_blob_endpoint(None, Some("acct.evil.com")).is_err());
    }

    #[test]
    fn test_resolve_blob_endpoint_ignores_empty_strings() {
        // An empty endpoint must not shadow a valid storage account.
        assert_eq!(
            resolve_blob_endpoint(Some(""), Some("acct")).unwrap(),
            "https://acct.blob.core.windows.net"
        );
        assert!(resolve_blob_endpoint(Some(""), Some("")).is_err());
    }

    #[test]
    fn test_build_entra_path_builds_operator() {
        // No connection string + a storage account selects the Entra path. The
        // operator is constructed lazily (no network), so build() succeeds; assert
        // the wiring (scheme + container) rather than just that it did not panic.
        let op = AzureBlobCache::build(None, "container", "prefix", Some("mystorageacct"), None)
            .unwrap();
        assert_eq!(op.info().scheme(), "azblob");
        assert_eq!(op.info().name(), "container");
    }

    #[test]
    fn test_build_connection_string_path_builds_operator() {
        // AccountKey must be valid base64 (opendal validates it at build time).
        let conn = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=dGVzdGtleQ==;EndpointSuffix=core.windows.net";
        let op = AzureBlobCache::build(Some(conn), "container", "prefix", None, None).unwrap();
        assert_eq!(op.info().scheme(), "azblob");
        assert_eq!(op.info().name(), "container");
    }

    #[test]
    fn test_build_rejects_conflicting_auth_sources() {
        // Both operands of the mutual-exclusivity guard are exercised: a
        // connection string paired with a storage account, and with an endpoint.
        let err = AzureBlobCache::build(Some("conn"), "container", "prefix", Some("acct"), None)
            .unwrap_err();
        assert!(err.to_string().contains("not both"));

        let err = AzureBlobCache::build(
            Some("conn"),
            "container",
            "prefix",
            None,
            Some("https://acct.blob.core.windows.net"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not both"));
    }

    #[test]
    fn test_build_requires_an_auth_source() {
        // A container with no connection string and no Entra source: the error
        // names both the env vars and the config fields, since this branch is
        // reachable from a file config too.
        let err = AzureBlobCache::build(None, "container", "prefix", None, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("storage account or blob endpoint"), "{msg}");
    }

    #[test]
    fn test_build_blank_connection_string_falls_through_to_entra() {
        // A blank connection_string from a file config must behave as absent and
        // NOT be mistaken for a shared-key source that conflicts with the account.
        assert!(
            AzureBlobCache::build(Some(""), "container", "prefix", Some("mystorageacct"), None)
                .is_ok()
        );
    }

    #[test]
    fn test_build_blank_entra_fields_do_not_conflict_with_connection_string() {
        // Blank storage_account/endpoint from a file config must not trip the
        // mutual-exclusivity guard when a real connection string is set.
        let conn = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=dGVzdGtleQ==;EndpointSuffix=core.windows.net";
        assert!(
            AzureBlobCache::build(Some(conn), "container", "prefix", Some(""), Some("")).is_ok()
        );
    }
}
