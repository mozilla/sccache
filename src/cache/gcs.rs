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

use std::{fmt, io, sync::Arc, time};

use crate::{
    cache::{Cache, CacheRead, CacheWrite, Storage},
    errors::*,
    util::HeadersExt,
};
use hyper::Method;
use hyperx::header::{Authorization, Bearer, ContentLength, ContentType};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::{Client, Request};
use serde::de;
use url::form_urlencoded;

/// Lifted from the url crate
/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

/// https://url.spec.whatwg.org/#path-percent-encode-set
const PATH: &AsciiSet = &FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');

const PATH_SEGMENT: &AsciiSet = &PATH.add(b'/').add(b'%');

/// https://url.spec.whatwg.org/#query-state
const QUERY: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');

/// GCS bucket
struct Bucket {
    name: String,
    client: Client,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket(name={})", self.name)
    }
}

impl Bucket {
    pub fn new(name: String) -> Result<Bucket> {
        let client = Client::new();

        Ok(Bucket { name, client })
    }

    async fn get(
        &self,
        key: &str,
        cred_provider: &Option<GCSCredentialProvider>,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "https://www.googleapis.com/download/storage/v1/b/{}/o/{}?alt=media",
            utf8_percent_encode(&self.name, PATH_SEGMENT),
            utf8_percent_encode(key, PATH_SEGMENT)
        );

        let client = self.client.clone();

        let creds_opt = if let Some(ref cred_provider) = *cred_provider {
            cred_provider
                .credentials(&self.client)
                .await
                .map_err(|err| {
                    warn!("Error getting credentials: {:?}", err);
                    err
                })
                .map(Some)?
        } else {
            None
        };

        let mut request = Request::new(Method::GET, url.parse().unwrap());
        if let Some(creds) = creds_opt {
            request
                .headers_mut()
                .set(Authorization(Bearer { token: creds.token }));
        }
        let res = client
            .execute(request)
            .await
            .with_context(|| format!("failed GET: {}", url))?;
        if res.status().is_success() {
            let bytes = res.bytes().await.context("failed to read HTTP body")?;
            Ok(bytes.into_iter().collect())
        } else {
            Err(BadHttpStatusError(res.status()).into())
        }
    }

    async fn put(
        &self,
        key: &str,
        content: Vec<u8>,
        cred_provider: &Option<GCSCredentialProvider>,
    ) -> Result<()> {
        let url = format!(
            "https://www.googleapis.com/upload/storage/v1/b/{}/o?name={}&uploadType=media",
            utf8_percent_encode(&self.name, PATH_SEGMENT),
            utf8_percent_encode(key, QUERY)
        );
        let url = url.parse().unwrap();

        let client = self.client.clone();

        let creds_opt = if let Some(ref cred_provider) = cred_provider {
            let val = cred_provider.credentials(&self.client).await?;
            Some(val)
        } else {
            None
        };

        let mut request = Request::new(Method::POST, url);
        {
            let headers = request.headers_mut();
            if let Some(creds) = creds_opt {
                headers.set(Authorization(Bearer { token: creds.token }));
            }
            headers.set(ContentType::octet_stream());
            headers.set(ContentLength(content.len() as u64));
        }
        *request.body_mut() = Some(content.into());

        match client.execute(request).await {
            Ok(res) => {
                if res.status().is_success() {
                    trace!("PUT succeeded");
                    Ok(())
                } else {
                    trace!("PUT failed with HTTP status: {}", res.status());
                    Err(BadHttpStatusError(res.status()).into())
                }
            }
            Err(e) => {
                trace!("PUT failed with error: {:?}", e);
                Err(e.into())
            }
        }
    }
}

/// GCSCredentialProvider provides GCS OAUTH tokens.
///
/// It uses service account credentials to request tokens, and caches the result so that successive
/// calls to GCS APIs don't need to request new tokens.
pub struct GCSCredentialProvider {
    rw_mode: RWMode,
    sa_info: ServiceAccountInfo,
    cached_credentials: futures_locks::Mutex<Option<GCSCredential>>,
}

/// ServiceAccountInfo either contains a URL to fetch the oauth token
/// or the service account key
pub enum ServiceAccountInfo {
    DeprecatedUrl(String),
    OAuthUrl(String),
    AccountKey(ServiceAccountKey),
}

fn deserialize_gcp_key<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private key string")
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            // -----BEGIN PRIVATE KEY-----\n<key_data_with_newlines>\n-----END PRIVATE KEY-----\n
            let key_string = v
                .split("-----")
                .nth(2)
                .ok_or_else(|| E::custom("invalid private key format"))?;

            // Strip out all of the newlines
            let key_string = key_string.split_whitespace().fold(
                String::with_capacity(key_string.len()),
                |mut s, line| {
                    s.push_str(line);
                    s
                },
            );

            base64::decode_config(key_string.as_bytes(), base64::STANDARD)
                .map_err(|e| E::custom(format!("failed to decode from base64 string: {}", e)))
        }
    }

    deserializer.deserialize_any(Visitor)
}

/// ServiceAccountKey is a subset of the information in the JSON service account credentials.
///
/// Note: by default, serde ignores extra fields when deserializing. This allows us to keep this
/// structure minimal and not list all the fields present in a service account credential file.
#[derive(Debug, Deserialize)]
pub struct ServiceAccountKey {
    #[serde(deserialize_with = "deserialize_gcp_key")]
    private_key: Vec<u8>,
    client_email: String,
    /// The URI we send the token requests to, eg https://oauth2.googleapis.com/token
    token_uri: String,
}

/// JwtClaims are the required claims that must be present in the OAUTH token request JWT.
#[derive(Serialize)]
struct JwtClaims<'a> {
    #[serde(rename = "iss")]
    issuer: &'a str,
    #[serde(rename = "aud")]
    audience: &'a str,
    #[serde(rename = "exp")]
    expiration: i64,
    #[serde(rename = "iat")]
    issued_at: i64,
    scope: &'a str,
}

/// TokenMsg is a subset of the information provided by GCS in response to an OAUTH token request.
///
/// Note: by default, serde ignores extra fields when deserializing. This allows us to keep this
/// structure minimal and not list all the fields present in the response.
#[derive(Deserialize)]
struct TokenMsg {
    access_token: String,
}

/// AuthResponse represents the json response body from taskcluster-auth.gcsCredentials endpoint
#[derive(Deserialize)]
struct DeprecatedAuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireTime")]
    expire_time: String,
}

/// AuthResponse represents the json response body from taskcluster-auth.gcsCredentials endpoint
#[derive(Deserialize)]
struct OAuthResponse {
    access_token: String,
    expires_in: i64,
}

/// RWMode describes whether or not to attempt cache writes.
#[derive(Copy, Clone)]
pub enum RWMode {
    ReadOnly,
    ReadWrite,
}

/// GCSCredential is a GCS OAUTH token paired with an expiration time.
#[derive(Clone)]
pub struct GCSCredential {
    token: String,
    expiration_time: chrono::DateTime<chrono::offset::Utc>,
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Serialize)]
struct Header<'a> {
    /// The type of JWS: it can only be "JWT" here
    ///
    /// Defined in [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    pub typ: &'a str,
    /// The algorithm used
    ///
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    pub alg: &'a str,
}

fn to_jwt_part<T: serde::Serialize>(input: &T) -> Result<String> {
    let json = serde_json::to_string(input)?;
    Ok(base64::encode_config(
        json.as_bytes(),
        base64::URL_SAFE_NO_PAD,
    ))
}

use ring::signature;

fn sign_rsa(
    signing_input: &str,
    key: &[u8],
    alg: &'static dyn signature::RsaEncoding,
) -> Result<String> {
    let key_pair =
        signature::RsaKeyPair::from_pkcs8(key).context("failed to deserialize rsa key")?;

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, signing_input.as_bytes(), &mut signature)
        .context("failed to sign JWT claim")?;

    Ok(base64::encode_config(&signature, base64::URL_SAFE_NO_PAD))
}

fn encode(header: &Header<'_>, claims: &JwtClaims<'_>, key: &[u8]) -> Result<String> {
    let encoded_header = to_jwt_part(header)?;
    let encoded_claims = to_jwt_part(claims)?;
    let signing_input = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign_rsa(&*signing_input, key, &signature::RSA_PKCS1_SHA256)?;

    Ok([signing_input, signature].join("."))
}

impl GCSCredentialProvider {
    pub fn new(rw_mode: RWMode, sa_info: ServiceAccountInfo) -> Self {
        GCSCredentialProvider {
            rw_mode,
            sa_info,
            cached_credentials: futures_locks::Mutex::new(None),
        }
    }

    fn auth_request_jwt(
        &self,
        sa_key: &ServiceAccountKey,
        expire_at: &chrono::DateTime<chrono::offset::Utc>,
    ) -> Result<String> {
        let scope = match self.rw_mode {
            RWMode::ReadOnly => "https://www.googleapis.com/auth/devstorage.readonly",
            RWMode::ReadWrite => "https://www.googleapis.com/auth/devstorage.read_write",
        };

        encode(
            &Header {
                typ: "JWT",
                alg: "RS256",
            },
            &JwtClaims {
                issuer: &sa_key.client_email,
                scope,
                audience: &sa_key.token_uri,
                expiration: expire_at.timestamp(),
                issued_at: chrono::offset::Utc::now().timestamp(),
            },
            &sa_key.private_key,
        )
    }

    async fn request_new_token(
        &self,
        sa_key: &ServiceAccountKey,
        client: &Client,
    ) -> Result<GCSCredential> {
        let expires_at = chrono::offset::Utc::now() + chrono::Duration::minutes(59);
        let auth_jwt = self.auth_request_jwt(sa_key, &expires_at)?;
        let url = sa_key.token_uri.clone();
        // Request credentials
        let params = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
            .append_pair("assertion", &auth_jwt)
            .finish();

        let mut request = Request::new(Method::POST, url.parse().unwrap());
        {
            let headers = request.headers_mut();
            headers.set(ContentType::form_url_encoded());
            headers.set(ContentLength(params.len() as u64));
        }
        *request.body_mut() = Some(params.into());

        let res = client.execute(request).await?;

        let token_msg = if res.status().is_success() {
            let token_msg = res.json::<TokenMsg>().await?;
            Ok(token_msg)
        } else {
            Err(BadHttpStatusError(res.status()))
        }?;

        Ok(GCSCredential {
            token: token_msg.access_token,
            expiration_time: expires_at,
        })
    }

    async fn request_new_token_from_tcauth(
        &self,
        url: &str,
        client: &Client,
    ) -> Result<GCSCredential> {
        let res = client.get(url).send().await?;

        if res.status().is_success() {
            let resp = res.json::<DeprecatedAuthResponse>().await?;
            Ok(GCSCredential {
                token: resp.access_token,
                expiration_time: resp.expire_time.parse()?,
            })
        } else {
            Err(BadHttpStatusError(res.status()).into())
        }
    }

    async fn request_new_token_from_oauth(
        &self,
        url: &str,
        client: &Client,
    ) -> Result<GCSCredential> {
        let res = client
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;

        if res.status().is_success() {
            let resp = res.json::<OAuthResponse>().await?;
            Ok(GCSCredential {
                token: resp.access_token,
                expiration_time: chrono::offset::Utc::now()
                    + chrono::Duration::seconds(resp.expires_in),
            })
        } else {
            Err(BadHttpStatusError(res.status()).into())
        }
    }

    pub async fn credentials(&self, client: &Client) -> Result<GCSCredential> {
        // NOTE: Only this function is responsible for managing credentials and
        // its cache; make sure we hold the lock across the yield points
        let mut cache = self.cached_credentials.lock().await;

        match *cache {
            Some(ref creds) if creds.expiration_time >= chrono::offset::Utc::now() => {
                Ok(creds.clone())
            }
            _ => {
                let new_creds = match self.sa_info {
                    ServiceAccountInfo::AccountKey(ref sa_key) => {
                        self.request_new_token(sa_key, client).await
                    }
                    ServiceAccountInfo::DeprecatedUrl(ref url) => {
                        self.request_new_token_from_tcauth(url, client).await
                    }
                    ServiceAccountInfo::OAuthUrl(ref url) => {
                        self.request_new_token_from_oauth(url, client).await
                    }
                }?;

                *cache = Some(new_creds.clone());

                Ok(new_creds)
            }
        }
    }
}

/// A cache that stores entries in Google Cloud Storage
pub struct GCSCache {
    /// The GCS bucket
    bucket: Arc<Bucket>,
    /// The key prefix
    key_prefix: String,
    /// Credential provider for GCS
    credential_provider: Option<GCSCredentialProvider>,
    /// Read-only or not
    rw_mode: RWMode,
}

impl GCSCache {
    /// Create a new `GCSCache` storing data in `bucket`
    pub fn new(
        bucket: String,
        key_prefix: String,
        credential_provider: Option<GCSCredentialProvider>,
        rw_mode: RWMode,
    ) -> Result<GCSCache> {
        Ok(GCSCache {
            bucket: Arc::new(Bucket::new(bucket)?),
            key_prefix,
            rw_mode,
            credential_provider,
        })
    }

    fn normalize_key(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", &self.key_prefix, key)
        }
    }
}

#[async_trait]
impl Storage for GCSCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        let key = self.normalize_key(key);
        match self.bucket.get(&key, &self.credential_provider).await {
            Ok(data) => {
                let hit = CacheRead::from(io::Cursor::new(data))?;
                Ok(Cache::Hit(hit))
            }
            Err(e) => {
                warn!("Got GCS error: {:?}", e);
                Ok(Cache::Miss)
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<time::Duration> {
        if let RWMode::ReadOnly = self.rw_mode {
            return Ok(time::Duration::new(0, 0));
        }

        let start = time::Instant::now();
        let data = entry.finish()?;

        let bucket = self.bucket.clone();
        let key = self.normalize_key(key);
        let _ = bucket
            .put(&key, data, &self.credential_provider)
            .await
            .context("failed to put cache entry in GCS")?;

        Ok(start.elapsed())
    }

    fn location(&self) -> String {
        format!(
            "GCS, bucket: {}, key_prefix: {}",
            self.bucket,
            if self.key_prefix.is_empty() {
                "(none)"
            } else {
                &self.key_prefix
            },
        )
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

#[tokio::test]
async fn test_gcs_credential_provider() {
    use futures::{FutureExt, TryFutureExt};
    use std::convert::Infallible;

    const EXPIRE_TIME: &str = "3000-01-01T00:00:00.0Z";
    let addr = ([127, 0, 0, 1], 3000).into();
    let make_service = hyper::service::make_service_fn(|_socket| async {
        Ok::<_, Infallible>(hyper::service::service_fn(|_request| async {
            let token = serde_json::json!({
                "accessToken": "1234567890",
                "expireTime": EXPIRE_TIME,
            });
            Ok::<_, Infallible>(hyper::Response::new(hyper::Body::from(token.to_string())))
        }))
    });

    let server = hyper::Server::bind(&addr).serve(make_service);

    let credential_provider = GCSCredentialProvider::new(
        RWMode::ReadWrite,
        ServiceAccountInfo::DeprecatedUrl("http://127.0.0.1:3000/".to_string()),
    );

    let client = Client::new();
    let cred_fut = credential_provider
        .credentials(&client)
        .map_ok(move |credential| {
            assert_eq!(credential.token, "1234567890");
            assert_eq!(
                credential.expiration_time.timestamp(),
                EXPIRE_TIME
                    .parse::<chrono::DateTime<chrono::offset::Utc>>()
                    .unwrap()
                    .timestamp(),
            );
        })
        .map_err(move |err| panic!("{}", err.to_string()));

    let _ = server.with_graceful_shutdown(cred_fut.map(drop)).await;
}

#[test]
fn normalize_key() {
    let cache = GCSCache::new(
        String::from("bucket"),
        String::from(""),
        None,
        RWMode::ReadOnly,
    )
    .unwrap();
    assert_eq!(cache.normalize_key("key"), String::from("key"));

    let cache = GCSCache::new(
        String::from("bucket"),
        String::from("prefix"),
        None,
        RWMode::ReadOnly,
    )
    .unwrap();
    assert_eq!(cache.normalize_key("key"), String::from("prefix/key"));
}

#[test]
fn location() {
    let cache = GCSCache::new(
        String::from("bucket"),
        String::from(""),
        None,
        RWMode::ReadOnly,
    )
    .unwrap();
    assert_eq!(
        cache.location(),
        String::from("GCS, bucket: Bucket(name=bucket), key_prefix: (none)")
    );

    let cache = GCSCache::new(
        String::from("bucket"),
        String::from("prefix"),
        None,
        RWMode::ReadOnly,
    )
    .unwrap();
    assert_eq!(
        cache.location(),
        String::from("GCS, bucket: Bucket(name=bucket), key_prefix: prefix")
    );
}

#[tokio::test]
async fn test_gcs_oauth_provider() {
    use futures::{FutureExt, TryFutureExt};
    use std::convert::Infallible;

    const EXPIRE_TIME: i64 = 600;
    let addr = ([127, 0, 0, 1], 3001).into();
    let make_service = hyper::service::make_service_fn(|_socket| async {
        Ok::<_, Infallible>(hyper::service::service_fn(|_request| async {
            let token = serde_json::json!({
                "access_token": "1234567890",
                "expires_in": EXPIRE_TIME,
            });
            Ok::<_, Infallible>(hyper::Response::new(hyper::Body::from(token.to_string())))
        }))
    });

    let server = hyper::Server::bind(&addr).serve(make_service);

    let credential_provider = GCSCredentialProvider::new(
        RWMode::ReadWrite,
        ServiceAccountInfo::OAuthUrl("http://127.0.0.1:3001/".to_string()),
    );

    let client = Client::new();
    let cred_fut = credential_provider
        .credentials(&client)
        .map_ok(move |credential| {
            assert_eq!(credential.token, "1234567890");
        })
        .map_err(move |err| panic!("{}", err.to_string()));

    let _ = server.with_graceful_shutdown(cred_fut.map(drop)).await;
}
