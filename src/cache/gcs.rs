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

use crate::{
    cache::{Cache, CacheRead, CacheWrite, Storage},
    errors::*,
    util::HeadersExt,
};
use futures::future::Shared;
use hyper::Method;
use hyperx::header::{Authorization, Bearer, ContentLength, ContentType};
use reqwest::{Client, Request};
use serde::de;
use std::{convert::Infallible, sync};
use std::{fmt, io, pin::Pin, result, sync::Arc, time};
use url::{
    form_urlencoded,
    percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET, QUERY_ENCODE_SET},
};
// use ::ReqwestRequestBuilderExt;
use futures::FutureExt;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Http error: {0}")]
    Http(#[from] crate::errors::BadHttpStatusError),

    #[error("Error: {0}")]
    Arbitrary(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Arbitrary(s.to_string())
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::Arbitrary(s.to_owned())
    }
}

impl From<reqwest::Error> for Error {
    fn from(s: reqwest::Error) -> Self {
        Self::Arbitrary(s.to_string())
    }
}

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
            percent_encode(self.name.as_bytes(), PATH_SEGMENT_ENCODE_SET),
            percent_encode(key.as_bytes(), PATH_SEGMENT_ENCODE_SET)
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
            .map_err(|_e| Error::from(format!("failed GET: {}", url)))?;
        let status = res.status();
        if status.is_success() {
            let bytes = res
                .bytes()
                .await
                .map_err(|_e| Error::from("failed to read HTTP body"))?;
            Ok(bytes.iter().copied().collect())
        } else {
            Err(BadHttpStatusError(status).into())
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
            percent_encode(self.name.as_bytes(), PATH_SEGMENT_ENCODE_SET),
            percent_encode(key.as_bytes(), QUERY_ENCODE_SET)
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
    cached_credentials: sync::RwLock<
        Option<
            Shared<
                Pin<
                    Box<
                        dyn 'static
                            + Send
                            + futures::Future<Output = result::Result<GCSCredential, Error>>,
                    >,
                >,
            >,
        >,
    >,
}

/// ServiceAccountInfo either contains a URL to fetch the oauth token
/// or the service account key
#[derive(Clone)]
pub enum ServiceAccountInfo {
    URL(String),
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
                .splitn(5, "-----")
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
#[derive(Debug, Deserialize, Clone)]
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
struct AuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireTime")]
    expire_time: String,
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
        Self {
            rw_mode,
            sa_info,
            cached_credentials: sync::RwLock::new(Option::<_>::None),
        }
    }

    fn auth_request_jwt(
        rw_mode: RWMode,
        sa_key: &ServiceAccountKey,
        expire_at: &chrono::DateTime<chrono::offset::Utc>,
    ) -> result::Result<String, Error> {
        let scope = match rw_mode {
            RWMode::ReadOnly => "https://www.googleapis.com/auth/devstorage.readonly",
            RWMode::ReadWrite => "https://www.googleapis.com/auth/devstorage.read_write",
        };

        Ok(encode(
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
        .unwrap())
    }

    async fn request_new_token(
        rw_mode: RWMode,
        sa_key: ServiceAccountKey,
        client: Client,
    ) -> result::Result<GCSCredential, Error> {
        let expires_at = chrono::offset::Utc::now() + chrono::Duration::minutes(59);

        let auth_jwt = Self::auth_request_jwt(rw_mode, &sa_key, &expires_at)?;

        let url = &sa_key.token_uri;

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

        let res = client.execute(request).await.map_err(|x| x.to_string())?;

        let res_status = res.status();
        let token_msg = if res_status.is_success() {
            let token_msg = res
                .json::<TokenMsg>()
                .await
                .map_err(|_e| "failed to read HTTP body")?;
            Ok(token_msg)
        } else {
            Err(Error::from(BadHttpStatusError(res_status)))
        }?;

        Ok(GCSCredential {
            token: token_msg.access_token,
            expiration_time: expires_at,
        })
    }

    async fn request_new_token_from_tcauth(
        url: String,
        client: Client,
    ) -> result::Result<GCSCredential, Error> {
        let res = client.get(&url).send().await?;

        if res.status().is_success() {
            let resp = res
                .json::<AuthResponse>()
                .await
                .map_err(|_e| "failed to read HTTP body")?;
            Ok(GCSCredential {
                token: resp.access_token,
                expiration_time: resp
                    .expire_time
                    .parse()
                    .map_err(|_e| "Failed to parse GCS expiration time")?,
            })
        } else {
            Err(Error::from(BadHttpStatusError(res.status())))
        }
    }

    pub async fn credentials(&self, client: &Client) -> result::Result<GCSCredential, Error> {
        let client = client.clone();
        let shared = {
            let shared = self.cached_credentials.read().unwrap();
            let shared = shared.clone();
            shared
        };
        // let sa_info = self.sa_info.clone();
        let rw_mode = self.rw_mode;
        let needs_refresh = if let Some(shared) = shared {
            // query the result of the last shared response or wait for the current ongoing
            let ret = shared.await;
            let maybe_creds = ret
                .ok()
                .filter(|creds| creds.expiration_time < chrono::offset::Utc::now());
            maybe_creds
        } else {
            None
        };

        // TODO make this better, and avoid serialized writes
        // TODO by using `futures_util::lock()` instead of `std::sync` primitives.

        let creds = if let Some(still_good) = needs_refresh {
            still_good
        } else {
            let credentials = match &self.sa_info {
                ServiceAccountInfo::AccountKey(sa_key) => {
                    Box::pin(Self::request_new_token(rw_mode, sa_key.clone(), client))
                        as Pin<
                            Box<
                                dyn 'static
                                    + Send
                                    + futures::Future<
                                        Output = result::Result<GCSCredential, Error>,
                                    >,
                            >,
                        >
                }
                ServiceAccountInfo::URL(url) => {
                    Box::pin(Self::request_new_token_from_tcauth(url.to_owned(), client))
                        as Pin<
                            Box<
                                dyn 'static
                                    + Send
                                    + futures::Future<
                                        Output = result::Result<GCSCredential, Error>,
                                    >,
                            >,
                        >
                }
            };
            let credentials = credentials.shared();
            {
                let mut write = self.cached_credentials.write().unwrap();
                *write = Some(credentials.clone());
            }
            let creds = credentials.await?;
            creds
        };

        Ok(creds)
    }
}

/// A cache that stores entries in Google Cloud Storage
pub struct GCSCache {
    /// The GCS bucket
    bucket: Arc<Bucket>,
    /// Credential provider for GCS
    credential_provider: Option<GCSCredentialProvider>,
    /// Read-only or not
    rw_mode: RWMode,
}

impl GCSCache {
    /// Create a new `GCSCache` storing data in `bucket`
    pub fn new(
        bucket: String,
        credential_provider: Option<GCSCredentialProvider>,
        rw_mode: RWMode,
    ) -> Result<GCSCache> {
        Ok(GCSCache {
            bucket: Arc::new(Bucket::new(bucket)?),
            rw_mode,
            credential_provider,
        })
    }
}

#[async_trait]
impl Storage for GCSCache {
    async fn get(&self, key: &str) -> Result<Cache> {
        self.bucket
            .get(&key, &self.credential_provider)
            .await
            .and_then(|data| Ok(Cache::Hit(CacheRead::from(io::Cursor::new(data))?)))
            .or_else(|e| {
                warn!("Got GCS error: {:?}", e);
                Ok(Cache::Miss)
            })
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<time::Duration> {
        if let RWMode::ReadOnly = self.rw_mode {
            return Ok(time::Duration::new(0, 0));
        }

        let start = time::Instant::now();
        let data = entry.finish()?;

        let bucket = self.bucket.clone();
        let response = bucket
            .put(&key, data, &self.credential_provider)
            .await
            .context("failed to put cache entry in GCS");

        response.map(move |_| start.elapsed())
    }

    fn location(&self) -> String {
        format!("GCS, bucket: {}", self.bucket)
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

use futures::TryFutureExt;

#[test]
fn test_gcs_credential_provider() {
    const EXPIRE_TIME: &str = "3000-01-01T00:00:00.0Z";
    let addr = ([127, 0, 0, 1], 23535).into();
    let make_service =
    hyper::service::make_service_fn(|_socket| async move {
        Ok::<_, Infallible>(hyper::service::service_fn(|_request| async move{
            let token = serde_json::json!({
                "accessToken": "secr3t",
                "expireTime": EXPIRE_TIME,
            });
            Ok::<_, Infallible>(hyper::Response::new(hyper::Body::from(token.to_string())))
        }))
    });


    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let fut = async move {
    let server = hyper::Server::bind(&addr).serve(make_service);

    let credential_provider = GCSCredentialProvider::new(
        RWMode::ReadWrite,
        ServiceAccountInfo::URL(format!("http://{}/", addr)),
    );

    let client = Client::new();
    let cred_fut = credential_provider
        .credentials(&client)
        .map(move |credential| {
            if let Err(err) = credential.map(|credential| {
                assert_eq!(credential.token, "secr3t");
                assert_eq!(
                    credential.expiration_time.timestamp(),
                    EXPIRE_TIME
                        .parse::<chrono::DateTime<chrono::offset::Utc>>()
                        .unwrap()
                        .timestamp(),
                );
            }) {
                panic!(err.to_string());
            }
        });
        server.with_graceful_shutdown(cred_fut).await;
    };

    rt.block_on(fut);
}
