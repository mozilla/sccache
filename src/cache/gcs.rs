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

use std::{cell::RefCell, fmt, io, rc::Rc, time};

use crate::{
    cache::{Cache, CacheRead, CacheWrite, Storage},
    errors::*,
    util::HeadersExt,
};
use futures::{
    future::{self, Shared},
    Async, Future, Stream,
};
use hyper::Method;
use hyperx::header::{Authorization, Bearer, ContentLength, ContentType};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::r#async::{Client, Request};
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

    fn get(&self, key: &str, cred_provider: &Option<GCSCredentialProvider>) -> SFuture<Vec<u8>> {
        let url = format!(
            "https://www.googleapis.com/download/storage/v1/b/{}/o/{}?alt=media",
            utf8_percent_encode(&self.name, PATH_SEGMENT),
            utf8_percent_encode(key, PATH_SEGMENT)
        );

        let client = self.client.clone();

        let creds_opt_future = if let Some(ref cred_provider) = *cred_provider {
            future::Either::A(
                cred_provider
                    .credentials(&self.client)
                    .map_err(|err| {
                        warn!("Error getting credentials: {:?}", err);
                        err
                    })
                    .map(Some),
            )
        } else {
            future::Either::B(future::ok(None))
        };

        Box::new(creds_opt_future.and_then(move |creds_opt| {
            let mut request = Request::new(Method::GET, url.parse().unwrap());
            if let Some(creds) = creds_opt {
                request
                    .headers_mut()
                    .set(Authorization(Bearer { token: creds.token }));
            }
            client
                .execute(request)
                .fwith_context(move || format!("failed GET: {}", url))
                .and_then(|res| {
                    if res.status().is_success() {
                        Ok(res.into_body())
                    } else {
                        Err(BadHttpStatusError(res.status()).into())
                    }
                })
                .and_then(|body| {
                    body.fold(Vec::new(), |mut body, chunk| {
                        body.extend_from_slice(&chunk);
                        Ok::<_, reqwest::Error>(body)
                    })
                    .fcontext("failed to read HTTP body")
                })
        }))
    }

    fn put(
        &self,
        key: &str,
        content: Vec<u8>,
        cred_provider: &Option<GCSCredentialProvider>,
    ) -> SFuture<()> {
        let url = format!(
            "https://www.googleapis.com/upload/storage/v1/b/{}/o?name={}&uploadType=media",
            utf8_percent_encode(&self.name, PATH_SEGMENT),
            utf8_percent_encode(key, QUERY)
        );

        let client = self.client.clone();

        let creds_opt_future = if let Some(ref cred_provider) = cred_provider {
            future::Either::A(cred_provider.credentials(&self.client).map(Some))
        } else {
            future::Either::B(future::ok(None))
        };

        Box::new(creds_opt_future.and_then(move |creds_opt| {
            let mut request = Request::new(Method::POST, url.parse().unwrap());
            {
                let headers = request.headers_mut();
                if let Some(creds) = creds_opt {
                    headers.set(Authorization(Bearer { token: creds.token }));
                }
                headers.set(ContentType::octet_stream());
                headers.set(ContentLength(content.len() as u64));
            }
            *request.body_mut() = Some(content.into());

            client.execute(request).then(|result| match result {
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
            })
        }))
    }
}

/// GCSCredentialProvider provides GCS OAUTH tokens.
///
/// It uses service account credentials to request tokens, and caches the result so that successive
/// calls to GCS APIs don't need to request new tokens.
pub struct GCSCredentialProvider {
    rw_mode: RWMode,
    sa_info: ServiceAccountInfo,
    cached_credentials: RefCell<Option<Shared<SFuture<GCSCredential>>>>,
}

/// ServiceAccountInfo either contains a URL to fetch the oauth token
/// or the service account key
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
        GCSCredentialProvider {
            rw_mode,
            sa_info,
            cached_credentials: RefCell::new(None),
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

    fn request_new_token(
        &self,
        sa_key: &ServiceAccountKey,
        client: &Client,
    ) -> SFuture<GCSCredential> {
        let client = client.clone();
        let expires_at = chrono::offset::Utc::now() + chrono::Duration::minutes(59);
        let auth_jwt = self.auth_request_jwt(sa_key, &expires_at);
        let url = sa_key.token_uri.clone();

        // Request credentials
        Box::new(
            future::result(auth_jwt)
                .and_then(move |auth_jwt| {
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

                    client.execute(request).map_err(Into::into)
                })
                .and_then(move |res| {
                    if res.status().is_success() {
                        Ok(res.into_body())
                    } else {
                        Err(BadHttpStatusError(res.status()).into())
                    }
                })
                .and_then(move |body| {
                    // Concatenate body chunks into a single Vec<u8>
                    body.fold(Vec::new(), |mut body, chunk| {
                        body.extend_from_slice(&chunk);
                        Ok::<_, reqwest::Error>(body)
                    })
                    .fcontext("failed to read HTTP body")
                })
                .and_then(move |body| {
                    // Convert body to string and parse the token out of the response
                    let body_str = String::from_utf8(body)?;
                    let token_msg: TokenMsg = serde_json::from_str(&body_str)?;

                    Ok(GCSCredential {
                        token: token_msg.access_token,
                        expiration_time: expires_at,
                    })
                }),
        )
    }

    fn request_new_token_from_tcauth(&self, url: &str, client: &Client) -> SFuture<GCSCredential> {
        Box::new(
            client
                .get(url)
                .send()
                .map_err(Into::into)
                .and_then(move |res| {
                    if res.status().is_success() {
                        Ok(res.into_body())
                    } else {
                        Err(BadHttpStatusError(res.status()).into())
                    }
                })
                .and_then(move |body| {
                    body.fold(Vec::new(), |mut body, chunk| {
                        body.extend_from_slice(&chunk);
                        Ok::<_, reqwest::Error>(body)
                    })
                    .fcontext("failed to read HTTP body")
                })
                .and_then(move |body| {
                    let body_str = String::from_utf8(body)?;
                    let resp: AuthResponse = serde_json::from_str(&body_str)?;
                    Ok(GCSCredential {
                        token: resp.access_token,
                        expiration_time: resp.expire_time.parse()?,
                    })
                }),
        )
    }

    pub fn credentials(&self, client: &Client) -> SFuture<GCSCredential> {
        let mut future_opt = self.cached_credentials.borrow_mut();

        let needs_refresh = match Option::as_mut(&mut future_opt).map(|f| f.poll()) {
            None => true,
            Some(Ok(Async::Ready(ref creds))) => creds.expiration_time < chrono::offset::Utc::now(),
            _ => false,
        };

        if needs_refresh {
            let credentials = match self.sa_info {
                ServiceAccountInfo::AccountKey(ref sa_key) => {
                    self.request_new_token(sa_key, client)
                }
                ServiceAccountInfo::URL(ref url) => self.request_new_token_from_tcauth(url, client),
            };
            *future_opt = Some(credentials.shared());
        };

        Box::new(
            Option::as_mut(&mut future_opt)
                .unwrap()
                .clone()
                .then(|result| match result {
                    Ok(e) => Ok((*e).clone()),
                    Err(e) => Err(anyhow!(e.to_string())),
                }),
        )
    }
}

/// A cache that stores entries in Google Cloud Storage
pub struct GCSCache {
    /// The GCS bucket
    bucket: Rc<Bucket>,
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
            bucket: Rc::new(Bucket::new(bucket)?),
            rw_mode,
            credential_provider,
        })
    }
}

impl Storage for GCSCache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        Box::new(
            self.bucket
                .get(&key, &self.credential_provider)
                .then(|result| match result {
                    Ok(data) => {
                        let hit = CacheRead::from(io::Cursor::new(data))?;
                        Ok(Cache::Hit(hit))
                    }
                    Err(e) => {
                        warn!("Got GCS error: {:?}", e);
                        Ok(Cache::Miss)
                    }
                }),
        )
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<time::Duration> {
        if let RWMode::ReadOnly = self.rw_mode {
            return Box::new(future::ok(time::Duration::new(0, 0)));
        }

        let start = time::Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return Box::new(future::err(e)),
        };
        let bucket = self.bucket.clone();
        let response = bucket
            .put(&key, data, &self.credential_provider)
            .fcontext("failed to put cache entry in GCS");

        Box::new(response.map(move |_| start.elapsed()))
    }

    fn location(&self) -> String {
        format!("GCS, bucket: {}", self.bucket)
    }

    fn current_size(&self) -> SFuture<Option<u64>> {
        Box::new(future::ok(None))
    }
    fn max_size(&self) -> SFuture<Option<u64>> {
        Box::new(future::ok(None))
    }
}

#[test]
fn test_gcs_credential_provider() {
    const EXPIRE_TIME: &str = "3000-01-01T00:00:00.0Z";
    let addr = ([127, 0, 0, 1], 3000).into();
    let make_service = || {
        hyper::service::service_fn_ok(|_| {
            let token = serde_json::json!({
                "accessToken": "1234567890",
                "expireTime": EXPIRE_TIME,
            });
            hyper::Response::new(hyper::Body::from(token.to_string()))
        })
    };

    let server = hyper::Server::bind(&addr).serve(make_service);

    let credential_provider = GCSCredentialProvider::new(
        RWMode::ReadWrite,
        ServiceAccountInfo::URL("http://127.0.0.1:3000/".to_string()),
    );

    let client = Client::new();
    let cred_fut = credential_provider
        .credentials(&client)
        .map(move |credential| {
            assert_eq!(credential.token, "1234567890");
            assert_eq!(
                credential.expiration_time.timestamp(),
                EXPIRE_TIME
                    .parse::<chrono::DateTime<chrono::offset::Utc>>()
                    .unwrap()
                    .timestamp(),
            );
        })
        .map_err(move |err| panic!(err.to_string()));

    server.with_graceful_shutdown(cred_fut);
}
