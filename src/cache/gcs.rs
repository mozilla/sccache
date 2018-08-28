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

use std::cell::RefCell;
use std::fmt;
use std::io;
use std::rc::Rc;
use std::time;

use cache::{
    Cache,
    CacheRead,
    CacheWrite,
    Storage,
};
use chrono;
use futures::future::Shared;
use futures::{future, Async, Future, Stream};
use hyper::header::{Authorization, Bearer, ContentType, ContentLength};
use hyper::Method;
use reqwest;
use reqwest::unstable::async::{Request, Client};
use jwt;
use openssl;
use serde_json;
use tokio_core::reactor::Handle;
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET, QUERY_ENCODE_SET};

use errors::*;

/// GCS bucket
struct Bucket {
    name: String,
    client: Client,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bucket(name={})", self.name)
    }
}

impl Bucket {
    pub fn new(name: String, handle: &Handle) -> Result<Bucket> {
        let client = Client::new(handle);

        Ok(Bucket { name, client })
    }

    fn get(&self, key: &str, cred_provider: &Option<GCSCredentialProvider>) -> SFuture<Vec<u8>> {
        let url = format!("https://www.googleapis.com/download/storage/v1/b/{}/o/{}?alt=media",
                    percent_encode(self.name.as_bytes(), PATH_SEGMENT_ENCODE_SET),
                    percent_encode(key.as_bytes(), PATH_SEGMENT_ENCODE_SET));

        let client = self.client.clone();

        let creds_opt_future = if let &Some(ref cred_provider) = cred_provider {
            future::Either::A(cred_provider.credentials(&self.client).map(Some))
        } else {
            future::Either::B(future::ok(None))
        };

        Box::new(creds_opt_future.and_then(move |creds_opt| {
            let mut request = Request::new(Method::Get, url.parse().unwrap());
            if let Some(creds) = creds_opt {
                request.headers_mut()
                    .set(Authorization(Bearer { token: creds.token }));
            }
            client.execute(request).chain_err(move || {
                format!("failed GET: {}", url)
            }).and_then(|res| {
                if res.status().is_success() {
                    Ok(res.into_body())
                } else {
                    Err(ErrorKind::BadHTTPStatus(res.status().clone()).into())
                }
            }).and_then(|body| {
                body.fold(Vec::new(), |mut body, chunk| {
                    body.extend_from_slice(&chunk);
                    Ok::<_, reqwest::Error>(body)
                }).chain_err(|| {
                    "failed to read HTTP body"
                })
            })
        }))
    }

    fn put(&self, key: &str, content: Vec<u8>, cred_provider: &Option<GCSCredentialProvider>) -> SFuture<()> {
        let url = format!("https://www.googleapis.com/upload/storage/v1/b/{}/o?name={}&uploadType=media",
                    percent_encode(self.name.as_bytes(), PATH_SEGMENT_ENCODE_SET),
                    percent_encode(key.as_bytes(), QUERY_ENCODE_SET));

        let client = self.client.clone();

        let creds_opt_future = if let &Some(ref cred_provider) = cred_provider {
            future::Either::A(cred_provider.credentials(&self.client).map(Some))
        } else {
            future::Either::B(future::ok(None))
        };

        Box::new(creds_opt_future.and_then(move |creds_opt| {
            let mut request = Request::new(Method::Post, url.parse().unwrap());
            {
                let headers = request.headers_mut();
                if let Some(creds) = creds_opt {
                    headers.set(Authorization(Bearer { token: creds.token }));
                }
                headers.set(ContentType::octet_stream());
                headers.set(ContentLength(content.len() as u64));
            }
            *request.body_mut() = Some(content.into());

            client.execute(request).then(|result| {
                match result {
                    Ok(res) => {
                        if res.status().is_success() {
                            trace!("PUT succeeded");
                            Ok(())
                        } else {
                            trace!("PUT failed with HTTP status: {}", res.status());
                            Err(ErrorKind::BadHTTPStatus(res.status().clone()).into())
                        }
                    }
                    Err(e) => {
                        trace!("PUT failed with error: {:?}", e);
                        Err(e.into())
                    }
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
    sa_key: ServiceAccountKey,
    cached_credentials: RefCell<Option<Shared<SFuture<GCSCredential>>>>,
}

/// ServiceAccountKey is a subset of the information in the JSON service account credentials.
///
/// Note: by default, serde ignores extra fields when deserializing. This allows us to keep this
/// structure minimal and not list all the fields present in a service account credential file.
#[derive(Debug, Deserialize)]
pub struct ServiceAccountKey {
    private_key: String,
    client_email: String,
}

/// JwtClaims are the required claims that must be present in the OAUTH token request JWT.
#[derive(Serialize)]
struct JwtClaims {
    #[serde(rename = "iss")]
    issuer: String,
    scope: String,
    #[serde(rename = "aud")]
    audience: String,
    #[serde(rename = "exp")]
    expiration: i64,
    #[serde(rename = "iat")]
    issued_at: i64,
}

/// TokenMsg is a subset of the information provided by GCS in response to an OAUTH token request.
///
/// Note: by default, serde ignores extra fields when deserializing. This allows us to keep this
/// structure minimal and not list all the fields present in the response.
#[derive(Deserialize)]
struct TokenMsg {
    access_token: String,
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

impl GCSCredentialProvider {
    pub fn new(rw_mode: RWMode, sa_key: ServiceAccountKey) -> Self {
        GCSCredentialProvider {
            rw_mode,
            sa_key,
            cached_credentials: RefCell::new(None),
        }
    }

    fn auth_request_jwt(&self, expire_at: &chrono::DateTime<chrono::offset::Utc>) -> Result<String> {
        let scope = (match self.rw_mode {
            RWMode::ReadOnly => "https://www.googleapis.com/auth/devstorage.readonly",
            RWMode::ReadWrite => "https://www.googleapis.com/auth/devstorage.read_write",
        }).to_owned();

        let jwt_claims = JwtClaims {
            issuer: self.sa_key.client_email.clone(),
            scope: scope,
            audience: "https://www.googleapis.com/oauth2/v4/token".to_owned(),
            expiration: expire_at.timestamp(),
            issued_at: chrono::offset::Utc::now().timestamp(),
        };

        let binary_key = openssl::rsa::Rsa::private_key_from_pem(
            self.sa_key.private_key.as_bytes()
        )?.private_key_to_der()?;

        let auth_request_jwt = jwt::encode(
            &jwt::Header::new(jwt::Algorithm::RS256),
            &jwt_claims,
            &binary_key,
        )?;

        Ok(auth_request_jwt)
    }

    fn request_new_token(&self, client: &Client) -> SFuture<GCSCredential> {
        let client = client.clone();
        let expires_at = chrono::offset::Utc::now() + chrono::Duration::minutes(59);
        let auth_jwt = self.auth_request_jwt(&expires_at);

        // Request credentials
        Box::new(future::result(auth_jwt).and_then(move |auth_jwt| {
            let url = "https://www.googleapis.com/oauth2/v4/token";
            let params = form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .append_pair("assertion", &auth_jwt)
                .finish();

            let mut request = Request::new(Method::Post, url.parse().unwrap());
            {
                let headers = request.headers_mut();
                headers.set(ContentType::form_url_encoded());
                headers.set(ContentLength(params.len() as u64));
            }
            *request.body_mut() = Some(params.into());

            client.execute(request).map_err(Into::into)
        }).and_then(move |res| {
            if res.status().is_success() {
                Ok(res.into_body())
            } else {
                Err(ErrorKind::BadHTTPStatus(res.status().clone()).into())
            }
        }).and_then(move |body| {
            // Concatenate body chunks into a single Vec<u8>
            body.fold(Vec::new(), |mut body, chunk| {
                body.extend_from_slice(&chunk);
                Ok::<_, reqwest::Error>(body)
            }).chain_err(|| {
                "failed to read HTTP body"
            })
        }).and_then(move |body| {
            // Convert body to string and parse the token out of the response
            let body_str = String::from_utf8(body)?;
            let token_msg: TokenMsg = serde_json::from_str(&body_str)?;
            Ok(GCSCredential {
                token: token_msg.access_token,
                expiration_time: expires_at,
            })
        }))
    }

    pub fn credentials(&self, client: &Client) -> SFuture<GCSCredential> {
        let mut future_opt = self.cached_credentials.borrow_mut();

        let needs_refresh = match Option::as_mut(&mut future_opt).map(|f| f.poll()) {
            None => true,
            Some(Ok(Async::Ready(ref creds))) => creds.expiration_time < chrono::offset::Utc::now(),
            _ => false
        };

        if needs_refresh {
            let credentials = self.request_new_token(client);
            *future_opt = Some(credentials.shared());
        };

        Box::new(Option::as_mut(&mut future_opt).unwrap().clone().then(|result| {
            match result {
                Ok(e) => Ok((*e).clone()),
                Err(e) => Err(e.to_string().into()),
            }
        }))
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
    pub fn new(bucket: String,
               credential_provider: Option<GCSCredentialProvider>,
               rw_mode: RWMode,
               handle: &Handle) -> Result<GCSCache>
    {
        Ok(GCSCache {
            bucket: Rc::new(Bucket::new(bucket, handle)?),
            rw_mode: rw_mode,
            credential_provider: credential_provider,
        })
    }
}

impl Storage for GCSCache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        Box::new(self.bucket.get(&key, &self.credential_provider).then(|result| {
            match result {
                Ok(data) => {
                    let hit = CacheRead::from(io::Cursor::new(data))?;
                    Ok(Cache::Hit(hit))
                }
                Err(e) => {
                    warn!("Got GCS error: {:?}", e);
                    Ok(Cache::Miss)
                }
            }
        }))
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<time::Duration> {
        if let RWMode::ReadOnly = self.rw_mode {
            return Box::new(future::ok(time::Duration::new(0, 0)));
        }

        let start = time::Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return Box::new(future::err(e.into())),
        };
        let bucket = self.bucket.clone();
        let response = bucket.put(&key, data, &self.credential_provider).chain_err(|| {
            "failed to put cache entry in GCS"
        });

        Box::new(response.map(move |_| start.elapsed()))
    }

    fn location(&self) -> String {
        format!("GCS, bucket: {}", self.bucket)
    }

    fn current_size(&self) -> SFuture<Option<u64>> { Box::new(future::ok(None)) }
    fn max_size(&self) -> SFuture<Option<u64>> { Box::new(future::ok(None)) }
}
