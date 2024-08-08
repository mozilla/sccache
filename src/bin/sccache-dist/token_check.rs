use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::Engine;
use sccache::dist::http::{ClientAuthCheck, ClientVisibleMsg};
use sccache::util::{BASE64_URL_SAFE_ENGINE, new_reqwest_client};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::result::Result as StdResult;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// https://auth0.com/docs/jwks
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    kty: String,
    n: String,
    e: String,
}

impl Jwk {
    // https://github.com/lawliet89/biscuit/issues/96#issuecomment-399149872
    pub fn to_der_pkcs1(&self) -> Result<Vec<u8>> {
        if self.kty != "RSA" {
            bail!("Cannot handle non-RSA JWK")
        }

        // JWK is big-endian, openssl bignum from_slice is big-endian
        let n = BASE64_URL_SAFE_ENGINE
            .decode(&self.n)
            .context("Failed to base64 decode n")?;
        let e = BASE64_URL_SAFE_ENGINE
            .decode(&self.e)
            .context("Failed to base64 decode e")?;
        let n_bn = openssl::bn::BigNum::from_slice(&n)
            .context("Failed to create openssl bignum from n")?;
        let e_bn = openssl::bn::BigNum::from_slice(&e)
            .context("Failed to create openssl bignum from e")?;
        let pubkey = openssl::rsa::Rsa::from_public_components(n_bn, e_bn)
            .context("Failed to create pubkey from n and e")?;
        let der: Vec<u8> = pubkey
            .public_key_to_der_pkcs1()
            .context("Failed to convert public key to der pkcs1")?;
        Ok(der)
    }
}

// Check a token is equal to a fixed string
pub struct EqCheck {
    s: String,
}

#[async_trait]
impl ClientAuthCheck for EqCheck {
    async fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        if self.s == token {
            Ok(())
        } else {
            warn!("User token {} != expected token {}", token, self.s);
            Err(ClientVisibleMsg::from_nonsensitive(
                "Fixed token mismatch".to_owned(),
            ))
        }
    }
}

impl EqCheck {
    pub fn new(s: String) -> Self {
        Self { s }
    }
}

// Don't check a token is valid (it may not even be a JWT) just forward it to
// an API and check for success
pub struct ProxyTokenCheck {
    client: reqwest::Client,
    maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>>,
    url: String,
}

#[async_trait]
impl ClientAuthCheck for ProxyTokenCheck {
    async fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_token_with_forwarding(token).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("Proxying token validation failed: {}", e);
                Err(ClientVisibleMsg::from_nonsensitive(
                    "Validation with token forwarding failed".to_owned(),
                ))
            }
        }
    }
}

impl ProxyTokenCheck {
    pub(super) fn new(url: String, cache_secs: Option<u64>) -> Result<Self> {
        let maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>> =
            cache_secs.map(|secs| Mutex::new((HashMap::new(), Duration::from_secs(secs))));
        Ok(Self {
            client: new_reqwest_client()
                .context("failed to build proxy-token validation HTTP client")?,
            maybe_auth_cache,
            url,
        })
    }

    async fn check_token_with_forwarding(&self, token: &str) -> Result<()> {
        trace!("Validating token by forwarding to {}", self.url);
        // If the token is cached and not cache has not expired, return it
        if let Some(ref auth_cache) = self.maybe_auth_cache {
            let mut auth_cache = auth_cache.lock().unwrap();
            let (ref mut auth_cache, cache_duration) = *auth_cache;
            if let Some(cached_at) = auth_cache.get(token) {
                if cached_at.elapsed() < cache_duration {
                    return Ok(());
                }
            }
            auth_cache.remove(token);
        }
        // Make a request to another API, which as a side effect should actually check the token
        let res = self
            .client
            .get(&self.url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to make request to proxying url")?;
        if !res.status().is_success() {
            bail!("Token forwarded to {} returned {}", self.url, res.status());
        }
        // Cache the token
        if let Some(ref auth_cache) = self.maybe_auth_cache {
            let mut auth_cache = auth_cache.lock().unwrap();
            let (ref mut auth_cache, _) = *auth_cache;
            auth_cache.insert(token.to_owned(), Instant::now());
        }
        Ok(())
    }
}

// Check a JWT is valid
pub struct ValidJWTCheck {
    audience: String,
    issuer: String,
    kid_to_pkcs1: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl ClientAuthCheck for ValidJWTCheck {
    async fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_jwt_validity(token) {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("JWT validation failed: {}", e);
                Err(ClientVisibleMsg::from_nonsensitive(
                    "JWT could not be validated".to_owned(),
                ))
            }
        }
    }
}

impl ValidJWTCheck {
    pub async fn new(audience: String, issuer: String, jwks_url: &str) -> Result<Self> {
        let client = new_reqwest_client().context("failed to build JWK retrieval HTTP client")?;
        let res = client
            .get(jwks_url)
            .send()
            .await
            .context("Failed to make request to JWKs url")?;
        if !res.status().is_success() {
            bail!("Could not retrieve JWKs, HTTP error: {}", res.status())
        }
        let jwks: Jwks = res.json().await.context("Failed to parse JWKs json")?;
        let kid_to_pkcs1 = jwks
            .keys
            .into_iter()
            .map(|k| k.to_der_pkcs1().map(|pkcs1| (k.kid, pkcs1)))
            .collect::<Result<_>>()
            .context("Failed to convert JWKs into pkcs1")?;
        Ok(Self {
            audience,
            issuer,
            kid_to_pkcs1,
        })
    }

    fn check_jwt_validity(&self, token: &str) -> Result<()> {
        let header = jwt::decode_header(token).context("Could not decode jwt header")?;
        trace!("Validating JWT in scheduler");
        // Prepare validation
        let kid = header.kid.context("No kid found")?;
        let pkcs1 = jwt::DecodingKey::from_rsa_der(
            self.kid_to_pkcs1
                .get(&kid)
                .context("kid not found in jwks")?,
        );
        let mut validation = jwt::Validation::new(header.alg);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        #[derive(Deserialize)]
        struct Claims {}
        // Decode the JWT, discarding any claims - we just care about validity
        let _tokendata = jwt::decode::<Claims>(token, &pkcs1, &validation)
            .context("Unable to validate and decode jwt")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    #[tokio::test]
    async fn proxy_token_timeout_does_not_cache_token() {
        // A listening socket with no responder stalls after the TCP connection succeeds.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let mut checker = ProxyTokenCheck::new(url, Some(60)).unwrap();
        checker.client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();

        let error = timeout(
            Duration::from_secs(5),
            checker.check_token_with_forwarding("test-token"),
        )
        .await
        .expect("proxy validation must respect its HTTP client timeout")
        .unwrap_err();
        assert_eq!(error.to_string(), "Failed to make request to proxying url");
        assert!(error.downcast_ref::<reqwest::Error>().unwrap().is_timeout());
        assert!(
            checker
                .maybe_auth_cache
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[tokio::test]
    async fn jwks_retrieval_handles_local_responses() {
        for (status, body, expected_error) in [
            ("200 OK", r#"{"keys":[]}"#, None),
            (
                "503 Service Unavailable",
                r#"{"keys":[]}"#,
                Some("Could not retrieve JWKs, HTTP error: 503 Service Unavailable"),
            ),
            ("200 OK", "not JSON", Some("Failed to parse JWKs json")),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/jwks", listener.local_addr().unwrap());
            let serve = async {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut buf = [0; 1024];
                    let read = connection.read(&mut buf).await.unwrap();
                    assert_ne!(
                        read, 0,
                        "client disconnected before sending request headers"
                    );
                    request.extend_from_slice(&buf[..read]);
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                connection.write_all(response.as_bytes()).await.unwrap();
            };
            let (result, ()) = timeout(Duration::from_secs(5), async {
                tokio::join!(
                    ValidJWTCheck::new("audience".to_owned(), "issuer".to_owned(), &url),
                    serve,
                )
            })
            .await
            .expect("local JWK retrieval must finish");

            if let Some(expected_error) = expected_error {
                assert_eq!(
                    result
                        .err()
                        .expect("expected JWK retrieval failure")
                        .to_string(),
                    expected_error
                );
            } else {
                let checker = result.unwrap();
                assert_eq!(checker.audience, "audience");
                assert_eq!(checker.issuer, "issuer");
                assert!(checker.kid_to_pkcs1.is_empty());
            }
        }
    }
}
