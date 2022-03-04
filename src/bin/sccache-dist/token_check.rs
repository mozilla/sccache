use crate::jwt;
use anyhow::{bail, Context, Result};
use sccache::dist::http::{ClientAuthCheck, ClientVisibleMsg};
use sccache::util::RequestExt;
use std::collections::HashMap;
use std::result::Result as StdResult;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
        let n = base64::decode_config(&self.n, base64::URL_SAFE)
            .context("Failed to base64 decode n")?;
        let e = base64::decode_config(&self.e, base64::URL_SAFE)
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

impl ClientAuthCheck for EqCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
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

// https://infosec.mozilla.org/guidelines/iam/openid_connect#session-handling
const MOZ_SESSION_TIMEOUT: Duration = Duration::from_secs(60 * 15);
const MOZ_USERINFO_ENDPOINT: &str = "https://auth.mozilla.auth0.com/userinfo";

/// Mozilla-specific check by forwarding the token onto the auth0 userinfo endpoint
pub struct MozillaCheck {
    // token, token_expiry
    auth_cache: Mutex<HashMap<String, Instant>>,
    client: reqwest::blocking::Client,
    required_groups: Vec<String>,
}

impl ClientAuthCheck for MozillaCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        self.check_mozilla(token).map_err(|e| {
            warn!("Mozilla token validation failed: {}", e);
            ClientVisibleMsg::from_nonsensitive(
                "Failed to validate Mozilla OAuth token, run sccache --dist-auth".to_owned(),
            )
        })
    }
}

impl MozillaCheck {
    pub fn new(required_groups: Vec<String>) -> Self {
        Self {
            auth_cache: Mutex::new(HashMap::new()),
            client: reqwest::blocking::Client::new(),
            required_groups,
        }
    }

    fn check_mozilla(&self, token: &str) -> Result<()> {
        // azp == client_id
        // {
        //   "iss": "https://auth.mozilla.auth0.com/",
        //   "sub": "ad|Mozilla-LDAP|asayers",
        //   "aud": [
        //     "sccache",
        //     "https://auth.mozilla.auth0.com/userinfo"
        //   ],
        //   "iat": 1541103283,
        //   "exp": 1541708083,
        //   "azp": "F1VVD6nRTckSVrviMRaOdLBWIk1AvHYo",
        //   "scope": "openid"
        // }
        #[derive(Deserialize)]
        struct MozillaToken {
            exp: u64,
            sub: String,
        }
        let mut validation = jwt::Validation::default();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        // We don't really do any validation here (just forwarding on) so it's ok to unsafely decode
        validation.insecure_disable_signature_validation();
        let dummy_key = jwt::DecodingKey::from_secret(b"secret");
        let insecure_token = jwt::decode::<MozillaToken>(token, &dummy_key, &validation)
            .context("Unable to decode jwt")?;
        let user = insecure_token.claims.sub;
        trace!("Validating token for user {} with mozilla", user);
        if UNIX_EPOCH + Duration::from_secs(insecure_token.claims.exp) < SystemTime::now() {
            bail!("JWT expired")
        }

        // If the token is cached and not expired, return it
        let mut auth_cache = self.auth_cache.lock().unwrap();
        if let Some(cached_at) = auth_cache.get(token) {
            if cached_at.elapsed() < MOZ_SESSION_TIMEOUT {
                return Ok(());
            }
        }
        auth_cache.remove(token);

        debug!("User {} not in cache, validating via auth0 endpoint", user);
        // Retrieve the groups from the auth0 /userinfo endpoint, which Mozilla rules populate with groups
        // https://github.com/mozilla-iam/auth0-deploy/blob/6889f1dde12b84af50bb4b2e2f00d5e80d5be33f/rules/CIS-Claims-fixups.js#L158-L168
        let url = reqwest::Url::parse(MOZ_USERINFO_ENDPOINT)
            .expect("Failed to parse MOZ_USERINFO_ENDPOINT");
        let header = hyperx::header::Authorization(hyperx::header::Bearer {
            token: token.to_owned(),
        });
        let res = self
            .client
            .get(url.clone())
            .set_header(header)
            .send()
            .context("Failed to make request to mozilla userinfo")?;
        let status = res.status();
        let res_text = res
            .text()
            .context("Failed to interpret response from mozilla userinfo as string")?;
        if !status.is_success() {
            bail!("JWT forwarded to {} returned {}: {}", url, status, res_text)
        }

        // The API didn't return a HTTP error code, let's check the response
        let () = check_mozilla_profile(&user, &self.required_groups, &res_text)
            .with_context(|| format!("Validation of the user profile failed for {}", user))?;

        // Validation success, cache the token
        debug!("Validation for user {} succeeded, caching", user);
        auth_cache.insert(token.to_owned(), Instant::now());
        Ok(())
    }
}

fn check_mozilla_profile(user: &str, required_groups: &[String], profile: &str) -> Result<()> {
    #[derive(Deserialize)]
    struct UserInfo {
        sub: String,
        #[serde(rename = "https://sso.mozilla.com/claim/groups")]
        groups: Vec<String>,
    }
    let profile: UserInfo = serde_json::from_str(profile)
        .with_context(|| format!("Could not parse profile: {}", profile))?;
    if user != profile.sub {
        bail!(
            "User {} retrieved in profile is different to desired user {}",
            profile.sub,
            user
        )
    }
    for group in required_groups.iter() {
        if !profile.groups.contains(group) {
            bail!("User {} is not a member of required group {}", user, group)
        }
    }
    Ok(())
}

#[test]
fn test_auth_verify_check_mozilla_profile() {
    // A successful response
    let profile = r#"{
        "sub": "ad|Mozilla-LDAP|asayers",
        "https://sso.mozilla.com/claim/groups": [
            "everyone",
            "hris_dept_firefox",
            "hris_individual_contributor",
            "hris_nonmanagers",
            "hris_is_staff",
            "hris_workertype_contractor"
        ],
        "https://sso.mozilla.com/claim/README_FIRST": "Please refer to https://github.com/mozilla-iam/person-api in order to query Mozilla IAM CIS user profile data"
    }"#;

    // If the user has been deactivated since the token was issued. Note this may be partnered with an error code
    // response so may never reach validation
    let profile_fail = r#"{
        "error": "unauthorized",
        "error_description": "user is blocked"
    }"#;

    assert!(check_mozilla_profile(
        "ad|Mozilla-LDAP|asayers",
        &["hris_dept_firefox".to_owned()],
        profile,
    )
    .is_ok());
    assert!(check_mozilla_profile("ad|Mozilla-LDAP|asayers", &[], profile).is_ok());
    assert!(check_mozilla_profile(
        "ad|Mozilla-LDAP|asayers",
        &["hris_the_ceo".to_owned()],
        profile,
    )
    .is_err());

    assert!(check_mozilla_profile("ad|Mozilla-LDAP|asayers", &[], profile_fail).is_err());
}

// Don't check a token is valid (it may not even be a JWT) just forward it to
// an API and check for success
pub struct ProxyTokenCheck {
    client: reqwest::blocking::Client,
    maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>>,
    url: String,
}

impl ClientAuthCheck for ProxyTokenCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_token_with_forwarding(token) {
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
    pub fn new(url: String, cache_secs: Option<u64>) -> Self {
        let maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>> =
            cache_secs.map(|secs| Mutex::new((HashMap::new(), Duration::from_secs(secs))));
        Self {
            client: reqwest::blocking::Client::new(),
            maybe_auth_cache,
            url,
        }
    }

    fn check_token_with_forwarding(&self, token: &str) -> Result<()> {
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
        let header = hyperx::header::Authorization(hyperx::header::Bearer {
            token: token.to_owned(),
        });
        let res = self
            .client
            .get(&self.url)
            .set_header(header)
            .send()
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

impl ClientAuthCheck for ValidJWTCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
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
    pub fn new(audience: String, issuer: String, jwks_url: &str) -> Result<Self> {
        let res = reqwest::blocking::get(jwks_url).context("Failed to make request to JWKs url")?;
        if !res.status().is_success() {
            bail!("Could not retrieve JWKs, HTTP error: {}", res.status())
        }
        let jwks: Jwks = res.json().context("Failed to parse JWKs json")?;
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
