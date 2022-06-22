// Originally from https://github.com/rusoto/rusoto/blob/master/src/credential.rs
//! Types for loading and managing AWS access credentials for API requests.
#![allow(dead_code)]

use chrono::{offset, DateTime, Duration};
use directories::UserDirs;
use futures::future;
use hyperx::header::Connection;
use regex::Regex;
use reqwest::Client;
#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::env::*;
use std::fs::{self, File};
use std::future::Future;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use crate::errors::*;
use crate::util::RequestExt;

/// AWS API access credentials, including access key, secret key, token (for IAM profiles), and
/// expiration timestamp.
#[derive(Clone, Debug)]
pub struct AwsCredentials {
    key: String,
    secret: String,
    token: Option<String>,
    expires_at: DateTime<offset::Utc>,
}

impl AwsCredentials {
    /// Create a new `AwsCredentials` from a key ID, secret key, optional access token, and expiry
    /// time.
    pub fn new<K, S>(
        key: K,
        secret: S,
        token: Option<String>,
        expires_at: DateTime<offset::Utc>,
    ) -> AwsCredentials
    where
        K: Into<String>,
        S: Into<String>,
    {
        AwsCredentials {
            key: key.into(),
            secret: secret.into(),
            token,
            expires_at,
        }
    }

    /// Get a reference to the access key ID.
    pub fn aws_access_key_id(&self) -> &str {
        &self.key
    }

    /// Get a reference to the secret access key.
    pub fn aws_secret_access_key(&self) -> &str {
        &self.secret
    }

    /// Get a reference to the expiry time.
    pub fn expires_at(&self) -> &DateTime<offset::Utc> {
        &self.expires_at
    }

    /// Get a reference to the access token.
    pub fn token(&self) -> &Option<String> {
        &self.token
    }

    /// Determine whether or not the credentials are expired.
    fn credentials_are_expired(&self) -> bool {
        // This is a rough hack to hopefully avoid someone requesting creds then sitting on them
        // before issuing the request:
        self.expires_at < offset::Utc::now() + Duration::seconds(20)
    }
}

/// A trait for types that produce `AwsCredentials`.
pub trait ProvideAwsCredentials: Send + Sync {
    /// Produce a new `AwsCredentials`.
    fn credentials(&self)
        -> Pin<Box<dyn Future<Output = Result<AwsCredentials>> + Send + 'static>>;
}

/// Provides AWS credentials from environment variables.
pub struct EnvironmentProvider;

impl ProvideAwsCredentials for EnvironmentProvider {
    fn credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredentials>> + Send + 'static>> {
        Box::pin(async { credentials_from_environment() })
    }
}

fn credentials_from_environment() -> Result<AwsCredentials> {
    let env_key = var("AWS_ACCESS_KEY_ID").context("No AWS_ACCESS_KEY_ID in environment")?;
    let env_secret =
        var("AWS_SECRET_ACCESS_KEY").context("No AWS_SECRET_ACCESS_KEY in environment")?;

    if env_key.is_empty() || env_secret.is_empty() {
        bail!(
            "Couldn't find either AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY or both in environment."
        )
    }

    // Present when using temporary credentials, e.g. on Lambda with IAM roles
    let token = match var("AWS_SESSION_TOKEN") {
        Ok(val) => {
            if val.is_empty() {
                None
            } else {
                Some(val)
            }
        }
        Err(_) => None,
    };

    Ok(AwsCredentials::new(
        env_key,
        env_secret,
        token,
        in_ten_minutes(),
    ))
}

/// Provides AWS credentials from a profile in a credentials file.
#[derive(Clone, Debug)]
pub struct ProfileProvider {
    credentials: Option<AwsCredentials>,
    file_path: PathBuf,
    profile: String,
}

impl ProfileProvider {
    /// Create a new `ProfileProvider` for the default credentials file path and profile name.
    pub fn new() -> Result<ProfileProvider> {
        // Default credentials file location:
        // ~/.aws/credentials (Linux/Mac)
        // %USERPROFILE%\.aws\credentials  (Windows)
        let profile_location = UserDirs::new()
            .map(|d| d.home_dir().join(".aws").join("credentials"))
            .context("Couldn't get user directories")?;

        Ok(ProfileProvider {
            credentials: None,
            file_path: profile_location,
            profile: "default".to_owned(),
        })
    }

    /// Create a new `ProfileProvider` for the credentials file at the given path, using
    /// the given profile.
    pub fn with_configuration<F, P>(file_path: F, profile: P) -> ProfileProvider
    where
        F: Into<PathBuf>,
        P: Into<String>,
    {
        ProfileProvider {
            credentials: None,
            file_path: file_path.into(),
            profile: profile.into(),
        }
    }

    /// Get a reference to the credentials file path.
    pub fn file_path(&self) -> &Path {
        self.file_path.as_ref()
    }

    /// Get a reference to the profile name.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Set the credentials file path.
    pub fn set_file_path<F>(&mut self, file_path: F)
    where
        F: Into<PathBuf>,
    {
        self.file_path = file_path.into();
    }

    /// Set the profile name.
    pub fn set_profile<P>(&mut self, profile: P)
    where
        P: Into<String>,
    {
        self.profile = profile.into();
    }
}

impl ProvideAwsCredentials for ProfileProvider {
    fn credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredentials>> + Send + 'static>> {
        let file_path = self.file_path().to_owned();
        let profile = self.profile.to_owned();

        Box::pin(async move {
            let mut profiles = parse_credentials_file(&file_path)?;

            profiles.remove(&profile).context("profile not found")
        })
    }
}

fn parse_credentials_file(file_path: &Path) -> Result<HashMap<String, AwsCredentials>> {
    let metadata = fs::metadata(file_path).context("couldn't stat credentials file")?;
    if !metadata.is_file() {
        bail!("Couldn't open file.");
    }

    let file = File::open(file_path)?;

    let profile_regex = Regex::new(r"^\[([^\]]+)\]$").unwrap();
    let mut profiles: HashMap<String, AwsCredentials> = HashMap::new();
    let mut access_key: Option<String> = None;
    let mut secret_key: Option<String> = None;
    let mut profile_name: Option<String> = None;

    let file_lines = BufReader::new(&file);
    for line in file_lines.lines() {
        let unwrapped_line: String = line.unwrap();

        // skip comments
        if unwrapped_line.starts_with('#') {
            continue;
        }

        // handle the opening of named profile blocks
        if profile_regex.is_match(&unwrapped_line) {
            if let (Some(profile_name), Some(access_key), Some(secret_key)) =
                (profile_name, access_key, secret_key)
            {
                let creds = AwsCredentials::new(access_key, secret_key, None, in_ten_minutes());
                profiles.insert(profile_name, creds);
            }

            access_key = None;
            secret_key = None;

            let caps = profile_regex.captures(&unwrapped_line).unwrap();
            profile_name = Some(caps.get(1).unwrap().as_str().to_string());
            continue;
        }

        // otherwise look for key=value pairs we care about
        let lower_case_line = unwrapped_line.to_ascii_lowercase().to_string();

        if lower_case_line.contains("aws_access_key_id") && access_key.is_none() {
            let v: Vec<&str> = unwrapped_line.split('=').collect();
            if !v.is_empty() {
                access_key = Some(v[1].trim_matches(' ').to_string());
            }
        } else if lower_case_line.contains("aws_secret_access_key") && secret_key.is_none() {
            let v: Vec<&str> = unwrapped_line.split('=').collect();
            if !v.is_empty() {
                secret_key = Some(v[1].trim_matches(' ').to_string());
            }
        }

        // we could potentially explode here to indicate that the file is invalid
    }

    if let (Some(profile_name), Some(access_key), Some(secret_key)) =
        (profile_name, access_key, secret_key)
    {
        let creds = AwsCredentials::new(access_key, secret_key, None, in_ten_minutes());
        profiles.insert(profile_name, creds);
    }

    if profiles.is_empty() {
        bail!("No credentials found.")
    }

    Ok(profiles)
}

/// Provides AWS credentials from a resource's IAM role.
pub struct IamProvider {
    client: Client,
}

impl IamProvider {
    pub fn new() -> IamProvider {
        IamProvider {
            client: Client::new(),
        }
    }

    async fn iam_role(client: &Client) -> Result<String> {
        // First get the IAM role
        let address = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let response = client
            .get(address)
            .set_header(Connection::close())
            .body("")
            .send()
            .await
            .context("couldn't connect to metadata service")?;
        let bytes = response.bytes().await?;
        let body = String::from_utf8(bytes.into_iter().collect())
            .context("Didn't get a parsable response body from metadata service")?;

        let mut address = address.to_string();
        address.push_str(&body);
        Ok(address)
    }
}

impl ProvideAwsCredentials for IamProvider {
    fn credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredentials>> + Send + 'static>> {
        let client = self.client.clone();

        Box::pin(async {
            let url = match var("AWS_IAM_CREDENTIALS_URL") {
                Ok(url) => url,
                Err(_) => Self::iam_role(&client).await?,
            };
            let address = url
                .parse::<reqwest::Url>()
                .with_context(|| format!("failed to parse `{}` as url", url))?;

            debug!("Attempting to fetch credentials from {}", address);

            let fetch_creds = async move {
                let response = client
                    .get(address)
                    .set_header(Connection::close())
                    .body("")
                    .send()
                    .await
                    .context("failed to send http request")?;

                let body: serde_json::Value = response
                    .json()
                    .await
                    .context("failed to read IAM role response")?;

                let access_key = match body.get("AccessKeyId") {
                    None => bail!("Couldn't find AccessKeyId in response."),
                    Some(val) => val
                        .as_str()
                        .expect("AccessKeyId value was not a string")
                        .to_owned()
                        .replace('\"', ""),
                };

                let secret_key = match body.get("SecretAccessKey") {
                    None => bail!("Couldn't find SecretAccessKey in response."),
                    Some(val) => val
                        .as_str()
                        .expect("SecretAccessKey value was not a string")
                        .to_owned()
                        .replace('\"', ""),
                };

                let expiration = match body.get("Expiration") {
                    None => bail!("Couldn't find Expiration in response."),
                    Some(val) => val
                        .as_str()
                        .expect("Expiration value was not a string")
                        .to_owned()
                        .replace('\"', ""),
                };

                let expiration_time = expiration
                    .parse()
                    .context("failed to parse expiration time")?;

                let token_from_response = match body.get("Token") {
                    None => bail!("Couldn't find Token in response."),
                    Some(val) => val
                        .as_str()
                        .expect("Token value was not a string")
                        .to_owned()
                        .replace('\"', ""),
                };

                Ok(AwsCredentials::new(
                    access_key,
                    secret_key,
                    Some(token_from_response),
                    expiration_time,
                ))
            };

            //XXX: this is crappy, but this blocks on non-EC2 machines like
            // our mac builders.
            match tokio::time::timeout(std::time::Duration::from_secs(2), fetch_creds).await {
                Ok(Ok(creds)) => Ok(creds),
                Ok(Err(e)) => {
                    warn!("Failed to fetch IAM credentials: {}", e);
                    Err(e)
                }
                Err(_elased) => bail!("took too long to fetch credentials"),
            }
        })
    }
}

/// Wrapper for ProvideAwsCredentials that caches the credentials returned by the
/// wrapped provider.  Each time the credentials are accessed, they are checked to see if
/// they have expired, in which case they are retrieved from the wrapped provider again.
pub struct AutoRefreshingProvider<P: Send + Sync> {
    credentials_provider: P,
    cached_credentials: Arc<futures_locks::Mutex<Option<AwsCredentials>>>,
}

impl<P: ProvideAwsCredentials + Send + Sync> AutoRefreshingProvider<P> {
    pub fn new(provider: P) -> AutoRefreshingProvider<P> {
        AutoRefreshingProvider {
            cached_credentials: Arc::new(futures_locks::Mutex::new(None)),
            credentials_provider: provider,
        }
    }
}

impl<P: ProvideAwsCredentials + Sync> ProvideAwsCredentials for AutoRefreshingProvider<P> {
    fn credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredentials>> + Send + 'static>> {
        let cached_credentials = Arc::clone(&self.cached_credentials);
        let new_creds = self.credentials_provider.credentials();

        Box::pin(async move {
            let mut cache = cached_credentials.lock().await;

            match *cache {
                Some(ref creds) if !creds.credentials_are_expired() => Ok(creds.clone()),
                _ => {
                    let new_creds = new_creds.await?;

                    *cache = Some(new_creds.clone());
                    Ok(new_creds)
                }
            }
        })
    }
}

/// Provides AWS credentials from multiple possible sources using a priority order.
///
/// The following sources are checked in order for credentials when calling `credentials`:
///
/// 1. Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
/// 2. AWS credentials file. Usually located at `~/.aws/credentials`.
/// 3. IAM instance profile. Will only work if running on an EC2 instance with an instance profile/role.
///
/// If the sources are exhausted without finding credentials, an error is returned.
#[derive(Clone)]
pub struct ChainProvider {
    profile_providers: Vec<ProfileProvider>,
}

impl ProvideAwsCredentials for ChainProvider {
    fn credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredentials>> + Send + 'static>> {
        use futures::FutureExt;

        let environment_provider = EnvironmentProvider
            .credentials()
            .inspect(|_| debug!("Using AWS credentials from environment"))
            .boxed();
        let iam_provider = IamProvider::new()
            .credentials()
            .inspect(|_| debug!("Using AWS credentials from IAM"))
            .boxed();

        let providers: Vec<_> = std::iter::empty()
            .chain(std::iter::once(environment_provider))
            .chain(
                self.profile_providers
                    .iter()
                    .map(ProvideAwsCredentials::credentials),
            )
            .chain(std::iter::once(iam_provider))
            .collect();

        Box::pin(async move {
            match future::select_ok(providers).await {
                Ok((creds, _rest)) => Ok(creds),
                Err(_) => bail!(
                    "Couldn't find AWS credentials in environment, credentials file, or IAM role."
                ),
            }
        })
    }
}

impl ChainProvider {
    /// Create a new `ChainProvider` using a `ProfileProvider` with the default settings.
    pub fn new() -> ChainProvider {
        ChainProvider {
            profile_providers: ProfileProvider::new().into_iter().collect(),
        }
    }

    /// Create a new `ChainProvider` using the provided `ProfileProvider`s.
    pub fn with_profile_providers(profile_providers: Vec<ProfileProvider>) -> ChainProvider {
        ChainProvider { profile_providers }
    }
}

fn in_ten_minutes() -> DateTime<offset::Utc> {
    offset::Utc::now() + Duration::seconds(600)
}
