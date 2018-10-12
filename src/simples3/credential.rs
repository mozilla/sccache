// Originally from https://github.com/rusoto/rusoto/blob/master/src/credential.rs
//! Types for loading and managing AWS access credentials for API requests.
#![allow(dead_code)]

use chrono::{Duration, offset, DateTime};
use directories::UserDirs;
use futures::{Future, Async, IntoFuture, Stream};
use futures::future::{self, Shared};
use hyper::{self, Client, Method};
use hyper::client::{HttpConnector, Request};
use hyper::header::Connection;
use regex::Regex;
use serde_json::{Value, from_str};
#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env::*;
use std::fs::File;
use std::fs;
use std::io::BufReader;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;
use tokio_core::reactor::{Handle, Timeout};

use errors::*;

/// AWS API access credentials, including access key, secret key, token (for IAM profiles), and
/// expiration timestamp.
#[derive(Clone, Debug)]
pub struct AwsCredentials {
    key: String,
    secret: String,
    token: Option<String>,
    expires_at: DateTime<offset::Utc>
}

impl AwsCredentials {
    /// Create a new `AwsCredentials` from a key ID, secret key, optional access token, and expiry
    /// time.
    pub fn new<K, S>(key:K, secret:S, token:Option<String>, expires_at:DateTime<offset::Utc>)
    -> AwsCredentials where K:Into<String>, S:Into<String> {
        AwsCredentials {
            key: key.into(),
            secret: secret.into(),
            token: token,
            expires_at: expires_at,
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
pub trait ProvideAwsCredentials {
    /// Produce a new `AwsCredentials`.
    fn credentials(&self) -> SFuture<AwsCredentials>;
}

/// Provides AWS credentials from environment variables.
pub struct EnvironmentProvider;

impl ProvideAwsCredentials for EnvironmentProvider {
    fn credentials(&self) -> SFuture<AwsCredentials> {
		Box::new(future::result(credentials_from_environment()))
    }
}

fn credentials_from_environment() -> Result<AwsCredentials> {
    let env_key = var("AWS_ACCESS_KEY_ID").chain_err(|| {
        "No AWS_ACCESS_KEY_ID in environment"
    })?;
    let env_secret = var("AWS_SECRET_ACCESS_KEY").chain_err(|| {
        "No AWS_SECRET_ACCESS_KEY in environment"
    })?;

    if env_key.is_empty() || env_secret.is_empty() {
        bail!("Couldn't find either AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY or both in environment.")
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

    Ok(AwsCredentials::new(env_key, env_secret, token, in_ten_minutes()))

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
            .ok_or("Couldn't get user directories")?;

        Ok(ProfileProvider {
            credentials: None,
            file_path: profile_location,
            profile: "default".to_owned(),
        })
    }

    /// Create a new `ProfileProvider` for the credentials file at the given path, using
    /// the given profile.
    pub fn with_configuration<F, P>(file_path: F, profile: P) -> ProfileProvider
    where F: Into<PathBuf>, P: Into<String> {
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
    pub fn set_file_path<F>(&mut self, file_path: F) where F: Into<PathBuf> {
        self.file_path = file_path.into();
    }

    /// Set the profile name.
    pub fn set_profile<P>(&mut self, profile: P) where P: Into<String> {
        self.profile = profile.into();
    }
}

impl ProvideAwsCredentials for ProfileProvider {
    fn credentials(&self) -> SFuture<AwsCredentials> {
        let result = parse_credentials_file(self.file_path());
        let result = result.and_then(|mut profiles| {
            profiles.remove(self.profile()).ok_or("profile not found".into())
        });
        Box::new(future::result(result))
    }
}

fn parse_credentials_file(file_path: &Path) -> Result<HashMap<String, AwsCredentials>> {
    let metadata = fs::metadata(file_path).chain_err(|| {
        "couldn't stat credentials file"
    })?;
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

        let unwrapped_line : String = line.unwrap();

        // skip comments
        if unwrapped_line.starts_with('#') {
            continue;
        }

        // handle the opening of named profile blocks
        if profile_regex.is_match(&unwrapped_line) {

            if profile_name.is_some() && access_key.is_some() && secret_key.is_some() {
                let creds = AwsCredentials::new(access_key.unwrap(), secret_key.unwrap(), None, in_ten_minutes());
                profiles.insert(profile_name.unwrap(), creds);
            }

            access_key = None;
            secret_key = None;

            let caps = profile_regex.captures(&unwrapped_line).unwrap();
            profile_name = Some(caps.get(1).unwrap().as_str().to_string());
            continue;
        }

        // otherwise look for key=value pairs we care about
        let lower_case_line = unwrapped_line.to_ascii_lowercase().to_string();

        if lower_case_line.contains("aws_access_key_id") &&
            access_key.is_none()
        {
            let v: Vec<&str> = unwrapped_line.split('=').collect();
            if !v.is_empty() {
                access_key = Some(v[1].trim_matches(' ').to_string());
            }
        } else if lower_case_line.contains("aws_secret_access_key") &&
            secret_key.is_none()
        {
            let v: Vec<&str> = unwrapped_line.split('=').collect();
            if !v.is_empty() {
                secret_key = Some(v[1].trim_matches(' ').to_string());
            }
        }

        // we could potentially explode here to indicate that the file is invalid

    }

    if profile_name.is_some() && access_key.is_some() && secret_key.is_some() {
        let creds = AwsCredentials::new(access_key.unwrap(), secret_key.unwrap(), None, in_ten_minutes());
        profiles.insert(profile_name.unwrap(), creds);
    }

    if profiles.is_empty() {
        bail!("No credentials found.")
    }

    Ok(profiles)
}

/// Provides AWS credentials from a resource's IAM role.
pub struct IamProvider {
    client: Client<HttpConnector>,
    handle: Handle,
}

impl IamProvider {
    pub fn new(handle: &Handle) -> IamProvider {
        IamProvider {
            client: Client::new(handle),
            handle: handle.clone(),
        }
    }

    fn iam_role(&self) -> SFuture<String> {
        // First get the IAM role
        let address = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let mut req = Request::new(Method::Get, address.parse().unwrap());
        req.headers_mut().set(Connection::close());
        let response = self.client.request(req).and_then(|response| {
            response.body().fold(Vec::new(), |mut body, chunk| {
                body.extend_from_slice(&chunk);
                Ok::<_, hyper::Error>(body)
            })
        });

        Box::new(response.then(|res| {
            let bytes = res.chain_err(|| {
                "couldn't connect to metadata service"
            })?;
            String::from_utf8(bytes).chain_err(|| {
                "Didn't get a parsable response body from metadata service"
            })
        }).map(move |body| {
            let mut address = address.to_string();
            address.push_str(&body);
            address
        }))
    }
}

impl ProvideAwsCredentials for IamProvider {
    fn credentials(&self) -> SFuture<AwsCredentials> {
        let url = match var("AWS_IAM_CREDENTIALS_URL") {
            Ok(url) => f_ok(url),
            Err(_) => self.iam_role(),
        };
        let url = url.and_then(|url| {
            url.parse().chain_err(|| format!("failed to parse `{}` as url", url))
        });

        let client = self.client.clone();
        let response = url.and_then(move |address| {
            debug!("Attempting to fetch credentials from {}", address);
            let mut req = Request::new(Method::Get, address);
            req.headers_mut().set(Connection::close());
            client.request(req).chain_err(|| {
                "failed to send http request"
            })
        });
        let body = response.and_then(|response| {
            response.body().fold(Vec::new(), |mut body, chunk| {
                body.extend_from_slice(&chunk);
                Ok::<_, hyper::Error>(body)
            }).chain_err(|| {
                "failed to read http body"
            })
        });
        let body = body.map_err(|_e| {
            "Didn't get a parseable response body from instance role details".into()
        }).and_then(|body| {
            String::from_utf8(body).chain_err(|| {
                "failed to read iam role response"
            })
        });

        let creds = body.and_then(|body| {
            let json_object: Value;
            match from_str(&body) {
                Err(_) => bail!("Couldn't parse metadata response body."),
                Ok(val) => json_object = val
            };

            let access_key;
            match json_object.get("AccessKeyId") {
                None => bail!("Couldn't find AccessKeyId in response."),
                Some(val) => access_key = val.as_str().expect("AccessKeyId value was not a string").to_owned().replace("\"", "")
            };

            let secret_key;
            match json_object.get("SecretAccessKey") {
                None => bail!("Couldn't find SecretAccessKey in response."),
                Some(val) => secret_key = val.as_str().expect("SecretAccessKey value was not a string").to_owned().replace("\"", "")
            };

            let expiration;
            match json_object.get("Expiration") {
                None => bail!("Couldn't find Expiration in response."),
                Some(val) => expiration = val.as_str().expect("Expiration value was not a string").to_owned().replace("\"", "")
            };

            let expiration_time = expiration.parse().chain_err(|| {
                "failed to parse expiration time"
            })?;

            let token_from_response;
            match json_object.get("Token") {
                None => bail!("Couldn't find Token in response."),
                Some(val) => token_from_response = val.as_str().expect("Token value was not a string").to_owned().replace("\"", "")
            };

            Ok(AwsCredentials::new(access_key, secret_key, Some(token_from_response), expiration_time))
        });

        //XXX: this is crappy, but this blocks on non-EC2 machines like
        // our mac builders.
        let timeout = Timeout::new(StdDuration::from_secs(2), &self.handle);
        let timeout = timeout.into_future().flatten().map_err(|_e| {
            "timeout failed".into()
        });

        Box::new(creds.map(Ok).select(timeout.map(Err)).then(|result| {
            match result {
                Ok((Ok(creds), _timeout)) => Ok(creds),
                Ok((Err(_), _creds)) => {
                    bail!("took too long to fetch credentials")
                }
                Err((e, _)) => {
                    warn!("Failed to fetch IAM credentials: {}", e);
                    Err(e)
                }
            }
        }))
    }
}

/// Wrapper for ProvideAwsCredentials that caches the credentials returned by the
/// wrapped provider.  Each time the credentials are accessed, they are checked to see if
/// they have expired, in which case they are retrieved from the wrapped provider again.
pub struct AutoRefreshingProvider<P> {
	credentials_provider: P,
	cached_credentials: RefCell<Shared<SFuture<AwsCredentials>>>,
}

impl<P: ProvideAwsCredentials> AutoRefreshingProvider<P> {
	pub fn new(provider: P) -> AutoRefreshingProvider<P> {
		AutoRefreshingProvider {
			cached_credentials: RefCell::new(provider.credentials().shared()),
			credentials_provider: provider,
		}
	}
}

impl <P: ProvideAwsCredentials> ProvideAwsCredentials for AutoRefreshingProvider<P> {
    fn credentials(&self) -> SFuture<AwsCredentials> {
        let mut future = self.cached_credentials.borrow_mut();
        if let Ok(Async::Ready(creds)) = future.poll() {
            if creds.credentials_are_expired() {
                *future = self.credentials_provider.credentials().shared();
            }
        }
        Box::new(future.clone().then(|result| {
            match result {
                Ok(e) => Ok((*e).clone()),
                Err(e) => Err(e.to_string().into()),
            }
        }))
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
    handle: Handle,
}

impl ProvideAwsCredentials for ChainProvider {
    fn credentials(&self) -> SFuture<AwsCredentials> {
	    let creds = EnvironmentProvider.credentials().map(|c| {
            debug!("Using AWS credentials from environment");
            c
        });
        let mut creds = Box::new(creds) as SFuture<_>;
        for provider in self.profile_providers.iter() {
            let alternate = provider.credentials();
            creds = Box::new(creds.or_else(|_| alternate));
        }
        let handle = self.handle.clone();
        Box::new(creds.or_else(move |_| {
		    IamProvider::new(&handle).credentials().map(|c| {
                debug!("Using AWS credentials from IAM");
                c
            })
        }).map_err(|_| {
		    "Couldn't find AWS credentials in environment, credentials file, or IAM role.".into()
        }))
    }
}

impl ChainProvider {
    /// Create a new `ChainProvider` using a `ProfileProvider` with the default settings.
    pub fn new(handle: &Handle) -> ChainProvider {
        ChainProvider {
            profile_providers: ProfileProvider::new().into_iter().collect(),
            handle: handle.clone(),
        }
    }

    /// Create a new `ChainProvider` using the provided `ProfileProvider`s.
    pub fn with_profile_providers(profile_providers: Vec<ProfileProvider>,
                                  handle: &Handle)
    -> ChainProvider {
        ChainProvider {
            profile_providers: profile_providers,
            handle: handle.clone(),
        }
    }
}

fn in_ten_minutes() -> DateTime<offset::Utc> {
    offset::Utc::now() + Duration::seconds(600)
}
