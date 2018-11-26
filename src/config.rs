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

use directories::ProjectDirs;
use regex::Regex;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use reqwest;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, DeserializeOwned, Deserializer};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::Mutex;
use toml;

use errors::*;

lazy_static! {
    static ref CACHED_CONFIG_PATH: PathBuf = CachedConfig::file_config_path();
    static ref CACHED_CONFIG: Mutex<Option<CachedFileConfig>> = Mutex::new(None);
}

const ORGANIZATION: &str = "Mozilla";
const APP_NAME: &str = "sccache";
const DIST_APP_NAME: &str = "sccache-dist-client";
const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;

const MOZILLA_OAUTH_PKCE_CLIENT_ID: &str = "F1VVD6nRTckSVrviMRaOdLBWIk1AvHYo";
// The sccache audience is an API set up in auth0 for sccache to allow 7 day expiry,
// the openid scope allows us to query the auth0 /userinfo endpoint which contains
// group information due to Mozilla rules.
const MOZILLA_OAUTH_PKCE_AUTH_URL: &str = "https://auth.mozilla.auth0.com/authorize?audience=sccache&scope=openid";
const MOZILLA_OAUTH_PKCE_TOKEN_URL: &str = "https://auth.mozilla.auth0.com/oauth/token";

pub const INSECURE_DIST_CLIENT_TOKEN: &str = "dangerously_insecure_client";

// Unfortunately this means that nothing else can use the sccache cache dir as
// this top level directory is used directly to store sccache cached objects...
pub fn default_disk_cache_dir() -> PathBuf {
    ProjectDirs::from("", ORGANIZATION, APP_NAME)
        .expect("Unable to retrieve disk cache directory")
        .cache_dir().to_owned()
}
// ...whereas subdirectories are used of this one
pub fn default_dist_cache_dir() -> PathBuf {
    ProjectDirs::from("", ORGANIZATION, DIST_APP_NAME)
        .expect("Unable to retrieve dist cache directory")
        .cache_dir().to_owned()
}

fn default_disk_cache_size() -> u64 { TEN_GIGS }
fn default_toolchain_cache_size() -> u64 { TEN_GIGS }

pub fn parse_size(val: &str) -> Option<u64> {
    let re = Regex::new(r"^(\d+)([KMGT])$").expect("Fixed regex parse failure");
    re.captures(val)
        .and_then(|caps| {
            caps.get(1)
                .and_then(|size| u64::from_str(size.as_str()).ok())
                .and_then(|size| Some((size, caps.get(2))))
        })
        .and_then(|(size, suffix)| {
            match suffix.map(|s| s.as_str()) {
                Some("K") => Some(1024 * size),
                Some("M") => Some(1024 * 1024 * size),
                Some("G") => Some(1024 * 1024 * 1024 * size),
                Some("T") => Some(1024 * 1024 * 1024 * 1024 * size),
                _ => None,
            }
        })
}

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HTTPUrl(reqwest::Url);
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl Serialize for HTTPUrl {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(self.0.as_str())
    }
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl<'a> Deserialize<'a> for HTTPUrl {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error> where D: Deserializer<'a> {
        use serde::de::Error;
        let helper: String = Deserialize::deserialize(deserializer)?;
        let url = parse_http_url(&helper).map_err(D::Error::custom)?;
        Ok(HTTPUrl(url))
    }
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
fn parse_http_url(url: &str) -> Result<reqwest::Url> {
    use std::net::SocketAddr;
    let url = if let Ok(sa) = url.parse::<SocketAddr>() {
        warn!("Url {} has no scheme, assuming http", url);
        reqwest::Url::parse(&format!("http://{}", sa))
    } else {
        reqwest::Url::parse(url)
    }.map_err(|e| format!("{}", e))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("url not http or https")
    }
    // TODO: relative url handling just hasn't been implemented and tested
    if url.path() != "/" {
        bail!("url has a relative path (currently unsupported)")
    }
    Ok(url)
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl HTTPUrl {
    pub fn from_url(u: reqwest::Url) -> Self { HTTPUrl(u) }
    pub fn to_url(&self) -> reqwest::Url { self.0.clone() }
}

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureCacheConfig;

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct DiskCacheConfig {
    pub dir: PathBuf,
    // TODO: use deserialize_with to allow human-readable sizes in toml
    pub size: u64,
}

impl Default for DiskCacheConfig {
    fn default() -> Self {
        DiskCacheConfig {
            dir: default_disk_cache_dir(),
            size: default_disk_cache_size(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GCSCacheRWMode {
    #[serde(rename = "READ_ONLY")]
    ReadOnly,
    #[serde(rename = "READ_WRITE")]
    ReadWrite,
}

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GCSCacheConfig {
    pub bucket: String,
    pub cred_path: Option<PathBuf>,
    pub rw_mode: GCSCacheRWMode,
}

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemcachedCacheConfig {
    pub url: String,
}

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisCacheConfig {
    pub url: String,
}

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3CacheConfig {
    pub bucket: String,
    pub endpoint: String,
    pub get_auth: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CacheType {
    Azure(AzureCacheConfig),
    GCS(GCSCacheConfig),
    Memcached(MemcachedCacheConfig),
    Redis(RedisCacheConfig),
    S3(S3CacheConfig),
}

#[derive(Debug, Default)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfigs {
    pub azure: Option<AzureCacheConfig>,
    pub disk: Option<DiskCacheConfig>,
    pub gcs: Option<GCSCacheConfig>,
    pub memcached: Option<MemcachedCacheConfig>,
    pub redis: Option<RedisCacheConfig>,
    pub s3: Option<S3CacheConfig>,
}

impl CacheConfigs {
    /// Return a vec of the available cache types in an arbitrary but
    /// consistent ordering
    fn into_vec_and_fallback(self) -> (Vec<CacheType>, DiskCacheConfig) {
        let CacheConfigs {
            azure, disk, gcs, memcached, redis, s3
        } = self;

        let caches = s3.map(CacheType::S3).into_iter()
            .chain(redis.map(CacheType::Redis))
            .chain(memcached.map(CacheType::Memcached))
            .chain(gcs.map(CacheType::GCS))
            .chain(azure.map(CacheType::Azure))
            .collect();
        let fallback = disk.unwrap_or_else(Default::default);

        (caches, fallback)
    }

    /// Override self with any existing fields from other
    fn merge(&mut self, other: Self) {
        let CacheConfigs {
            azure, disk, gcs, memcached, redis, s3
        } = other;

        if azure.is_some()     { self.azure = azure }
        if disk.is_some()      { self.disk = disk }
        if gcs.is_some()       { self.gcs = gcs }
        if memcached.is_some() { self.memcached = memcached }
        if redis.is_some()     { self.redis = redis }
        if s3.is_some()        { self.s3 = s3 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
pub enum DistToolchainConfig {
    #[serde(rename = "no_dist")]
    NoDist {
        compiler_executable: PathBuf,
    },
    #[serde(rename = "path_override")]
    PathOverride {
        compiler_executable: PathBuf,
        archive: PathBuf,
        archive_compiler_executable: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum DistAuth {
    #[serde(rename = "token")]
    Token { token: String },
    #[serde(rename = "oauth2_code_grant_pkce")]
    Oauth2CodeGrantPKCE { client_id: String, auth_url: String, token_url: String },
    #[serde(rename = "oauth2_implicit")]
    Oauth2Implicit { client_id: String, auth_url: String },
}

// Convert a type = "mozilla" immediately into an actual oauth configuration
// https://github.com/serde-rs/serde/issues/595 could help if implemented
impl<'a> Deserialize<'a> for DistAuth {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error> where D: Deserializer<'a> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[serde(tag = "type")]
        pub enum Helper {
            #[serde(rename = "token")]
            Token { token: String },
            #[serde(rename = "mozilla")]
            Mozilla,
            #[serde(rename = "oauth2_code_grant_pkce")]
            Oauth2CodeGrantPKCE { client_id: String, auth_url: String, token_url: String },
            #[serde(rename = "oauth2_implicit")]
            Oauth2Implicit { client_id: String, auth_url: String },
        }

        let helper: Helper = Deserialize::deserialize(deserializer)?;

        Ok(match helper {
            Helper::Token { token } =>
                DistAuth::Token { token },
            Helper::Mozilla =>
                DistAuth::Oauth2CodeGrantPKCE {
                    client_id: MOZILLA_OAUTH_PKCE_CLIENT_ID.to_owned(),
                    auth_url: MOZILLA_OAUTH_PKCE_AUTH_URL.to_owned(),
                    token_url: MOZILLA_OAUTH_PKCE_TOKEN_URL.to_owned(),
                },
            Helper::Oauth2CodeGrantPKCE { client_id, auth_url, token_url } =>
                DistAuth::Oauth2CodeGrantPKCE { client_id, auth_url, token_url },
            Helper::Oauth2Implicit { client_id, auth_url } =>
                DistAuth::Oauth2Implicit { client_id, auth_url },
        })
    }
}

impl Default for DistAuth {
    fn default() -> Self {
        DistAuth::Token { token: INSECURE_DIST_CLIENT_TOKEN.to_owned() }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DistConfig {
    pub auth: DistAuth,
    #[cfg(any(feature = "dist-client", feature = "dist-server"))]
    pub scheduler_url: Option<HTTPUrl>,
    #[cfg(not(any(feature = "dist-client", feature = "dist-server")))]
    pub scheduler_url: Option<String>,
    pub cache_dir: PathBuf,
    pub toolchains: Vec<DistToolchainConfig>,
    pub toolchain_cache_size: u64,
}

impl Default for DistConfig {
    fn default() -> Self {
        Self {
            auth: Default::default(),
            scheduler_url: Default::default(),
            cache_dir: default_dist_cache_dir(),
            toolchains: Default::default(),
            toolchain_cache_size: default_toolchain_cache_size(),
        }
    }
}

// TODO: fields only pub for tests
#[derive(Debug, Default)]
#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub cache: CacheConfigs,
    pub dist: DistConfig,
}

// If the file doesn't exist or we can't read it, log the issue and proceed. If the
// config exists but doesn't parse then something is wrong - return an error.
pub fn try_read_config_file<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    debug!("Attempting to read config file at {:?}", path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            debug!("Couldn't open config file: {}", e);
            return Ok(None)
        },
    };

    let mut string = String::new();
    match file.read_to_string(&mut string) {
        Ok(_) => (),
        Err(e) => {
            warn!("Failed to read config file: {}", e);
            return Ok(None)
        }
    }

    let res = if path.extension().map_or(false, |e| e == "json") {
        serde_json::from_str(&string)
            .chain_err(|| format!("Failed to load json config file from {}", path.display()))?
    } else {
        toml::from_str(&string)
            .chain_err(|| format!("Failed to load toml config file from {}", path.display()))?
    };

    Ok(Some(res))
}

#[derive(Debug)]
pub struct EnvConfig {
    cache: CacheConfigs,
}

fn config_from_env() -> EnvConfig {
    let s3 = env::var("SCCACHE_BUCKET").ok()
        .map(|bucket| {
            let endpoint = match env::var("SCCACHE_ENDPOINT") {
                Ok(endpoint) => format!("{}/{}", endpoint, bucket),
                _ => match env::var("SCCACHE_REGION") {
                    Ok(ref region) if region != "us-east-1" =>
                        format!("{}.s3-{}.amazonaws.com", bucket, region),
                    _ => format!("{}.s3.amazonaws.com", bucket),
                },
            };

            let get_auth = env::var("SCCACHE_S3_GET_AUTH")
                .ok()
                .map_or(false, |v| v.to_lowercase() == "true");

            S3CacheConfig { bucket, endpoint, get_auth }
        });

    let redis = env::var("SCCACHE_REDIS").ok()
        .map(|url| RedisCacheConfig { url });

    let memcached = env::var("SCCACHE_MEMCACHED").ok()
        .map(|url| MemcachedCacheConfig { url });

    let gcs = env::var("SCCACHE_GCS_BUCKET").ok()
        .map(|bucket| {
            let cred_path = env::var_os("SCCACHE_GCS_KEY_PATH")
                .map(|p| PathBuf::from(p));
            let rw_mode = match env::var("SCCACHE_GCS_RW_MODE")
                                      .as_ref().map(String::as_str) {
                Ok("READ_ONLY") => GCSCacheRWMode::ReadOnly,
                Ok("READ_WRITE") => GCSCacheRWMode::ReadWrite,
                // TODO: unsure if these should warn during the configuration loading
                // or at the time when they're actually used to connect to GCS
                Ok(_) => {
                    warn!("Invalid SCCACHE_GCS_RW_MODE-- defaulting to READ_ONLY.");
                    GCSCacheRWMode::ReadOnly
                },
                _ => {
                    warn!("No SCCACHE_GCS_RW_MODE specified-- defaulting to READ_ONLY.");
                    GCSCacheRWMode::ReadOnly
                }
            };
            GCSCacheConfig { bucket, cred_path, rw_mode }
        });


    let azure = env::var("SCCACHE_AZURE_CONNECTION_STRING").ok()
        .map(|_| AzureCacheConfig);

    let disk = env::var_os("SCCACHE_DIR")
        .map(|p| PathBuf::from(p))
        .map(|dir| {
            let size: u64 = env::var("SCCACHE_CACHE_SIZE")
                .ok()
                .and_then(|v| parse_size(&v))
                .unwrap_or(TEN_GIGS);
            DiskCacheConfig { dir, size }
        });

    let cache = CacheConfigs {
        azure,
        disk,
        gcs,
        memcached,
        redis,
        s3,
    };

    EnvConfig { cache }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub caches: Vec<CacheType>,
    pub fallback_cache: DiskCacheConfig,
    pub dist: DistConfig,
}

impl Config {
    pub fn load() -> Result<Config> {
        let env_conf = config_from_env();

        let file_conf_path = env::var_os("SCCACHE_CONF")
            .map(|p| PathBuf::from(p))
            .unwrap_or_else(|| {
                let dirs = ProjectDirs::from("", ORGANIZATION, APP_NAME)
                    .expect("Unable to get config directory");
                dirs.config_dir().join("config")
            });
        let file_conf = try_read_config_file(&file_conf_path)
            .chain_err(|| "Failed to load config file")?
            .unwrap_or_default();

        Ok(Config::from_env_and_file_configs(env_conf, file_conf))
    }

    fn from_env_and_file_configs(env_conf: EnvConfig, file_conf: FileConfig) -> Config {
        let mut conf_caches: CacheConfigs = Default::default();

        let FileConfig { cache, dist } = file_conf;
        conf_caches.merge(cache);

        let EnvConfig { cache } = env_conf;
        conf_caches.merge(cache);

        let (caches, fallback_cache) = conf_caches.into_vec_and_fallback();
        Config { caches, fallback_cache, dist }
    }
}

#[derive(Clone, Debug, Default)]
#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CachedDistConfig {
    pub auth_tokens: HashMap<String, String>,
}

#[derive(Clone, Debug, Default)]
#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CachedFileConfig {
    pub dist: CachedDistConfig,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CachedConfig(());

impl CachedConfig {
    pub fn load() -> Result<Self> {
        let mut cached_file_config = CACHED_CONFIG.lock().unwrap();

        if cached_file_config.is_none() {
            let cfg = Self::load_file_config().chain_err(|| "Unable to initialise cached config")?;
            *cached_file_config = Some(cfg)
        }
        Ok(CachedConfig(()))
    }
    pub fn with<F: FnOnce(&CachedFileConfig) -> T, T>(&self, f: F) -> T {
        let cached_file_config = CACHED_CONFIG.lock().unwrap();
        let cached_file_config = cached_file_config.as_ref().unwrap();

        f(&cached_file_config)
    }
    pub fn with_mut<F: FnOnce(&mut CachedFileConfig)>(&self, f: F) -> Result<()> {
        let mut cached_file_config = CACHED_CONFIG.lock().unwrap();
        let cached_file_config = cached_file_config.as_mut().unwrap();

        let mut new_config = cached_file_config.clone();
        f(&mut new_config);
        Self::save_file_config(&new_config)?;
        *cached_file_config = new_config;
        Ok(())
    }

    fn file_config_path() -> PathBuf {
        env::var_os("SCCACHE_CACHED_CONF")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let dirs = ProjectDirs::from("", ORGANIZATION, APP_NAME)
                    .expect("Unable to get config directory");
                dirs.config_dir().join("cached-config")
            })
    }
    fn load_file_config() -> Result<CachedFileConfig> {
        let file_conf_path = &*CACHED_CONFIG_PATH;

        if !file_conf_path.exists() {
            let file_conf_dir = file_conf_path.parent().expect("Cached conf file has no parent directory");
            if !file_conf_dir.is_dir() {
                fs::create_dir_all(file_conf_dir).chain_err(|| "Failed to create dir to hold cached config")?
            }
            Self::save_file_config(&Default::default())
                .chain_err(|| format!("Unable to create cached config file at {}", file_conf_path.display()))?
        }
        try_read_config_file(&file_conf_path)
            .chain_err(|| "Failed to load cached config file")?
            .ok_or_else(|| format!("Failed to load from {}", file_conf_path.display()).into())
    }
    fn save_file_config(c: &CachedFileConfig) -> Result<()> {
        let file_conf_path = &*CACHED_CONFIG_PATH;
        let mut file = File::create(file_conf_path).chain_err(|| "Could not open config for writing")?;
        file.write_all(&toml::to_vec(c).unwrap()).map_err(Into::into)
    }
}

#[cfg(feature = "dist-server")]
pub mod scheduler {
    use std::net::SocketAddr;
    use std::path::Path;

    use errors::*;

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ClientAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "token")]
        Token { token: String },
        #[serde(rename = "jwt_validate")]
        JwtValidate { audience: String, issuer: String, jwks_url: String },
        #[serde(rename = "mozilla")]
        Mozilla { required_groups: Vec<String> },
        #[serde(rename = "proxy_token")]
        ProxyToken { url: String, cache_secs: Option<u64> }
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ServerAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "jwt_hs256")]
        JwtHS256 { secret_key: String },
        #[serde(rename = "token")]
        Token { token: String },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub public_addr: SocketAddr,
        pub client_auth: ClientAuth,
        pub server_auth: ServerAuth,
    }

    pub fn from_path(conf_path: &Path) -> Result<Option<Config>> {
        super::try_read_config_file(&conf_path).chain_err(|| "Failed to load scheduler config file")
    }
}

#[cfg(feature = "dist-server")]
pub mod server {
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use super::HTTPUrl;

    use errors::*;

    const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;
    fn default_toolchain_cache_size() -> u64 { TEN_GIGS }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum BuilderType {
        #[serde(rename = "docker")]
        Docker,
        #[serde(rename = "overlay")]
        Overlay { build_dir: PathBuf, bwrap_path: PathBuf },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum SchedulerAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "jwt_token")]
        JwtToken { token: String },
        #[serde(rename = "token")]
        Token { token: String },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub builder: BuilderType,
        pub cache_dir: PathBuf,
        pub public_addr: SocketAddr,
        pub scheduler_url: HTTPUrl,
        pub scheduler_auth: SchedulerAuth,
        #[serde(default = "default_toolchain_cache_size")]
        pub toolchain_cache_size: u64,
    }

    pub fn from_path(conf_path: &Path) -> Result<Option<Config>> {
        super::try_read_config_file(&conf_path).chain_err(|| "Failed to load server config file")
    }
}

#[test]
fn test_parse_size() {
    assert_eq!(None, parse_size(""));
    assert_eq!(None, parse_size("100"));
    assert_eq!(Some(2048), parse_size("2K"));
    assert_eq!(Some(10 * 1024 * 1024), parse_size("10M"));
    assert_eq!(Some(TEN_GIGS), parse_size("10G"));
    assert_eq!(Some(1024 * TEN_GIGS), parse_size("10T"));
}

#[test]
fn config_overrides() {
    let env_conf = EnvConfig {
        cache: CacheConfigs {
            azure: Some(AzureCacheConfig),
            disk: Some(DiskCacheConfig {
                dir: "/env-cache".into(),
                size: 5,
            }),
            redis: Some(RedisCacheConfig {
                url: "myotherredisurl".to_owned(),
            }),
            ..Default::default()
        },
    };

    let file_conf = FileConfig {
        cache: CacheConfigs {
            disk: Some(DiskCacheConfig {
                dir: "/file-cache".into(),
                size: 15,
            }),
            memcached: Some(MemcachedCacheConfig {
                url: "memurl".to_owned(),
            }),
            redis: Some(RedisCacheConfig {
                url: "myredisurl".to_owned(),
            }),
            ..Default::default()
        },
        dist: Default::default(),
    };

    assert_eq!(
        Config::from_env_and_file_configs(env_conf, file_conf),
        Config {
            caches: vec![
                CacheType::Redis(RedisCacheConfig { url: "myotherredisurl".to_owned() }),
                CacheType::Memcached(MemcachedCacheConfig { url: "memurl".to_owned() }),
                CacheType::Azure(AzureCacheConfig),
            ],
            fallback_cache: DiskCacheConfig {
                dir: "/env-cache".into(),
                size: 5,
            },
            dist: Default::default(),
        }
    );
}
