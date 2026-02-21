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

use crate::cache::CacheMode;
#[cfg(target_os = "windows")]
use crate::util::normalize_win_path;
use directories::ProjectDirs;
use fs::File;
use fs_err as fs;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use serde::ser::Serializer;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeOwned, Deserializer},
};
#[cfg(test)]
use serial_test::serial;
use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use std::{collections::HashMap, fmt};
use typed_path::Utf8TypedPathBuf;

use crate::errors::*;

/// Defines how the multi-level cache handles write failures.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WritePolicy {
    /// Never fail on write errors - log warnings only (most permissive)
    Ignore,
    /// Fail only if L0 write fails (default - balances reliability and performance)
    #[default]
    L0,
    /// Fail if any read-write level fails (most strict)
    All,
}

impl FromStr for WritePolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ignore" => Ok(WritePolicy::Ignore),
            "l0" => Ok(WritePolicy::L0),
            "all" => Ok(WritePolicy::All),
            _ => Err(anyhow!(
                "Invalid write policy '{}'. Valid values: ignore, l0, all",
                s
            )),
        }
    }
}

impl fmt::Display for WritePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WritePolicy::Ignore => write!(f, "ignore"),
            WritePolicy::L0 => write!(f, "l0"),
            WritePolicy::All => write!(f, "all"),
        }
    }
}

/// Configuration for multi-level cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiLevelConfig {
    /// Ordered list of cache backends (L0, L1, L2, ...)
    #[serde(rename = "chain")]
    pub chain: Vec<String>,
    /// Write failure handling policy
    #[serde(default)]
    pub write_policy: WritePolicy,
}

static CACHED_CONFIG_PATH: LazyLock<PathBuf> = LazyLock::new(CachedConfig::file_config_path);
static CACHED_CONFIG: Mutex<Option<CachedFileConfig>> = Mutex::new(None);

const ORGANIZATION: &str = "Mozilla";
const APP_NAME: &str = "sccache";
const DIST_APP_NAME: &str = "sccache-dist-client";
const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;

pub const INSECURE_DIST_CLIENT_TOKEN: &str = "dangerously_insecure_client";

// Unfortunately this means that nothing else can use the sccache cache dir as
// this top level directory is used directly to store sccache cached objects...
pub fn default_disk_cache_dir() -> PathBuf {
    ProjectDirs::from("", ORGANIZATION, APP_NAME)
        .expect("Unable to retrieve disk cache directory")
        .cache_dir()
        .to_owned()
}
// ...whereas subdirectories are used of this one
pub fn default_dist_cache_dir() -> PathBuf {
    ProjectDirs::from("", ORGANIZATION, DIST_APP_NAME)
        .expect("Unable to retrieve dist cache directory")
        .cache_dir()
        .to_owned()
}

fn default_disk_cache_size() -> u64 {
    TEN_GIGS
}
fn default_toolchain_cache_size() -> u64 {
    TEN_GIGS
}

struct StringOrU64Visitor;

impl de::Visitor<'_> for StringOrU64Visitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string with size suffix (like '20G') or a u64")
    }

    fn visit_str<E>(self, value: &str) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        parse_size(value).ok_or_else(|| E::custom(format!("Invalid size value: {}", value)))
    }

    fn visit_u64<E>(self, value: u64) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value)
    }

    fn visit_i64<E>(self, value: i64) -> StdResult<Self::Value, E>
    where
        E: de::Error,
    {
        if value < 0 {
            Err(E::custom("negative values not supported"))
        } else {
            Ok(value as u64)
        }
    }
}

fn deserialize_size_from_str<'de, D>(deserializer: D) -> StdResult<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringOrU64Visitor)
}

pub fn parse_size(val: &str) -> Option<u64> {
    let multiplier = match val.chars().last().map(|v| v.to_ascii_uppercase()) {
        Some('K') => 1024,
        Some('M') => 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('T') => 1024 * 1024 * 1024 * 1024,
        _ => 1,
    };
    let val = if multiplier > 1 && !val.is_empty() {
        val.split_at(val.len() - 1).0
    } else {
        val
    };
    u64::from_str(val).ok().map(|size| size * multiplier)
}

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HTTPUrl(reqwest::Url);
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl Serialize for HTTPUrl {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl<'a> Deserialize<'a> for HTTPUrl {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
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
    }?;
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
    pub fn from_url(u: reqwest::Url) -> Self {
        HTTPUrl(u)
    }
    pub fn to_url(&self) -> reqwest::Url {
        self.0.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureCacheConfig {
    pub connection_string: String,
    pub container: String,
    pub key_prefix: String,
}

/// Configuration switches for preprocessor cache mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct PreprocessorCacheModeConfig {
    /// Whether to use preprocessor cache mode entirely
    pub use_preprocessor_cache_mode: bool,
    /// If false (default), only compare header files by hashing their contents.
    /// If true, will use size + ctime + mtime to check whether a file has changed.
    /// See other flags below for more control over this behavior.
    pub file_stat_matches: bool,
    /// If true (default), uses the ctime (file status change on UNIX,
    /// creation time on Windows) to check that a file has/hasn't changed.
    /// Can be useful to disable when backdating modification times
    /// in a controlled manner.
    pub use_ctime_for_stat: bool,
    /// If true, ignore `__DATE__`, `__TIME__` and `__TIMESTAMP__` being present
    /// in the source code. Will speed up preprocessor cache mode,
    /// but can result in false positives.
    pub ignore_time_macros: bool,
    /// If true, preprocessor cache mode will not cache system headers, only
    /// add them to the hash.
    pub skip_system_headers: bool,
    /// If true (default), will add the current working directory in the hash to
    /// distinguish two compilations from different directories.
    pub hash_working_directory: bool,
}

impl Default for PreprocessorCacheModeConfig {
    fn default() -> Self {
        Self {
            use_preprocessor_cache_mode: false,
            file_stat_matches: false,
            use_ctime_for_stat: true,
            ignore_time_macros: false,
            skip_system_headers: false,
            hash_working_directory: true,
        }
    }
}

impl PreprocessorCacheModeConfig {
    /// Return a default [`Self`], but with the cache active.
    pub fn activated() -> Self {
        Self {
            use_preprocessor_cache_mode: true,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct DiskCacheConfig {
    pub dir: PathBuf,
    #[serde(deserialize_with = "deserialize_size_from_str")]
    pub size: u64,
    pub preprocessor_cache_mode: PreprocessorCacheModeConfig,
    pub rw_mode: CacheModeConfig,
}

impl Default for DiskCacheConfig {
    fn default() -> Self {
        DiskCacheConfig {
            dir: default_disk_cache_dir(),
            size: default_disk_cache_size(),
            preprocessor_cache_mode: PreprocessorCacheModeConfig::activated(),
            rw_mode: CacheModeConfig::ReadWrite,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CacheModeConfig {
    #[serde(rename = "READ_ONLY")]
    ReadOnly,
    #[serde(rename = "READ_WRITE")]
    ReadWrite,
}

impl From<CacheModeConfig> for CacheMode {
    fn from(value: CacheModeConfig) -> Self {
        match value {
            CacheModeConfig::ReadOnly => CacheMode::ReadOnly,
            CacheModeConfig::ReadWrite => CacheMode::ReadWrite,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GCSCacheConfig {
    pub bucket: String,
    pub key_prefix: String,
    pub cred_path: Option<String>,
    pub service_account: Option<String>,
    pub rw_mode: CacheModeConfig,
    pub credential_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GHACacheConfig {
    pub enabled: bool,
    /// Version for gha cache is a namespace. By setting different versions,
    /// we can avoid mixed caches.
    pub version: String,
}

/// Memcached's default value of expiration is 10800s (3 hours), which is too
/// short for use case of sccache.
///
/// We increase the default expiration to 86400s (1 day) to balance between
/// memory consumpation and cache hit rate.
///
/// Please change this value freely if we have a better choice.
const DEFAULT_MEMCACHED_CACHE_EXPIRATION: u32 = 86400;

fn default_memcached_cache_expiration() -> u32 {
    DEFAULT_MEMCACHED_CACHE_EXPIRATION
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MemcachedCacheConfig {
    #[serde(alias = "endpoint")]
    pub url: String,

    /// Username to authenticate with.
    pub username: Option<String>,

    /// Password to authenticate with.
    pub password: Option<String>,

    /// the expiration time in seconds.
    ///
    /// Default to 24 hours (86400)
    /// Up to 30 days (2592000)
    #[serde(default = "default_memcached_cache_expiration")]
    pub expiration: u32,

    #[serde(default)]
    pub key_prefix: String,
}

/// redis has no default TTL - all caches live forever
///
/// We keep the TTL as 0 here as redis does
///
/// Please change this value freely if we have a better choice.
const DEFAULT_REDIS_CACHE_TTL: u64 = 0;
pub const DEFAULT_REDIS_DB: u32 = 0;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RedisCacheConfig {
    /// The single-node redis endpoint.
    /// Mutually exclusive with `cluster_endpoints`.
    pub endpoint: Option<String>,

    /// The redis cluster endpoints.
    /// Mutually exclusive with `endpoint`.
    pub cluster_endpoints: Option<String>,

    /// Username to authenticate with.
    pub username: Option<String>,

    /// Password to authenticate with.
    pub password: Option<String>,

    /// The redis URL.
    /// Deprecated in favor of `endpoint`.
    pub url: Option<String>,

    /// the db number to use
    ///
    /// Default to 0
    #[serde(default)]
    pub db: u32,

    /// the ttl (expiration) time in seconds.
    ///
    /// Default to infinity (0)
    #[serde(default, alias = "expiration")]
    pub ttl: u64,

    #[serde(default)]
    pub key_prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebdavCacheConfig {
    pub endpoint: String,
    #[serde(default)]
    pub key_prefix: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3CacheConfig {
    pub bucket: String,
    pub region: Option<String>,
    #[serde(default)]
    pub key_prefix: String,
    pub no_credentials: bool,
    pub endpoint: Option<String>,
    pub use_ssl: Option<bool>,
    pub server_side_encryption: Option<bool>,
    pub enable_virtual_host_style: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OSSCacheConfig {
    pub bucket: String,
    #[serde(default)]
    pub key_prefix: String,
    pub endpoint: Option<String>,
    pub no_credentials: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct COSCacheConfig {
    pub bucket: String,
    #[serde(default)]
    pub key_prefix: String,
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheType {
    Azure(AzureCacheConfig),
    GCS(GCSCacheConfig),
    GHA(GHACacheConfig),
    Memcached(MemcachedCacheConfig),
    Redis(RedisCacheConfig),
    S3(S3CacheConfig),
    Webdav(WebdavCacheConfig),
    OSS(OSSCacheConfig),
    COS(COSCacheConfig),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CacheConfigs {
    pub azure: Option<AzureCacheConfig>,
    pub disk: Option<DiskCacheConfig>,
    pub gcs: Option<GCSCacheConfig>,
    pub gha: Option<GHACacheConfig>,
    pub memcached: Option<MemcachedCacheConfig>,
    pub redis: Option<RedisCacheConfig>,
    pub s3: Option<S3CacheConfig>,
    pub webdav: Option<WebdavCacheConfig>,
    pub oss: Option<OSSCacheConfig>,
    pub cos: Option<COSCacheConfig>,
    /// Multi-level cache configuration
    pub multilevel: Option<MultiLevelConfig>,
}

impl CacheConfigs {
    /// Return cache type in an arbitrary but
    /// consistent ordering (Phase 1 behavior - single cache)
    fn into_fallback(self) -> (Option<CacheType>, DiskCacheConfig) {
        let CacheConfigs {
            azure,
            disk,
            gcs,
            gha,
            memcached,
            redis,
            s3,
            webdav,
            oss,
            cos,
            multilevel: _,
        } = self;

        let cache_type = s3
            .map(CacheType::S3)
            .or_else(|| redis.map(CacheType::Redis))
            .or_else(|| memcached.map(CacheType::Memcached))
            .or_else(|| gcs.map(CacheType::GCS))
            .or_else(|| gha.map(CacheType::GHA))
            .or_else(|| azure.map(CacheType::Azure))
            .or_else(|| webdav.map(CacheType::Webdav))
            .or_else(|| oss.map(CacheType::OSS))
            .or_else(|| cos.map(CacheType::COS));

        let fallback = disk.unwrap_or_default();

        (cache_type, fallback)
    }

    /// Get ordered list of cache types based on configured levels.
    /// If levels are specified, returns them in order with validation.
    /// If no levels specified and single remote cache, returns that single cache.
    /// If no levels and multiple caches, returns error.
    pub fn get_cache_levels(self) -> Result<Vec<CacheType>> {
        if let Some(ml_config) = &self.multilevel {
            // Build caches in the order specified by multilevel chain
            let mut caches = Vec::new();
            for level_name in &ml_config.chain {
                let level_name = level_name.trim();
                let cache_type = match level_name {
                    "s3" => self.s3.clone().map(CacheType::S3).ok_or_else(|| {
                        anyhow!("S3 cache not configured but specified in levels")
                    })?,
                    "redis" => self.redis.clone().map(CacheType::Redis).ok_or_else(|| {
                        anyhow!("Redis cache not configured but specified in levels")
                    })?,
                    "memcached" => self
                        .memcached
                        .clone()
                        .map(CacheType::Memcached)
                        .ok_or_else(|| {
                            anyhow!("Memcached cache not configured but specified in levels")
                        })?,
                    "gcs" => self.gcs.clone().map(CacheType::GCS).ok_or_else(|| {
                        anyhow!("GCS cache not configured but specified in levels")
                    })?,
                    "gha" => self.gha.clone().map(CacheType::GHA).ok_or_else(|| {
                        anyhow!("GHA cache not configured but specified in levels")
                    })?,
                    "azure" => self.azure.clone().map(CacheType::Azure).ok_or_else(|| {
                        anyhow!("Azure cache not configured but specified in levels")
                    })?,
                    "webdav" => self.webdav.clone().map(CacheType::Webdav).ok_or_else(|| {
                        anyhow!("Webdav cache not configured but specified in levels")
                    })?,
                    "oss" => self.oss.clone().map(CacheType::OSS).ok_or_else(|| {
                        anyhow!("OSS cache not configured but specified in levels")
                    })?,
                    "disk" => {
                        // Disk cache is handled separately in MultiLevelStorage::from_config
                        // Mark it by continuing - it will be added to the storage list there
                        continue;
                    }
                    _ => bail!("Unknown cache level: {}", level_name),
                };
                caches.push(cache_type);
            }
            Ok(caches)
        } else {
            // No levels specified - use single cache (backward compatible)
            let (cache_type, _) = self.clone().into_fallback();
            Ok(cache_type.map(|ct| vec![ct]).unwrap_or_default())
        }
    }

    /// Override self with any existing fields from other
    fn merge(&mut self, other: Self) {
        let CacheConfigs {
            azure,
            disk,
            gcs,
            gha,
            memcached,
            redis,
            s3,
            webdav,
            oss,
            cos,
            multilevel,
        } = other;

        if azure.is_some() {
            self.azure = azure;
        }
        if disk.is_some() {
            self.disk = disk;
        }
        if gcs.is_some() {
            self.gcs = gcs;
        }
        if gha.is_some() {
            self.gha = gha;
        }
        if memcached.is_some() {
            self.memcached = memcached;
        }
        if redis.is_some() {
            self.redis = redis;
        }
        if s3.is_some() {
            self.s3 = s3;
        }
        if webdav.is_some() {
            self.webdav = webdav;
        }
        if oss.is_some() {
            self.oss = oss;
        }
        if cos.is_some() {
            self.cos = cos;
        }

        if multilevel.is_some() {
            self.multilevel = multilevel;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
pub enum DistToolchainConfig {
    #[serde(rename = "no_dist")]
    NoDist { compiler_executable: PathBuf },
    #[serde(rename = "path_override")]
    PathOverride {
        compiler_executable: PathBuf,
        archive: PathBuf,
        archive_compiler_executable: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum DistAuth {
    #[serde(rename = "token")]
    Token { token: String },
    #[serde(rename = "oauth2_code_grant_pkce")]
    Oauth2CodeGrantPKCE {
        client_id: String,
        auth_url: String,
        token_url: String,
    },
    #[serde(rename = "oauth2_implicit")]
    Oauth2Implicit { client_id: String, auth_url: String },
}

// Convert a type = "mozilla" immediately into an actual oauth configuration
// https://github.com/serde-rs/serde/issues/595 could help if implemented
impl<'a> Deserialize<'a> for DistAuth {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[serde(tag = "type")]
        pub enum Helper {
            #[serde(rename = "token")]
            Token { token: String },
            #[serde(rename = "oauth2_code_grant_pkce")]
            Oauth2CodeGrantPKCE {
                client_id: String,
                auth_url: String,
                token_url: String,
            },
            #[serde(rename = "oauth2_implicit")]
            Oauth2Implicit { client_id: String, auth_url: String },
        }

        let helper: Helper = Deserialize::deserialize(deserializer)?;

        Ok(match helper {
            Helper::Token { token } => DistAuth::Token { token },
            Helper::Oauth2CodeGrantPKCE {
                client_id,
                auth_url,
                token_url,
            } => DistAuth::Oauth2CodeGrantPKCE {
                client_id,
                auth_url,
                token_url,
            },
            Helper::Oauth2Implicit {
                client_id,
                auth_url,
            } => DistAuth::Oauth2Implicit {
                client_id,
                auth_url,
            },
        })
    }
}

impl Default for DistAuth {
    fn default() -> Self {
        DistAuth::Token {
            token: INSECURE_DIST_CLIENT_TOKEN.to_owned(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(deserialize_with = "deserialize_size_from_str")]
    pub toolchain_cache_size: u64,
    pub rewrite_includes_only: bool,
}

impl Default for DistConfig {
    fn default() -> Self {
        Self {
            auth: Default::default(),
            scheduler_url: Default::default(),
            cache_dir: default_dist_cache_dir(),
            toolchains: Default::default(),
            toolchain_cache_size: default_toolchain_cache_size(),
            rewrite_includes_only: false,
        }
    }
}

// TODO: fields only pub for tests
#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub cache: CacheConfigs,
    pub dist: DistConfig,
    pub server_startup_timeout_ms: Option<u64>,
    /// Base directories to strip from paths for cache key computation.
    pub basedirs: Vec<String>,
}

// If the file doesn't exist or we can't read it, log the issue and proceed. If the
// config exists but doesn't parse then something is wrong - return an error.
pub fn try_read_config_file<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    debug!("Attempting to read config file at {:?}", path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            debug!("Couldn't open config file: {}", e);
            return Ok(None);
        }
    };

    let mut string = String::new();
    match file.read_to_string(&mut string) {
        Ok(_) => (),
        Err(e) => {
            warn!("Failed to read config file: {}", e);
            return Ok(None);
        }
    }

    let res = if path.extension().is_some_and(|e| e == "json") {
        serde_json::from_str(&string)
            .with_context(|| format!("Failed to load json config file from {}", path.display()))?
    } else {
        toml::from_str(&string)
            .with_context(|| format!("Failed to load toml config file from {}", path.display()))?
    };

    Ok(Some(res))
}

#[derive(Debug)]
pub struct EnvConfig {
    cache: CacheConfigs,
    basedirs: Option<Vec<String>>,
}

fn key_prefix_from_env_var(env_var_name: &str) -> String {
    env::var(env_var_name)
        .ok()
        .as_ref()
        .map(|s| s.trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn number_from_env_var<A: std::str::FromStr>(env_var_name: &str) -> Option<Result<A>>
where
    <A as FromStr>::Err: std::fmt::Debug,
{
    let value = env::var(env_var_name).ok()?;

    value
        .parse::<A>()
        .map_err(|err| anyhow!("{env_var_name} value is invalid: {err:?}"))
        .into()
}

fn bool_from_env_var(env_var_name: &str) -> Result<Option<bool>> {
    env::var(env_var_name)
        .ok()
        .map(|value| match value.to_lowercase().as_str() {
            "true" | "on" | "1" => Ok(true),
            "false" | "off" | "0" => Ok(false),
            _ => bail!(
                "{} must be 'true', 'on', '1', 'false', 'off' or '0'.",
                env_var_name
            ),
        })
        .transpose()
}

fn config_from_env() -> Result<EnvConfig> {
    // ======= AWS =======
    let s3 = if let Ok(bucket) = env::var("SCCACHE_BUCKET") {
        let region = env::var("SCCACHE_REGION").ok();
        let no_credentials = bool_from_env_var("SCCACHE_S3_NO_CREDENTIALS")?.unwrap_or(false);
        let use_ssl = bool_from_env_var("SCCACHE_S3_USE_SSL")?;
        let server_side_encryption = bool_from_env_var("SCCACHE_S3_SERVER_SIDE_ENCRYPTION")?;
        let endpoint = env::var("SCCACHE_ENDPOINT").ok();
        let key_prefix = key_prefix_from_env_var("SCCACHE_S3_KEY_PREFIX");
        let enable_virtual_host_style = bool_from_env_var("SCCACHE_S3_ENABLE_VIRTUAL_HOST_STYLE")?;

        Some(S3CacheConfig {
            bucket,
            region,
            no_credentials,
            key_prefix,
            endpoint,
            use_ssl,
            server_side_encryption,
            enable_virtual_host_style,
        })
    } else {
        None
    };

    if s3.as_ref().map(|s3| s3.no_credentials).unwrap_or_default()
        && (env::var_os("AWS_ACCESS_KEY_ID").is_some()
            || env::var_os("AWS_SECRET_ACCESS_KEY").is_some())
    {
        bail!("If setting S3 credentials, SCCACHE_S3_NO_CREDENTIALS must not be set.");
    }

    // ======= redis =======
    let redis = match (
        env::var("SCCACHE_REDIS").ok(),
        env::var("SCCACHE_REDIS_ENDPOINT").ok(),
        env::var("SCCACHE_REDIS_CLUSTER_ENDPOINTS").ok(),
    ) {
        (None, None, None) => None,
        (url, endpoint, cluster_endpoints) => {
            let db = number_from_env_var("SCCACHE_REDIS_DB")
                .transpose()?
                .unwrap_or(DEFAULT_REDIS_DB);

            let username = env::var("SCCACHE_REDIS_USERNAME").ok();
            let password = env::var("SCCACHE_REDIS_PASSWORD").ok();

            let ttl = number_from_env_var("SCCACHE_REDIS_EXPIRATION")
                .or_else(|| number_from_env_var("SCCACHE_REDIS_TTL"))
                .transpose()?
                .unwrap_or(DEFAULT_REDIS_CACHE_TTL);

            let key_prefix = key_prefix_from_env_var("SCCACHE_REDIS_KEY_PREFIX");

            Some(RedisCacheConfig {
                url,
                endpoint,
                cluster_endpoints,
                username,
                password,
                db,
                ttl,
                key_prefix,
            })
        }
    };

    if env::var_os("SCCACHE_REDIS_EXPIRATION").is_some()
        && env::var_os("SCCACHE_REDIS_TTL").is_some()
    {
        bail!("You mustn't set both SCCACHE_REDIS_EXPIRATION and SCCACHE_REDIS_TTL. Use only one.");
    }

    // ======= memcached =======
    let memcached = if let Ok(url) =
        env::var("SCCACHE_MEMCACHED").or_else(|_| env::var("SCCACHE_MEMCACHED_ENDPOINT"))
    {
        let username = env::var("SCCACHE_MEMCACHED_USERNAME").ok();
        let password = env::var("SCCACHE_MEMCACHED_PASSWORD").ok();

        let expiration = number_from_env_var("SCCACHE_MEMCACHED_EXPIRATION")
            .transpose()?
            .unwrap_or(DEFAULT_MEMCACHED_CACHE_EXPIRATION);

        let key_prefix = key_prefix_from_env_var("SCCACHE_MEMCACHED_KEY_PREFIX");

        Some(MemcachedCacheConfig {
            url,
            username,
            password,
            expiration,
            key_prefix,
        })
    } else {
        None
    };

    if env::var_os("SCCACHE_MEMCACHED").is_some()
        && env::var_os("SCCACHE_MEMCACHED_ENDPOINT").is_some()
    {
        bail!(
            "You mustn't set both SCCACHE_MEMCACHED and SCCACHE_MEMCACHED_ENDPOINT. Please, use only SCCACHE_MEMCACHED_ENDPOINT."
        );
    }

    // ======= GCP/GCS =======
    if (env::var("SCCACHE_GCS_CREDENTIALS_URL").is_ok()
        || env::var("SCCACHE_GCS_OAUTH_URL").is_ok()
        || env::var("SCCACHE_GCS_KEY_PATH").is_ok())
        && env::var("SCCACHE_GCS_BUCKET").is_err()
    {
        bail!(
            "If setting GCS credentials, SCCACHE_GCS_BUCKET and an auth mechanism need to be set."
        );
    }

    let gcs = env::var("SCCACHE_GCS_BUCKET").ok().map(|bucket| {
        let key_prefix = key_prefix_from_env_var("SCCACHE_GCS_KEY_PREFIX");

        if env::var("SCCACHE_GCS_OAUTH_URL").is_ok() {
            eprintln!("SCCACHE_GCS_OAUTH_URL has been deprecated");
            eprintln!("if you intend to use vm metadata for auth, please set correct service account instead");
        }

        let credential_url = env::var("SCCACHE_GCS_CREDENTIALS_URL").ok();

        let cred_path = env::var("SCCACHE_GCS_KEY_PATH").ok();
        let service_account = env::var("SCCACHE_GCS_SERVICE_ACCOUNT").ok();

        let rw_mode = match env::var("SCCACHE_GCS_RW_MODE").as_ref().map(String::as_str) {
            Ok("READ_ONLY") => CacheModeConfig::ReadOnly,
            Ok("READ_WRITE") => CacheModeConfig::ReadWrite,
            // TODO: unsure if these should warn during the configuration loading
            // or at the time when they're actually used to connect to GCS
            Ok(_) => {
                warn!("Invalid SCCACHE_GCS_RW_MODE -- defaulting to READ_ONLY.");
                CacheModeConfig::ReadOnly
            }
            _ => {
                warn!("No SCCACHE_GCS_RW_MODE specified -- defaulting to READ_ONLY.");
                CacheModeConfig::ReadOnly
            }
        };

        GCSCacheConfig {
            bucket,
            key_prefix,
            cred_path,
            service_account,
            rw_mode,
            credential_url,
        }
    });

    // ======= GHA =======
    let gha = if let Ok(version) = env::var("SCCACHE_GHA_VERSION") {
        // If SCCACHE_GHA_VERSION has been set, we don't need to check
        // SCCACHE_GHA_ENABLED's value anymore.
        Some(GHACacheConfig {
            enabled: true,
            version,
        })
    } else if bool_from_env_var("SCCACHE_GHA_ENABLED")?.unwrap_or(false) {
        // If only SCCACHE_GHA_ENABLED has been set to the true value, enable with
        // default version.
        Some(GHACacheConfig {
            enabled: true,
            version: String::new(),
        })
    } else {
        None
    };

    // ======= Azure =======
    let azure = if let (Ok(connection_string), Ok(container)) = (
        env::var("SCCACHE_AZURE_CONNECTION_STRING"),
        env::var("SCCACHE_AZURE_BLOB_CONTAINER"),
    ) {
        let key_prefix = key_prefix_from_env_var("SCCACHE_AZURE_KEY_PREFIX");
        Some(AzureCacheConfig {
            connection_string,
            container,
            key_prefix,
        })
    } else {
        None
    };

    // ======= WebDAV =======
    let webdav = if let Ok(endpoint) = env::var("SCCACHE_WEBDAV_ENDPOINT") {
        let key_prefix = key_prefix_from_env_var("SCCACHE_WEBDAV_KEY_PREFIX");
        let username = env::var("SCCACHE_WEBDAV_USERNAME").ok();
        let password = env::var("SCCACHE_WEBDAV_PASSWORD").ok();
        let token = env::var("SCCACHE_WEBDAV_TOKEN").ok();

        Some(WebdavCacheConfig {
            endpoint,
            key_prefix,
            username,
            password,
            token,
        })
    } else {
        None
    };

    // ======= OSS =======
    let oss = if let Ok(bucket) = env::var("SCCACHE_OSS_BUCKET") {
        let endpoint = env::var("SCCACHE_OSS_ENDPOINT").ok();
        let key_prefix = key_prefix_from_env_var("SCCACHE_OSS_KEY_PREFIX");

        let no_credentials = bool_from_env_var("SCCACHE_OSS_NO_CREDENTIALS")?.unwrap_or(false);

        Some(OSSCacheConfig {
            bucket,
            endpoint,
            key_prefix,
            no_credentials,
        })
    } else {
        None
    };

    if oss
        .as_ref()
        .map(|oss| oss.no_credentials)
        .unwrap_or_default()
        && (env::var_os("ALIBABA_CLOUD_ACCESS_KEY_ID").is_some()
            || env::var_os("ALIBABA_CLOUD_ACCESS_KEY_SECRET").is_some())
    {
        bail!("If setting OSS credentials, SCCACHE_OSS_NO_CREDENTIALS must not be set.");
    }

    // ======= COS =======
    let cos = if let Ok(bucket) = env::var("SCCACHE_COS_BUCKET") {
        let endpoint = env::var("SCCACHE_COS_ENDPOINT").ok();
        let key_prefix = key_prefix_from_env_var("SCCACHE_COS_KEY_PREFIX");

        Some(COSCacheConfig {
            bucket,
            endpoint,
            key_prefix,
        })
    } else {
        None
    };

    // ======= Local =======
    let disk_dir = env::var_os("SCCACHE_DIR").map(PathBuf::from);
    let disk_sz = env::var("SCCACHE_CACHE_SIZE")
        .ok()
        .and_then(|v| parse_size(&v));

    let mut preprocessor_mode_config = PreprocessorCacheModeConfig::activated();
    let preprocessor_mode_overridden = if let Some(value) = bool_from_env_var("SCCACHE_DIRECT")? {
        preprocessor_mode_config.use_preprocessor_cache_mode = value;
        true
    } else {
        false
    };

    let (disk_rw_mode, disk_rw_mode_overridden) = match env::var("SCCACHE_LOCAL_RW_MODE")
        .as_ref()
        .map(String::as_str)
    {
        Ok("READ_ONLY") => (CacheModeConfig::ReadOnly, true),
        Ok("READ_WRITE") => (CacheModeConfig::ReadWrite, true),
        Ok(_) => {
            warn!("Invalid SCCACHE_LOCAL_RW_MODE -- defaulting to READ_WRITE.");
            (CacheModeConfig::ReadWrite, false)
        }
        _ => (CacheModeConfig::ReadWrite, false),
    };

    let any_overridden = disk_dir.is_some()
        || disk_sz.is_some()
        || preprocessor_mode_overridden
        || disk_rw_mode_overridden;
    let disk = if any_overridden {
        Some(DiskCacheConfig {
            dir: disk_dir.unwrap_or_else(default_disk_cache_dir),
            size: disk_sz.unwrap_or_else(default_disk_cache_size),
            preprocessor_cache_mode: preprocessor_mode_config,
            rw_mode: disk_rw_mode,
        })
    } else {
        None
    };

    // Parse multi-level cache configuration
    let multilevel = if let Ok(chain_str) = env::var("SCCACHE_MULTILEVEL_CHAIN") {
        let chain: Vec<String> = chain_str.split(',').map(|s| s.trim().to_string()).collect();

        let write_policy = env::var("SCCACHE_MULTILEVEL_WRITE_POLICY")
            .ok()
            .and_then(|s| s.parse::<WritePolicy>().ok())
            .unwrap_or_default();

        Some(MultiLevelConfig {
            chain,
            write_policy,
        })
    } else {
        None
    };

    let cache = CacheConfigs {
        azure,
        disk,
        gcs,
        gha,
        memcached,
        redis,
        s3,
        webdav,
        oss,
        cos,
        multilevel,
    };

    // ======= Base directory =======
    // Support multiple paths separated by ';' on Windows and ':' on other platforms
    // to match PATH behavior.
    #[cfg(target_os = "windows")]
    let split_symbol = ';';
    #[cfg(not(target_os = "windows"))]
    let split_symbol = ':';
    let basedirs = env::var_os("SCCACHE_BASEDIRS").map(|s| {
        s.to_string_lossy()
            .split(split_symbol)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .collect()
    });

    Ok(EnvConfig { cache, basedirs })
}

// The directories crate changed the location of `config_dir` on macos in version 3,
// so we also check the config in `preference_dir` (new in that version), which
// corresponds to the old location, for compatibility with older setups.
fn config_file(env_var: &str, leaf: &str) -> PathBuf {
    if let Some(env_value) = env::var_os(env_var) {
        return env_value.into();
    }
    let dirs =
        ProjectDirs::from("", ORGANIZATION, APP_NAME).expect("Unable to get config directory");
    // If the new location exists, use that.
    let path = dirs.config_dir().join(leaf);
    if path.exists() {
        return path;
    }
    // If the old location exists, use that.
    let path = dirs.preference_dir().join(leaf);
    if path.exists() {
        return path;
    }
    // Otherwise, use the new location.
    dirs.config_dir().join(leaf)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub cache: Option<CacheType>,
    pub cache_configs: CacheConfigs,
    pub fallback_cache: DiskCacheConfig,
    pub dist: DistConfig,
    pub server_startup_timeout: Option<std::time::Duration>,
    /// Base directory (or directories) to strip from paths for cache key computation.
    /// Similar to ccache's CCACHE_BASEDIR.
    pub basedirs: Vec<Vec<u8>>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let env_conf = config_from_env()?;

        let file_conf_path = config_file("SCCACHE_CONF", "config");
        let file_conf = try_read_config_file(&file_conf_path)
            .context("Failed to load config file")?
            .unwrap_or_default();

        Self::from_env_and_file_configs(env_conf, file_conf)
    }

    fn from_env_and_file_configs(env_conf: EnvConfig, file_conf: FileConfig) -> Result<Self> {
        let mut conf_caches: CacheConfigs = Default::default();

        let FileConfig {
            cache,
            dist,
            server_startup_timeout_ms,
            basedirs: file_basedirs,
        } = file_conf;
        conf_caches.merge(cache);

        let server_startup_timeout =
            server_startup_timeout_ms.map(std::time::Duration::from_millis);

        let EnvConfig {
            cache,
            basedirs: env_basedirs,
        } = env_conf;
        conf_caches.merge(cache);

        // Environment variable takes precedence over file config if it is set
        let basedirs_raw = if let Some(basedirs) = env_basedirs {
            basedirs
        } else {
            file_basedirs
        };

        // Validate that all basedirs are absolute paths
        // basedirs_raw is Vec<PathBuf>
        let mut basedirs = Vec::with_capacity(basedirs_raw.len());
        for d in basedirs_raw {
            let p = Utf8TypedPathBuf::from(d);
            if !p.is_absolute() {
                bail!("Basedir path must be absolute: {:?}", p);
            }
            // Normalize basedir:
            // remove double separators, cur_dirs, parent_dirs, trailing slashes
            let p_norm = p.normalize();
            let mut bytes = p_norm.to_string().into_bytes();

            // Always add a trailing `/` to basedirs to ensure we only match complete path
            // components
            bytes.push(b'/');

            // normalize windows paths: use slashes and lowercase
            let normalized = {
                #[cfg(target_os = "windows")]
                {
                    normalize_win_path(&bytes)
                }

                #[cfg(not(target_os = "windows"))]
                {
                    bytes
                }
            };
            // push only if not already present
            if !basedirs.contains(&normalized) {
                basedirs.push(normalized);
            }
        }

        if !basedirs.is_empty() && log::log_enabled!(log::Level::Debug) {
            let basedirs_str: Vec<String> = basedirs
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect();
            debug!("Using basedirs for path normalization: {:?}", basedirs_str);
        }

        let (caches, fallback_cache) = conf_caches.clone().into_fallback();
        Ok(Self {
            cache: caches,
            cache_configs: conf_caches,
            fallback_cache,
            dist,
            server_startup_timeout,
            basedirs,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CachedDistConfig {
    pub auth_tokens: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
            let cfg = Self::load_file_config().context("Unable to initialise cached config")?;
            *cached_file_config = Some(cfg);
        }
        Ok(CachedConfig(()))
    }
    pub fn reload() -> Result<Self> {
        {
            let mut cached_file_config = CACHED_CONFIG.lock().unwrap();
            *cached_file_config = None;
        };
        Self::load()
    }
    pub fn with<F: FnOnce(&CachedFileConfig) -> T, T>(&self, f: F) -> T {
        let cached_file_config = CACHED_CONFIG.lock().unwrap();
        let cached_file_config = cached_file_config.as_ref().unwrap();

        f(cached_file_config)
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
        config_file("SCCACHE_CACHED_CONF", "cached-config")
    }
    fn load_file_config() -> Result<CachedFileConfig> {
        let file_conf_path = &*CACHED_CONFIG_PATH;

        if !file_conf_path.exists() {
            let file_conf_dir = file_conf_path
                .parent()
                .expect("Cached conf file has no parent directory");
            if !file_conf_dir.is_dir() {
                fs::create_dir_all(file_conf_dir)
                    .context("Failed to create dir to hold cached config")?;
            }
            Self::save_file_config(&Default::default()).with_context(|| {
                format!(
                    "Unable to create cached config file at {}",
                    file_conf_path.display()
                )
            })?;
        }
        try_read_config_file(file_conf_path)
            .context("Failed to load cached config file")?
            .with_context(|| format!("Failed to load from {}", file_conf_path.display()))
    }
    fn save_file_config(c: &CachedFileConfig) -> Result<()> {
        let file_conf_path = &*CACHED_CONFIG_PATH;
        let mut file = File::create(file_conf_path).context("Could not open config for writing")?;
        file.write_all(toml::to_string(c).unwrap().as_bytes())
            .map_err(Into::into)
    }
}

#[cfg(feature = "dist-server")]
pub mod scheduler {
    use std::net::SocketAddr;
    use std::path::Path;

    use crate::errors::*;

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ClientAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "token")]
        Token { token: String },
        #[serde(rename = "jwt_validate")]
        JwtValidate {
            audience: String,
            issuer: String,
            jwks_url: String,
        },
        #[serde(rename = "proxy_token")]
        ProxyToken {
            url: String,
            cache_secs: Option<u64>,
        },
    }

    #[derive(Debug, Serialize, Deserialize)]
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

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub public_addr: SocketAddr,
        pub client_auth: ClientAuth,
        pub server_auth: ServerAuth,
    }

    pub fn from_path(conf_path: &Path) -> Result<Option<Config>> {
        super::try_read_config_file(conf_path).context("Failed to load scheduler config file")
    }
}

#[cfg(feature = "dist-server")]
pub mod server {
    use super::HTTPUrl;
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    use crate::errors::*;

    const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;
    fn default_toolchain_cache_size() -> u64 {
        TEN_GIGS
    }

    const DEFAULT_POT_CLONE_FROM: &str = "sccache-template";
    const DEFAULT_POT_FS_ROOT: &str = "/opt/pot";
    const DEFAULT_POT_CMD: &str = "pot";
    const DEFAULT_POT_CLONE_ARGS: &[&str] = &["-i", "lo0|127.0.0.2"];

    fn default_pot_clone_from() -> String {
        DEFAULT_POT_CLONE_FROM.to_string()
    }

    fn default_pot_fs_root() -> PathBuf {
        DEFAULT_POT_FS_ROOT.into()
    }

    fn default_pot_cmd() -> PathBuf {
        DEFAULT_POT_CMD.into()
    }

    fn default_pot_clone_args() -> Vec<String> {
        DEFAULT_POT_CLONE_ARGS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum BuilderType {
        #[serde(rename = "docker")]
        Docker,
        #[serde(rename = "overlay")]
        Overlay {
            build_dir: PathBuf,
            bwrap_path: PathBuf,
        },
        #[serde(rename = "pot")]
        Pot {
            #[serde(default = "default_pot_fs_root")]
            pot_fs_root: PathBuf,
            #[serde(default = "default_pot_clone_from")]
            clone_from: String,
            #[serde(default = "default_pot_cmd")]
            pot_cmd: PathBuf,
            #[serde(default = "default_pot_clone_args")]
            pot_clone_args: Vec<String>,
        },
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
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

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub builder: BuilderType,
        pub cache_dir: PathBuf,
        pub public_addr: SocketAddr,
        pub bind_address: Option<SocketAddr>,
        pub scheduler_url: HTTPUrl,
        pub scheduler_auth: SchedulerAuth,
        #[serde(default = "default_toolchain_cache_size")]
        pub toolchain_cache_size: u64,
    }

    pub fn from_path(conf_path: &Path) -> Result<Option<Config>> {
        super::try_read_config_file(conf_path).context("Failed to load server config file")
    }
}

#[test]
fn test_parse_size() {
    assert_eq!(None, parse_size(""));
    assert_eq!(None, parse_size("bogus value"));
    assert_eq!(Some(100), parse_size("100"));
    assert_eq!(Some(2048), parse_size("2K"));
    assert_eq!(Some(2048), parse_size("2k"));
    assert_eq!(Some(10 * 1024 * 1024), parse_size("10M"));
    assert_eq!(Some(TEN_GIGS), parse_size("10G"));
    assert_eq!(Some(1024 * TEN_GIGS), parse_size("10T"));
}

#[test]
fn config_overrides() {
    let env_conf = EnvConfig {
        cache: CacheConfigs {
            azure: Some(AzureCacheConfig {
                connection_string: String::new(),
                container: String::new(),
                key_prefix: String::new(),
            }),
            disk: Some(DiskCacheConfig {
                dir: "/env-cache".into(),
                size: 5,
                preprocessor_cache_mode: Default::default(),
                rw_mode: CacheModeConfig::ReadWrite,
            }),
            redis: Some(RedisCacheConfig {
                endpoint: Some("myotherredisurl".to_owned()),
                ttl: 24 * 3600,
                key_prefix: "/redis/prefix".into(),
                db: 10,
                username: Some("user".to_owned()),
                password: Some("secret".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        },
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: CacheConfigs {
            disk: Some(DiskCacheConfig {
                dir: "/file-cache".into(),
                size: 15,
                preprocessor_cache_mode: Default::default(),
                rw_mode: CacheModeConfig::ReadWrite,
            }),
            memcached: Some(MemcachedCacheConfig {
                url: "memurl".to_owned(),
                expiration: 24 * 3600,
                key_prefix: String::new(),
                ..Default::default()
            }),
            redis: Some(RedisCacheConfig {
                url: Some("myredisurl".to_owned()),
                ttl: 25 * 3600,
                key_prefix: String::new(),
                ..Default::default()
            }),
            ..Default::default()
        },
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };

    assert_eq!(
        Config::from_env_and_file_configs(env_conf, file_conf).unwrap(),
        Config {
            cache: Some(CacheType::Redis(RedisCacheConfig {
                endpoint: Some("myotherredisurl".to_owned()),
                ttl: 24 * 3600,
                key_prefix: "/redis/prefix".into(),
                db: 10,
                username: Some("user".to_owned()),
                password: Some("secret".to_owned()),
                ..Default::default()
            })),
            cache_configs: CacheConfigs {
                azure: Some(AzureCacheConfig {
                    connection_string: String::new(),
                    container: String::new(),
                    key_prefix: String::new(),
                }),
                disk: Some(DiskCacheConfig {
                    dir: "/env-cache".into(),
                    size: 5,
                    preprocessor_cache_mode: Default::default(),
                    rw_mode: CacheModeConfig::ReadWrite,
                }),
                memcached: Some(MemcachedCacheConfig {
                    url: "memurl".to_owned(),
                    expiration: 24 * 3600,
                    key_prefix: String::new(),
                    ..Default::default()
                }),
                redis: Some(RedisCacheConfig {
                    endpoint: Some("myotherredisurl".to_owned()),
                    ttl: 24 * 3600,
                    key_prefix: "/redis/prefix".into(),
                    db: 10,
                    username: Some("user".to_owned()),
                    password: Some("secret".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            fallback_cache: DiskCacheConfig {
                dir: "/env-cache".into(),
                size: 5,
                preprocessor_cache_mode: Default::default(),
                rw_mode: CacheModeConfig::ReadWrite,
            },
            dist: Default::default(),
            server_startup_timeout: None,
            basedirs: vec![],
        }
    );
}

#[test]
#[cfg(target_os = "windows")]
fn config_basedirs_overrides() {
    // Test that env variable takes precedence over file config
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: vec!["C:/env/basedir".to_string()].into(),
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["C:/file/basedir".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert_eq!(config.basedirs, vec![b"c:/env/basedir/".to_vec()]);

    // Test that file config is used when env is None
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["C:/file/basedir".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert_eq!(config.basedirs, vec![b"c:/file/basedir/".to_vec()]);

    // Test that env config is used when env is set but empty
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: vec![].into(),
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["C:/file/basedir".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert!(config.basedirs.is_empty());

    // Test that both empty results in empty
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: vec![].into(),
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert!(config.basedirs.is_empty());
}

#[test]
#[cfg(not(target_os = "windows"))]
fn config_basedirs_overrides() {
    // Test that env variable takes precedence over file config
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: vec!["/env/basedir".to_string()].into(),
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/file/basedir".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert_eq!(config.basedirs, vec![b"/env/basedir/".to_vec()]);

    // Test that file config is used when env is None
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/file/basedir".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert_eq!(config.basedirs, vec![b"/file/basedir/".to_vec()]);

    // Test that env config is used when env is set but empty
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: vec![].into(),
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/file/basedir".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert!(config.basedirs.is_empty());

    // Test that both empty results in empty
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: vec![].into(),
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert!(config.basedirs.is_empty());
    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert!(config.basedirs.is_empty());
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_deserialize_basedirs() {
    // Test array of paths
    let toml = r#"
        basedirs = ["/home/user/project", "/home/user/workspace"]

        [cache.disk]
        dir = "/tmp/cache"
        size = 1073741824

        [dist]
    "#;

    let config: FileConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        config.basedirs,
        vec![
            "/home/user/project".to_string(),
            "/home/user/workspace".to_string()
        ]
    );
}

#[test]
fn test_deserialize_basedirs_missing() {
    // Test no basedirs specified (should default to empty vec)
    let toml = r#"
        [cache.disk]
        dir = "/tmp/cache"
        size = 1073741824

        [dist]
    "#;

    let config: FileConfig = toml::from_str(toml).unwrap();
    assert!(config.basedirs.is_empty());
}

#[test]
#[serial(config_from_env)]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_single() {
    unsafe {
        std::env::set_var("SCCACHE_BASEDIRS", "/home/user/project");
    }
    let config = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec!["/home/user/project".to_string()]
    );
}

#[test]
#[serial(config_from_env)]
#[cfg(target_os = "windows")]
fn test_env_basedirs_single() {
    unsafe {
        std::env::set_var("SCCACHE_BASEDIRS", "C:/home/user/project");
    }
    let config = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec!["C:/home/user/project".to_string()]
    );
}

#[test]
#[serial(config_from_env)]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_multiple() {
    unsafe {
        std::env::set_var(
            "SCCACHE_BASEDIRS",
            "/home/user/project:/home/user/workspace",
        );
    }
    let config = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "/home/user/project".to_string(),
            "/home/user/workspace".to_string()
        ]
    );
}

#[test]
#[serial(config_from_env)]
#[cfg(target_os = "windows")]
fn test_env_basedirs_multiple() {
    unsafe {
        std::env::set_var(
            "SCCACHE_BASEDIRS",
            "C:/home/user/project;C:/home/user/workspace",
        );
    }
    let config = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "C:/home/user/project".to_string(),
            "C:/home/user/workspace".to_string()
        ]
    );
}

#[test]
#[serial(config_from_env)]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_with_spaces() {
    // Test that spaces around paths are not trimmed
    unsafe {
        std::env::set_var(
            "SCCACHE_BASEDIRS",
            " /home/user/project : /home/user/workspace ",
        );
    }
    let env_conf = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        env_conf.basedirs.clone().expect("SCCACHE_BASEDIRS is set"),
        vec![
            " /home/user/project ".to_string(),
            " /home/user/workspace ".to_string()
        ]
    );
    // The lead to trailing spaces are preserved and server fails to start
    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };
    Config::from_env_and_file_configs(env_conf, file_conf)
        .expect_err("Should fail due to non-absolute path");
}

#[test]
#[serial(config_from_env)]
#[cfg(target_os = "windows")]
fn test_env_basedirs_with_spaces() {
    // Test that spaces around paths are not trimmed
    unsafe {
        std::env::set_var(
            "SCCACHE_BASEDIRS",
            " C:/home/user/project ; C:/home/user/workspace ",
        );
    }
    let env_conf = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        env_conf.basedirs.clone().expect("SCCACHE_BASEDIRS is set"),
        vec![
            " C:/home/user/project ".to_string(),
            " C:/home/user/workspace ".to_string()
        ]
    );
    // The lead to trailing spaces are preserved and server fails to start
    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };
    Config::from_env_and_file_configs(env_conf, file_conf)
        .expect_err("Should fail due to non-absolute path");
}

#[test]
#[serial(config_from_env)]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_empty_entries() {
    // Test that empty entries are filtered out
    unsafe {
        std::env::set_var(
            "SCCACHE_BASEDIRS",
            "/home/user/project::/home/user/workspace",
        );
    }
    let config = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "/home/user/project".to_string(),
            "/home/user/workspace".to_string()
        ]
    );
}

#[test]
#[serial(config_from_env)]
#[cfg(target_os = "windows")]
fn test_env_basedirs_empty_entries() {
    // Test that empty entries are filtered out
    unsafe {
        std::env::set_var(
            "SCCACHE_BASEDIRS",
            "c:/home/user/project;;c:/home/user/workspace",
        );
    }
    let config = config_from_env().unwrap();
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "c:/home/user/project".to_string(),
            "c:/home/user/workspace".to_string()
        ]
    );
}

#[test]
#[serial(config_from_env)]
fn test_env_basedirs_not_set() {
    unsafe {
        std::env::remove_var("SCCACHE_BASEDIRS");
    }
    let config = config_from_env().unwrap();
    assert!(config.basedirs.is_none());
}

#[test]
#[serial(config_from_env)]
#[cfg(feature = "s3")]
fn test_s3_no_credentials_conflict() {
    unsafe {
        env::set_var("SCCACHE_S3_NO_CREDENTIALS", "true");
        env::set_var("SCCACHE_BUCKET", "my-bucket");
        env::set_var("AWS_ACCESS_KEY_ID", "aws-access-key-id");
        env::set_var("AWS_SECRET_ACCESS_KEY", "aws-secret-access-key");
    }

    let cfg = config_from_env();

    unsafe {
        env::remove_var("SCCACHE_S3_NO_CREDENTIALS");
        env::remove_var("SCCACHE_BUCKET");
        env::remove_var("AWS_ACCESS_KEY_ID");
        env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    let error = cfg.unwrap_err();
    assert_eq!(
        "If setting S3 credentials, SCCACHE_S3_NO_CREDENTIALS must not be set.",
        error.to_string()
    );
}

#[test]
#[serial(config_from_env)]
fn test_s3_no_credentials_invalid() {
    unsafe {
        env::set_var("SCCACHE_S3_NO_CREDENTIALS", "yes");
        env::set_var("SCCACHE_BUCKET", "my-bucket");
    }

    let cfg = config_from_env();

    unsafe {
        env::remove_var("SCCACHE_S3_NO_CREDENTIALS");
        env::remove_var("SCCACHE_BUCKET");
    }

    let error = cfg.unwrap_err();
    assert_eq!(
        "SCCACHE_S3_NO_CREDENTIALS must be 'true', 'on', '1', 'false', 'off' or '0'.",
        error.to_string()
    );
}

#[test]
#[serial(config_from_env)]
fn test_s3_no_credentials_valid_true() {
    unsafe {
        env::set_var("SCCACHE_S3_NO_CREDENTIALS", "true");
        env::set_var("SCCACHE_BUCKET", "my-bucket");
    }

    let cfg = config_from_env();

    unsafe {
        env::remove_var("SCCACHE_S3_NO_CREDENTIALS");
        env::remove_var("SCCACHE_BUCKET");
    }

    let env_cfg = cfg.unwrap();
    match env_cfg.cache.s3 {
        Some(S3CacheConfig {
            ref bucket,
            no_credentials,
            ..
        }) => {
            assert_eq!(bucket, "my-bucket");
            assert!(no_credentials);
        }
        None => unreachable!(),
    }
}

#[test]
#[serial(config_from_env)]
fn test_s3_no_credentials_valid_false() {
    unsafe {
        env::set_var("SCCACHE_S3_NO_CREDENTIALS", "false");
        env::set_var("SCCACHE_BUCKET", "my-bucket");
    }

    let cfg = config_from_env();

    unsafe {
        env::remove_var("SCCACHE_S3_NO_CREDENTIALS");
        env::remove_var("SCCACHE_BUCKET");
    }

    let env_cfg = cfg.unwrap();
    match env_cfg.cache.s3 {
        Some(S3CacheConfig {
            ref bucket,
            no_credentials,
            ..
        }) => {
            assert_eq!(bucket, "my-bucket");
            assert!(!no_credentials);
        }
        None => unreachable!(),
    }
}

#[test]
#[serial(config_from_env)]
#[cfg(feature = "gcs")]
fn test_gcs_service_account() {
    unsafe {
        env::set_var("SCCACHE_GCS_BUCKET", "my-bucket");
        env::set_var("SCCACHE_GCS_SERVICE_ACCOUNT", "my@example.com");
        env::set_var("SCCACHE_GCS_RW_MODE", "READ_WRITE");
    }

    let cfg = config_from_env();

    unsafe {
        env::remove_var("SCCACHE_GCS_BUCKET");
        env::remove_var("SCCACHE_GCS_SERVICE_ACCOUNT");
        env::remove_var("SCCACHE_GCS_RW_MODE");
    }

    let env_cfg = cfg.unwrap();
    match env_cfg.cache.gcs {
        Some(GCSCacheConfig {
            ref bucket,
            service_account,
            rw_mode,
            ..
        }) => {
            assert_eq!(bucket, "my-bucket");
            assert_eq!(service_account, Some("my@example.com".to_string()));
            assert_eq!(rw_mode, CacheModeConfig::ReadWrite);
        }
        None => unreachable!(),
    }
}

#[test]
fn full_toml_parse() {
    const CONFIG_STR: &str = r#"
server_startup_timeout_ms = 10000

[dist]
# where to find the scheduler
scheduler_url = "http://1.2.3.4:10600"
# a set of prepackaged toolchains
toolchains = []
# the maximum size of the toolchain cache in bytes
toolchain_cache_size = 5368709120
cache_dir = "/home/user/.cache/sccache-dist-client"

[dist.auth]
type = "token"
token = "secrettoken"


#[cache.azure]
# does not work as it appears

[cache.disk]
dir = "/tmp/.cache/sccache"
size = 7516192768 # 7 GiBytes

[cache.gcs]
rw_mode = "READ_ONLY"
# rw_mode = "READ_WRITE"
cred_path = "/psst/secret/cred"
bucket = "bucket"
key_prefix = "prefix"
service_account = "example_service_account"

[cache.gha]
enabled = true
version = "sccache"

[cache.memcached]
# Deprecated alias for `endpoint`
# url = "127.0.0.1:11211"
endpoint = "tcp://127.0.0.1:11211"
# Username and password for authentication
username = "user"
password = "passwd"
expiration = 90000
key_prefix = "/custom/prefix/if/need"

[cache.redis]
url = "redis://user:passwd@1.2.3.4:6379/?db=1"
endpoint = "redis://127.0.0.1:6379"
cluster_endpoints = "tcp://10.0.0.1:6379,redis://10.0.0.2:6379"
username = "another_user"
password = "new_passwd"
db = 12
expiration = 86400
key_prefix = "/my/redis/cache"

[cache.s3]
bucket = "name"
region = "us-east-2"
endpoint = "s3-us-east-1.amazonaws.com"
use_ssl = true
key_prefix = "s3prefix"
no_credentials = true
server_side_encryption = false

[cache.webdav]
endpoint = "http://127.0.0.1:8080"
key_prefix = "webdavprefix"
username = "webdavusername"
password = "webdavpassword"
token = "webdavtoken"

[cache.oss]
bucket = "name"
endpoint = "oss-us-east-1.aliyuncs.com"
key_prefix = "ossprefix"
no_credentials = true

[cache.cos]
bucket = "name"
endpoint = "cos.na-siliconvalley.myqcloud.com"
key_prefix = "cosprefix"
"#;

    let file_config: FileConfig = toml::from_str(CONFIG_STR).expect("Is valid toml.");
    assert_eq!(
        file_config,
        FileConfig {
            cache: CacheConfigs {
                azure: None, // TODO not sure how to represent a unit struct in TOML Some(AzureCacheConfig),
                disk: Some(DiskCacheConfig {
                    dir: PathBuf::from("/tmp/.cache/sccache"),
                    size: 7 * 1024 * 1024 * 1024,
                    preprocessor_cache_mode: PreprocessorCacheModeConfig::activated(),
                    rw_mode: CacheModeConfig::ReadWrite,
                }),
                gcs: Some(GCSCacheConfig {
                    bucket: "bucket".to_owned(),
                    cred_path: Some("/psst/secret/cred".to_string()),
                    service_account: Some("example_service_account".to_string()),
                    rw_mode: CacheModeConfig::ReadOnly,
                    key_prefix: "prefix".into(),
                    credential_url: None,
                }),
                gha: Some(GHACacheConfig {
                    enabled: true,
                    version: "sccache".to_string()
                }),
                redis: Some(RedisCacheConfig {
                    url: Some("redis://user:passwd@1.2.3.4:6379/?db=1".to_owned()),
                    endpoint: Some("redis://127.0.0.1:6379".to_owned()),
                    cluster_endpoints: Some("tcp://10.0.0.1:6379,redis://10.0.0.2:6379".to_owned()),
                    username: Some("another_user".to_owned()),
                    password: Some("new_passwd".to_owned()),
                    db: 12,
                    ttl: 24 * 3600,
                    key_prefix: "/my/redis/cache".into(),
                }),
                memcached: Some(MemcachedCacheConfig {
                    url: "tcp://127.0.0.1:11211".to_owned(),
                    username: Some("user".to_owned()),
                    password: Some("passwd".to_owned()),
                    expiration: 25 * 3600,
                    key_prefix: "/custom/prefix/if/need".into(),
                }),
                s3: Some(S3CacheConfig {
                    bucket: "name".to_owned(),
                    region: Some("us-east-2".to_owned()),
                    endpoint: Some("s3-us-east-1.amazonaws.com".to_owned()),
                    use_ssl: Some(true),
                    key_prefix: "s3prefix".into(),
                    no_credentials: true,
                    server_side_encryption: Some(false),
                    enable_virtual_host_style: None,
                }),
                webdav: Some(WebdavCacheConfig {
                    endpoint: "http://127.0.0.1:8080".to_string(),
                    key_prefix: "webdavprefix".into(),
                    username: Some("webdavusername".to_string()),
                    password: Some("webdavpassword".to_string()),
                    token: Some("webdavtoken".to_string()),
                }),
                oss: Some(OSSCacheConfig {
                    bucket: "name".to_owned(),
                    endpoint: Some("oss-us-east-1.aliyuncs.com".to_owned()),
                    key_prefix: "ossprefix".into(),
                    no_credentials: true,
                }),
                cos: Some(COSCacheConfig {
                    bucket: "name".to_owned(),
                    endpoint: Some("cos.na-siliconvalley.myqcloud.com".to_owned()),
                    key_prefix: "cosprefix".into(),
                }),
                multilevel: None,
            },
            dist: DistConfig {
                auth: DistAuth::Token {
                    token: "secrettoken".to_owned()
                },
                #[cfg(any(feature = "dist-client", feature = "dist-server"))]
                scheduler_url: Some(
                    parse_http_url("http://1.2.3.4:10600")
                        .map(|url| { HTTPUrl::from_url(url) })
                        .expect("Scheduler url must be valid url str")
                ),
                #[cfg(not(any(feature = "dist-client", feature = "dist-server")))]
                scheduler_url: Some("http://1.2.3.4:10600".to_owned()),
                cache_dir: PathBuf::from("/home/user/.cache/sccache-dist-client"),
                toolchains: vec![],
                toolchain_cache_size: 5368709120,
                rewrite_includes_only: false,
            },
            server_startup_timeout_ms: Some(10000),
            basedirs: vec![],
        }
    );
}

#[test]
#[cfg(feature = "dist-server")]
fn server_toml_parse() {
    use server::BuilderType;
    use server::SchedulerAuth;
    const CONFIG_STR: &str = r#"
    # This is where client toolchains will be stored.
    cache_dir = "/tmp/toolchains"
    # The maximum size of the toolchain cache, in bytes.
    # If unspecified the default is 10GB.
    toolchain_cache_size = 10737418240
    # A public IP address and port that clients will use to connect to this builder.
    public_addr = "192.168.1.1:10501"
    # The socket address the builder will listen on.
    bind_address = "0.0.0.0:10501"
    # The URL used to connect to the scheduler (should use https, given an ideal
    # setup of a HTTPS server in front of the scheduler)
    scheduler_url = "https://192.168.1.1"

    [builder]
    type = "overlay"
    # The directory under which a sandboxed filesystem will be created for builds.
    build_dir = "/tmp/build"
    # The path to the bubblewrap version 0.3.0+ `bwrap` binary.
    bwrap_path = "/usr/bin/bwrap"

    [scheduler_auth]
    type = "jwt_token"
    # This will be generated by the `generate-jwt-hs256-server-token` command or
    # provided by an administrator of the sccache cluster.
    token = "my server's token"
    "#;

    let server_config: server::Config = toml::from_str(CONFIG_STR).expect("Is valid toml.");
    assert_eq!(
        server_config,
        server::Config {
            builder: BuilderType::Overlay {
                build_dir: PathBuf::from("/tmp/build"),
                bwrap_path: PathBuf::from("/usr/bin/bwrap"),
            },
            cache_dir: PathBuf::from("/tmp/toolchains"),
            public_addr: "192.168.1.1:10501"
                .parse()
                .expect("Public address must be valid socket address"),
            bind_address: Some(
                "0.0.0.0:10501"
                    .parse()
                    .expect("Bind address must be valid socket address")
            ),

            scheduler_url: parse_http_url("https://192.168.1.1")
                .map(|url| { HTTPUrl::from_url(url) })
                .expect("Scheduler url must be valid url str"),
            scheduler_auth: SchedulerAuth::JwtToken {
                token: "my server's token".to_owned()
            },
            toolchain_cache_size: 10737418240,
        }
    )
}

#[test]
fn human_units_parse() {
    const CONFIG_STR: &str = r#"
[dist]
toolchain_cache_size = "5g"

[cache.disk]
size = "7g"
"#;

    let file_config: FileConfig = toml::from_str(CONFIG_STR).expect("Is valid toml.");
    assert_eq!(
        file_config,
        FileConfig {
            cache: CacheConfigs {
                disk: Some(DiskCacheConfig {
                    size: 7 * 1024 * 1024 * 1024,
                    ..Default::default()
                }),
                ..Default::default()
            },
            dist: DistConfig {
                toolchain_cache_size: 5 * 1024 * 1024 * 1024,
                ..Default::default()
            },
            server_startup_timeout_ms: None,
            basedirs: vec![],
        }
    );
}

// Integration tests: Config normalization + strip_basedirs usage

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_config_normalizes_and_strips() {
    // Test that Config normalizes basedirs and strip_basedirs uses them correctly
    use crate::util::strip_basedirs;
    use std::borrow::Cow;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/home/user/project".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Verify config normalized the basedir with trailing slash
    assert_eq!(config.basedirs, vec![b"/home/user/project/"]);

    // Test that strip_basedirs uses the normalized basedir
    let input = b"# 1 \"/home/user/project/src/main.c\"\nint main() { return 0; }";
    let output = strip_basedirs(input, &config.basedirs);

    // Should strip the basedir
    let expected = b"# 1 \"src/main.c\"\nint main() { return 0; }";
    assert_eq!(&*output, expected);
    assert!(matches!(output, Cow::Owned(_)));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_normalized_path_with_double_slashes() {
    // Test that Config normalizes paths with double slashes
    use crate::util::strip_basedirs;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/home//user///project/".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Config should normalize to single slashes with one trailing slash
    assert_eq!(config.basedirs, vec![b"/home/user/project/"]);

    // Verify it works with strip_basedirs
    let input = b"# 1 \"/home/user/project/src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);
    assert_eq!(&*output, b"# 1 \"src/main.c\"");
}

#[test]
#[cfg(target_os = "windows")]
fn test_integration_windows_path_normalization() {
    // Test that Config normalizes Windows paths correctly
    use crate::util::strip_basedirs;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["C:\\Users\\Test\\Project".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Should be normalized to lowercase with forward slashes
    assert_eq!(config.basedirs, vec![b"c:/users/test/project/"]);

    // Test with mixed case preprocessor output
    let input = b"# 1 \"C:\\Users\\Test\\Project\\src\\main.c\"";
    let output = strip_basedirs(input, &config.basedirs);
    assert_eq!(&*output, b"# 1 \"src\\main.c\"");
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_cow_borrowed_when_no_match() {
    // Test that strip_basedirs returns Cow::Borrowed when no stripping occurs
    use crate::util::strip_basedirs;
    use std::borrow::Cow;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/home/user/project".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Input doesn't contain the basedir
    let input = b"# 1 \"/other/path/main.c\"\nint main() { return 0; }";
    let output = strip_basedirs(input, &config.basedirs);

    // Should return borrowed reference (no allocation)
    assert!(matches!(output, Cow::Borrowed(_)));
    assert_eq!(&*output, input);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_cow_borrowed_when_empty_basedirs() {
    // Test that strip_basedirs returns Cow::Borrowed when basedirs is empty
    use crate::util::strip_basedirs;
    use std::borrow::Cow;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec![],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert!(config.basedirs.is_empty());

    let input = b"# 1 \"/home/user/project/src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);

    // Should return borrowed reference when basedirs is empty
    assert!(matches!(output, Cow::Borrowed(_)));
    assert_eq!(&*output, input);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_multiple_basedirs_longest_match() {
    // Test that strip_basedirs prefers longest match with normalized basedirs
    use crate::util::strip_basedirs;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/home/user".to_string(), "/home/user/project".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Both should be normalized with trailing slashes
    assert_eq!(config.basedirs.len(), 2);
    assert_eq!(config.basedirs[0], b"/home/user/");
    assert_eq!(config.basedirs[1], b"/home/user/project/");

    // Input matches both, but longest should win
    let input = b"# 1 \"/home/user/project/src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);

    // Should match the longest basedir (/home/user/project/)
    let expected = b"# 1 \"src/main.c\"";
    assert_eq!(&*output, expected);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_paths_with_dots_normalized() {
    // Test that paths with . and .. are normalized correctly
    use crate::util::strip_basedirs;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["/home/user/./project/../project".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Should be normalized to remove ./ and ../
    assert_eq!(config.basedirs[0], b"/home/user/project/");

    // Verify it works with strip_basedirs
    let input = b"# 1 \"/home/user/project/src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);
    let expected = b"# 1 \"src/main.c\"";
    assert_eq!(&*output, expected);
}

#[test]
#[cfg(target_os = "windows")]
fn test_integration_windows_mixed_slashes() {
    // Test Windows path with mixed slashes in preprocessor output
    use crate::util::strip_basedirs;

    let env_conf = EnvConfig {
        cache: Default::default(),
        basedirs: None,
    };

    let file_conf = FileConfig {
        cache: Default::default(),
        dist: Default::default(),
        server_startup_timeout_ms: None,
        basedirs: vec!["C:\\Users\\test\\project".to_string()],
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert_eq!(config.basedirs[0], b"c:/users/test/project/");

    // Preprocessor output with mixed slashes
    let input = b"# 1 \"C:/Users\\test\\project\\src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);

    // Should strip despite mixed slashes
    let expected = b"# 1 \"src/main.c\"";
    assert_eq!(&*output, expected);
}

#[test]
#[serial(config_from_env)]
#[cfg(not(target_os = "windows"))]
fn test_integration_env_variable_to_strip() {
    // Test full flow: SCCACHE_BASEDIRS env var -> Config -> strip_basedirs
    use crate::util::strip_basedirs;

    unsafe {
        env::set_var("SCCACHE_BASEDIRS", "/home/user/project:/tmp/build");
    }

    let env_conf = config_from_env().unwrap();
    let file_conf = FileConfig::default();
    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    unsafe {
        env::remove_var("SCCACHE_BASEDIRS");
    }

    // Should have two normalized basedirs
    assert_eq!(config.basedirs.len(), 2);
    assert_eq!(config.basedirs[0], b"/home/user/project/");
    assert_eq!(config.basedirs[1], b"/tmp/build/");

    // Test stripping with both
    let input1 = b"# 1 \"/home/user/project/src/main.c\"";
    let output1 = strip_basedirs(input1, &config.basedirs);
    assert_eq!(&*output1, b"# 1 \"src/main.c\"");

    let input2 = b"# 1 \"/tmp/build/obj/file.o\"";
    let output2 = strip_basedirs(input2, &config.basedirs);
    assert_eq!(&*output2, b"# 1 \"obj/file.o\"");
}

#[test]
fn test_cache_levels_parsing() {
    // Test parsing cache levels from config
    let config_str = r#"
[cache.disk]
dir = "/tmp/disk"
size = 1024

[cache.s3]
bucket = "my-bucket"
region = "us-west-2"
no_credentials = false

[cache.redis]
endpoint = "redis://localhost"

[cache.multilevel]
chain = ["disk", "redis", "s3"]
"#;

    let file_config: FileConfig = toml::from_str(config_str).expect("Is valid toml");
    assert!(file_config.cache.multilevel.is_some());
    let ml_config = file_config.cache.multilevel.unwrap();
    assert_eq!(ml_config.chain.len(), 3);
    assert_eq!(ml_config.chain[0], "disk");
    assert_eq!(ml_config.chain[1], "redis");
    assert_eq!(ml_config.chain[2], "s3");
}

#[test]
fn test_cache_levels_backward_compatibility() {
    // Test that configs without levels still work (single cache selection)
    let config_str = r#"
[cache.s3]
bucket = "my-bucket"
region = "us-west-2"
no_credentials = false
"#;

    let file_config: FileConfig = toml::from_str(config_str).expect("Is valid toml");
    assert!(file_config.cache.multilevel.is_none());
    assert!(file_config.cache.s3.is_some());
}

#[test]
fn test_get_cache_levels_single_cache() {
    let configs = CacheConfigs {
        s3: Some(S3CacheConfig {
            bucket: "test".to_string(),
            region: None,
            key_prefix: String::new(),
            no_credentials: false,
            endpoint: None,
            use_ssl: None,
            server_side_encryption: None,
            enable_virtual_host_style: None,
        }),
        ..Default::default()
    };

    let levels = configs.get_cache_levels().expect("Should get single cache");
    assert_eq!(levels.len(), 1);
}

#[test]
fn test_get_cache_levels_invalid_level() {
    let configs = CacheConfigs {
        multilevel: Some(MultiLevelConfig {
            chain: vec!["unknown_cache".to_string()],
            write_policy: WritePolicy::default(),
        }),
        ..Default::default()
    };

    let result = configs.get_cache_levels();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unknown cache level")
    );
}

#[test]
fn test_get_cache_levels_missing_config() {
    let configs = CacheConfigs {
        multilevel: Some(MultiLevelConfig {
            chain: vec!["s3".to_string()],
            write_policy: WritePolicy::default(),
        }),
        ..Default::default()
    };

    let result = configs.get_cache_levels();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("S3 cache not configured")
    );
}
