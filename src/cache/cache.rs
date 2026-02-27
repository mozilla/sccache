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

use super::cache_io::*;
#[cfg(feature = "azure")]
use crate::cache::azure::AzureBlobCache;
#[cfg(feature = "cos")]
use crate::cache::cos::COSCache;
use crate::cache::disk::DiskCache;
#[cfg(feature = "gcs")]
use crate::cache::gcs::GCSCache;
#[cfg(feature = "gha")]
use crate::cache::gha::GHACache;
#[cfg(feature = "memcached")]
use crate::cache::memcached::MemcachedCache;
#[cfg(feature = "oss")]
use crate::cache::oss::OSSCache;
#[cfg(feature = "redis")]
use crate::cache::redis::RedisCache;
#[cfg(feature = "s3")]
use crate::cache::s3::S3Cache;
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::cache::utils::normalize_key;
#[cfg(feature = "webdav")]
use crate::cache::webdav::WebdavCache;
use crate::compiler::PreprocessorCacheEntry;
use crate::config::Config;
use crate::config::{self, CacheType, PreprocessorCacheModeConfig};
use async_trait::async_trait;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::errors::*;

/// An interface to cache storage.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    async fn get(&self, key: &str) -> Result<Cache>;

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration>;

    /// Check the cache capability.
    ///
    /// - `Ok(CacheMode::ReadOnly)` means cache can only be used to `get`
    ///   cache.
    /// - `Ok(CacheMode::ReadWrite)` means cache can do both `get` and `put`.
    /// - `Err(err)` means cache is not setup correctly or not match with
    ///   users input (for example, user try to use `ReadWrite` but cache
    ///   is `ReadOnly`).
    ///
    /// We will provide a default implementation which returns
    /// `Ok(CacheMode::ReadWrite)` for service that doesn't
    /// support check yet.
    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadWrite)
    }

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the cache backend type name (e.g., "disk", "redis", "s3").
    /// Used for statistics and display purposes.
    fn cache_type_name(&self) -> &'static str {
        "unknown"
    }

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;

    /// Return the config for preprocessor cache mode if applicable
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        // Enable by default, only in local mode
        PreprocessorCacheModeConfig::default()
    }
    /// Return the base directories for path normalization if configured
    fn basedirs(&self) -> &[Vec<u8>] {
        &[]
    }
    /// Return the preprocessor cache entry for a given preprocessor key,
    /// if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn get_preprocessor_cache_entry(
        &self,
        _key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        Ok(None)
    }
    /// Insert a preprocessor cache entry at the given preprocessor key,
    /// overwriting the entry if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn put_preprocessor_cache_entry(
        &self,
        _key: &str,
        _preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        Ok(())
    }
}

/// Wrapper for opendal::Operator that adds basedirs support
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
pub struct RemoteStorage {
    operator: opendal::Operator,
    basedirs: Vec<Vec<u8>>,
}

#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
impl RemoteStorage {
    pub fn new(operator: opendal::Operator, basedirs: Vec<Vec<u8>>) -> Self {
        Self { operator, basedirs }
    }
}

/// Implement storage for operator.
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
#[async_trait]
impl Storage for RemoteStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        match self.operator.read(&normalize_key(key)).await {
            Ok(res) => {
                let hit = CacheRead::from(io::Cursor::new(res.to_bytes()))?;
                Ok(Cache::Hit(hit))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(Cache::Miss),
            Err(e) => {
                warn!("Got unexpected error: {:?}", e);
                Ok(Cache::Miss)
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        let start = std::time::Instant::now();

        self.operator
            .write(&normalize_key(key), entry.finish()?)
            .await?;

        Ok(start.elapsed())
    }

    async fn check(&self) -> Result<CacheMode> {
        use opendal::ErrorKind;

        let path = ".sccache_check";

        // Read is required, return error directly if we can't read .
        match self.operator.read(path).await {
            Ok(_) => (),
            // Read not exist file with not found is ok.
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            // Tricky Part.
            //
            // We tolerate rate limited here to make sccache keep running.
            // For the worse case, we will miss all the cache.
            //
            // In some super rare cases, user could configure storage in wrong
            // and hitting other services rate limit. There are few things we
            // can do, so we will print our the error here to make users know
            // about it.
            Err(err) if err.kind() == ErrorKind::RateLimited => {
                eprintln!("cache storage read check: {err:?}, but we decide to keep running");
            }
            Err(err) => bail!("cache storage failed to read: {:?}", err),
        }

        let can_write = match self.operator.write(path, "Hello, World!").await {
            Ok(_) => true,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => true,
            // Tolerate all other write errors because we can do read at least.
            Err(err) => {
                eprintln!("storage write check failed: {err:?}");
                false
            }
        };

        let mode = if can_write {
            CacheMode::ReadWrite
        } else {
            CacheMode::ReadOnly
        };

        debug!("storage check result: {mode:?}");

        Ok(mode)
    }

    fn location(&self) -> String {
        let meta = self.operator.info();
        format!(
            "{}, name: {}, prefix: {}",
            meta.scheme(),
            meta.name(),
            meta.root()
        )
    }

    fn cache_type_name(&self) -> &'static str {
        // Use opendal's scheme as the cache type name
        // This returns "s3", "redis", "azure", "gcs", etc.
        self.operator.info().scheme()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }
}

/// Build a single cache storage from CacheType
/// Helper function used by storage_from_config for both single and multi-level caches
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
pub fn build_single_cache(
    cache_type: &CacheType,
    basedirs: &[Vec<u8>],
    _pool: &tokio::runtime::Handle,
) -> Result<Arc<dyn Storage>> {
    match cache_type {
        #[cfg(feature = "azure")]
        CacheType::Azure(config::AzureCacheConfig {
            connection_string,
            container,
            key_prefix,
        }) => {
            debug!("Init azure cache with container {container}, key_prefix {key_prefix}");
            let operator = AzureBlobCache::build(connection_string, container, key_prefix)
                .map_err(|err| anyhow!("create azure cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "gcs")]
        CacheType::GCS(config::GCSCacheConfig {
            bucket,
            key_prefix,
            cred_path,
            rw_mode,
            service_account,
            credential_url,
        }) => {
            debug!("Init gcs cache with bucket {bucket}, key_prefix {key_prefix}");

            let operator = GCSCache::build(
                bucket,
                key_prefix,
                cred_path.as_deref(),
                service_account.as_deref(),
                (*rw_mode).into(),
                credential_url.as_deref(),
            )
            .map_err(|err| anyhow!("create gcs cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "gha")]
        CacheType::GHA(config::GHACacheConfig { version, .. }) => {
            debug!("Init gha cache with version {version}");

            let operator = GHACache::build(version)
                .map_err(|err| anyhow!("create gha cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "memcached")]
        CacheType::Memcached(config::MemcachedCacheConfig {
            url,
            username,
            password,
            expiration,
            key_prefix,
        }) => {
            debug!("Init memcached cache with url {url}");

            let operator = MemcachedCache::build(
                url,
                username.as_deref(),
                password.as_deref(),
                key_prefix,
                *expiration,
            )
            .map_err(|err| anyhow!("create memcached cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "redis")]
        CacheType::Redis(config::RedisCacheConfig {
            endpoint,
            cluster_endpoints,
            username,
            password,
            db,
            url,
            ttl,
            key_prefix,
        }) => {
            let storage = match (endpoint, cluster_endpoints, url) {
                (Some(url_str), None, None) => {
                    if url_str.starts_with("redis-sentinel://") {
                        debug!("Init redis sentinel cache with url {url_str}");
                        if username.is_some() || password.is_some() || *db != crate::config::DEFAULT_REDIS_DB {
                            warn!("`username`, `password` and `db` have no effect when using a `redis-sentinel://` URL. Embed credentials in the URL instead.");
                        }
                        RedisCache::build_from_url(url_str, key_prefix, *ttl)
                    } else {
                        debug!("Init redis single-node cache with url {url_str}");
                        RedisCache::build_single(
                            url_str,
                            username.as_deref(),
                            password.as_deref(),
                            *db,
                            key_prefix,
                            *ttl,
                        )
                    }
                }
                (None, Some(urls), None) => {
                    debug!("Init redis cluster cache with urls {urls}");
                    RedisCache::build_cluster(
                        urls,
                        username.as_deref(),
                        password.as_deref(),
                        *db,
                        key_prefix,
                        *ttl,
                    )
                }
                (None, None, Some(url)) => {
                    warn!("Init redis single-node cache from deprecated API with url {url}");
                    if username.is_some() || password.is_some() || *db != crate::config::DEFAULT_REDIS_DB {
                        bail!("`username`, `password` and `db` has no effect when `url` is set. Please use `endpoint` or `cluster_endpoints` for new API accessing");
                    }

                    RedisCache::build_from_url(url, key_prefix, *ttl)
                }
                _ => bail!("Only one of `endpoint`, `cluster_endpoints`, `url` must be set"),
            }
            .map_err(|err| anyhow!("create redis cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(storage, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "s3")]
        CacheType::S3(c) => {
            debug!(
                "Init s3 cache with bucket {}, endpoint {:?}",
                c.bucket, c.endpoint
            );
            let storage_builder =
                S3Cache::new(c.bucket.clone(), c.key_prefix.clone(), c.no_credentials);
            let operator = storage_builder
                .with_region(c.region.clone())
                .with_endpoint(c.endpoint.clone())
                .with_use_ssl(c.use_ssl)
                .with_server_side_encryption(c.server_side_encryption)
                .with_enable_virtual_host_style(c.enable_virtual_host_style)
                .build()
                .map_err(|err| anyhow!("create s3 cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "webdav")]
        CacheType::Webdav(c) => {
            debug!("Init webdav cache with endpoint {}", c.endpoint);

            let operator = WebdavCache::build(
                &c.endpoint,
                &c.key_prefix,
                c.username.as_deref(),
                c.password.as_deref(),
                c.token.as_deref(),
            )
            .map_err(|err| anyhow!("create webdav cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "oss")]
        CacheType::OSS(c) => {
            debug!(
                "Init oss cache with bucket {}, endpoint {:?}",
                c.bucket, c.endpoint
            );

            let operator = OSSCache::build(
                &c.bucket,
                &c.key_prefix,
                c.endpoint.as_deref(),
                c.no_credentials,
            )
            .map_err(|err| anyhow!("create oss cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "cos")]
        CacheType::COS(c) => {
            debug!(
                "Init cos cache with bucket {}, endpoint {:?}",
                c.bucket, c.endpoint
            );

            let operator = COSCache::build(&c.bucket, &c.key_prefix, c.endpoint.as_deref())
                .map_err(|err| anyhow!("create cos cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec());
            Ok(Arc::new(storage))
        }
        #[allow(unreachable_patterns)]
        _ => {
            bail!("Cache type not supported with current feature configuration")
        }
    }
}

/// Get a suitable `Storage` implementation from configuration.
/// Supports both single-cache (backward compatible) and multi-level cache configurations.
pub fn storage_from_config(
    config: &Config,
    pool: &tokio::runtime::Handle,
) -> Result<Arc<dyn Storage>> {
    #[cfg(any(
        feature = "azure",
        feature = "gcs",
        feature = "gha",
        feature = "memcached",
        feature = "redis",
        feature = "s3",
        feature = "webdav",
        feature = "oss",
        feature = "cos"
    ))]
    if let Some(cache_type) = &config.cache {
        debug!("Configuring single cache from CacheType");
        return build_single_cache(cache_type, &config.basedirs, pool);
    }

    // No remote cache configured - use disk cache only
    let (dir, size) = (&config.fallback_cache.dir, config.fallback_cache.size);
    let preprocessor_cache_mode_config = config.fallback_cache.preprocessor_cache_mode;
    let rw_mode = config.fallback_cache.rw_mode.into();
    debug!("Init disk cache with dir {:?}, size {}", dir, size);

    Ok(Arc::new(DiskCache::new(
        dir,
        size,
        pool,
        preprocessor_cache_mode_config,
        rw_mode,
        config.basedirs.clone(),
    )))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::CacheModeConfig;
    use fs_err as fs;

    #[test]
    fn test_read_write_mode_local() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Use disk cache.
        let mut config = Config {
            cache: None,
            ..Default::default()
        };

        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test_rust_cargo")
            .tempdir()
            .context("Failed to create tempdir")
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        config.fallback_cache.dir = cache_dir;

        // Test Read Write
        config.fallback_cache.rw_mode = CacheModeConfig::ReadWrite;

        {
            let cache = storage_from_config(&config, runtime.handle()).unwrap();

            runtime.block_on(async move {
                cache.put("test1", CacheWrite::default()).await.unwrap();
                cache
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .await
                    .unwrap();
            });
        }

        // Test Read-only
        config.fallback_cache.rw_mode = CacheModeConfig::ReadOnly;

        {
            let cache = storage_from_config(&config, runtime.handle()).unwrap();

            runtime.block_on(async move {
                assert_eq!(
                    cache
                        .put("test1", CacheWrite::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
                assert_eq!(
                    cache
                        .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
            });
        }
    }

    #[test]
    #[cfg(feature = "s3")]
    fn test_operator_storage_s3_with_basedirs() {
        // Create S3 operator (doesn't need real credentials for this test)
        let operator = crate::cache::s3::S3Cache::new(
            "test-bucket".to_string(),
            "test-prefix".to_string(),
            true, // no_credentials = true
        )
        .with_region(Some("us-east-1".to_string()))
        .build()
        .expect("Failed to create S3 cache operator");

        let basedirs = vec![b"/home/user/project".to_vec(), b"/opt/build".to_vec()];

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, basedirs.clone());

        // Verify basedirs are stored and retrieved correctly
        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 2);
        assert_eq!(storage.basedirs()[0], b"/home/user/project".to_vec());
        assert_eq!(storage.basedirs()[1], b"/opt/build".to_vec());
    }

    #[test]
    #[cfg(feature = "redis")]
    fn test_operator_storage_redis_with_basedirs() {
        // Create Redis operator
        let operator = crate::cache::redis::RedisCache::build_single(
            "redis://localhost:6379",
            None,
            None,
            0,
            "test-prefix",
            0,
        )
        .expect("Failed to create Redis cache operator");

        let basedirs = vec![b"/workspace".to_vec()];

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, basedirs.clone());

        // Verify basedirs work
        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 1);
    }
}
