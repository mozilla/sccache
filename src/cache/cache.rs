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
use crate::cache::multilevel::MultiLevelStorage;
#[cfg(feature = "oss")]
use crate::cache::oss::OSSCache;
#[cfg(feature = "redis")]
use crate::cache::redis::RedisCache;
#[cfg(feature = "s3")]
use crate::cache::s3::S3Cache;
#[cfg(any_cache_remote)]
use crate::cache::storage::RemoteStorage;
use crate::cache::storage::Storage;
#[cfg(feature = "webdav")]
use crate::cache::webdav::WebdavCache;
use crate::config::Config;
use crate::config::{self, CacheType};

use std::sync::Arc;
#[cfg(feature = "redis")]
use std::time::Duration;

use crate::errors::*;

/// Build a single cache storage from CacheType
/// Helper function used by storage_from_config for both single and multi-level caches
pub fn build_single_cache(
    cache_type: &CacheType,
    basedirs: &[Vec<u8>],
    skip_cache_check: bool,
) -> Result<Arc<dyn Storage>> {
    match cache_type {
        #[cfg(feature = "azure")]
        CacheType::Azure(config::AzureCacheConfig {
            connection_string,
            container,
            key_prefix,
            storage_account,
            endpoint,
            rw_mode,
        }) => {
            debug!("Init azure cache with container {container}, key_prefix {key_prefix}");
            let operator = AzureBlobCache::build(
                connection_string.as_deref(),
                container,
                key_prefix,
                storage_account.as_deref(),
                endpoint.as_deref(),
            )
            .map_err(|err| anyhow!("create azure cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
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
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "gha")]
        CacheType::GHA(config::GHACacheConfig {
            version, rw_mode, ..
        }) => {
            debug!("Init gha cache with version {version}");

            let operator = GHACache::build(version)
                .map_err(|err| anyhow!("create gha cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "memcached")]
        CacheType::Memcached(config::MemcachedCacheConfig {
            url,
            username,
            password,
            expiration,
            key_prefix,
            rw_mode,
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
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
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
            io_timeout_secs,
            rw_mode,
        }) => {
            let io_timeout = io_timeout_secs.map(|secs| Duration::from_secs(secs.get()));
            let storage = match (endpoint, cluster_endpoints, url) {
                (Some(url), None, None) => {
                    debug!("Init redis single-node cache with url {url}");
                    RedisCache::build_single(
                        url,
                        username.as_deref(),
                        password.as_deref(),
                        *db,
                        key_prefix,
                        *ttl,
                        io_timeout,
                    )
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
                        io_timeout,
                    )
                }
                (None, None, Some(url)) => {
                    warn!("Init redis single-node cache from deprecated API with url {url}");
                    if username.is_some() || password.is_some() || *db != crate::config::DEFAULT_REDIS_DB {
                        bail!("`username`, `password` and `db` has no effect when `url` is set. Please use `endpoint` or `cluster_endpoints` for new API accessing");
                    }

                    RedisCache::build_from_url(url, key_prefix, *ttl, io_timeout)
                }
                _ => bail!("Only one of `endpoint`, `cluster_endpoints`, `url` must be set"),
            }
            .map_err(|err| anyhow!("create redis cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(storage, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
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
                .with_server_side_encryption_aws_kms(c.server_side_encryption_aws_kms)
                .with_server_side_encryption_kms_key_id(c.server_side_encryption_kms_key_id.clone())
                .with_enable_virtual_host_style(c.enable_virtual_host_style)
                .build()
                .map_err(|err| anyhow!("create s3 cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
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
                c.disable_create_dir,
            )
            .map_err(|err| anyhow!("create webdav cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
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

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
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

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
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
    // Check for multi-level cache configuration
    if let Some(multilevel) = MultiLevelStorage::from_config(config, pool)? {
        return Ok(Arc::new(multilevel));
    }

    // Single cache or fallback to disk (backward compatible path)
    #[cfg(any_cache_remote)]
    if let Some(cache_type) = &config.cache {
        debug!("Configuring single cache from CacheType");
        return build_single_cache(cache_type, &config.basedirs, config.skip_cache_check);
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
    use crate::{
        PreprocessorCacheEntry, cache::CacheMode, cache::CacheWrite, config::CacheModeConfig,
    };
    use fs_err as fs;

    #[test]
    #[cfg(not(feature = "redis"))]
    fn test_build_single_cache_feature_disabled() {
        let cache_type = CacheType::Redis(Default::default());
        let err = build_single_cache(&cache_type, &[], false)
            .err()
            .expect("disabled backend must be rejected");
        assert_eq!(
            err.to_string(),
            "Cache type not supported with current feature configuration"
        );
    }

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
        let storage = RemoteStorage::new(operator, basedirs.clone(), CacheMode::ReadWrite);

        // Verify basedirs are stored and retrieved correctly
        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 2);
        assert_eq!(storage.basedirs()[0], b"/home/user/project".to_vec());
        assert_eq!(storage.basedirs()[1], b"/opt/build".to_vec());
    }

    #[test]
    #[cfg(feature = "s3")]
    fn test_skip_remote_cache_check_uses_configured_mode() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for (configured_mode, expected_mode) in [
            (CacheModeConfig::ReadOnly, CacheMode::ReadOnly),
            (CacheModeConfig::ReadWrite, CacheMode::ReadWrite),
        ] {
            let cache_config = config::S3CacheConfig {
                bucket: "test-bucket".to_owned(),
                region: Some("us-east-1".to_owned()),
                key_prefix: String::new(),
                no_credentials: true,
                endpoint: Some("http://127.0.0.1:1".to_owned()),
                use_ssl: Some(false),
                server_side_encryption: None,
                server_side_encryption_aws_kms: None,
                server_side_encryption_kms_key_id: None,
                enable_virtual_host_style: None,
                rw_mode: configured_mode,
            };
            let single_cache_config = Config {
                cache: Some(CacheType::S3(cache_config.clone())),
                skip_cache_check: true,
                ..Default::default()
            };

            let storage = storage_from_config(&single_cache_config, runtime.handle()).unwrap();
            assert_eq!(runtime.block_on(storage.check()).unwrap(), expected_mode);

            let multilevel_config = Config {
                cache_configs: config::CacheConfigs {
                    s3: Some(cache_config),
                    multilevel: Some(config::MultiLevelConfig {
                        chain: vec!["s3".to_owned()],
                        write_error_policy: config::WriteErrorPolicy::default(),
                    }),
                    ..Default::default()
                },
                skip_cache_check: true,
                ..Default::default()
            };

            let storage = storage_from_config(&multilevel_config, runtime.handle()).unwrap();
            assert_eq!(runtime.block_on(storage.check()).unwrap(), expected_mode);
        }
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
            None,
        )
        .expect("Failed to create Redis cache operator");

        let basedirs = vec![b"/workspace".to_vec()];

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, basedirs.clone(), CacheMode::ReadWrite);

        // Verify basedirs work
        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 1);
    }

    #[test]
    #[cfg(feature = "redis")]
    fn test_operator_storage_redis_with_read_only() {
        // Create Redis operator

        use crate::test::utils::Waiter;
        let operator = crate::cache::redis::RedisCache::build_single(
            "redis://localhost:6379",
            None,
            None,
            0,
            "test-prefix",
            0,
            None,
        )
        .expect("Failed to create Redis cache operator");

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, vec![], CacheMode::ReadOnly);

        // Verify put fails
        let result = storage.put("test", CacheWrite::default()).wait();
        match result {
            Ok(_) => panic!("expected error, got success {result:?}"),
            Err(err) => assert_eq!(err.to_string(), "storage is read-only"),
        }
    }
}
