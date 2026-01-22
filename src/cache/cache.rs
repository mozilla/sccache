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
use super::preprocessor_cache::PreprocessorCacheStorage;
use super::storage::Storage;
use crate::cache::PreprocessorCache;
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
use crate::config::{self, CacheType};
use crate::config::{Config, DiskCacheConfig};
use crate::errors::*;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// Implement storage for operator.
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
))]
#[async_trait]
impl Storage for opendal::Operator {
    async fn get(&self, key: &str) -> Result<Cache> {
        match self.read(&normalize_key(key)).await {
            Ok(res) => {
                let hit = CacheRead::from(std::io::Cursor::new(res.to_bytes()))?;
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

        self.write(&normalize_key(key), entry.finish()?).await?;

        Ok(start.elapsed())
    }

    async fn check(&self) -> Result<CacheMode> {
        use opendal::ErrorKind;

        let path = ".sccache_check";

        // Read is required, return error directly if we can't read .
        match self.read(path).await {
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

        let can_write = match self.write(path, "Hello, World!").await {
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
        let meta = self.info();
        format!(
            "{}, name: {}, prefix: {}",
            meta.scheme(),
            meta.name(),
            meta.root()
        )
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

fn get_preprocessor_cache_storage(config: &Config) -> Result<Arc<dyn PreprocessorCacheStorage>> {
    Ok(Arc::new(PreprocessorCache::new(&config.preprocessor_cache)))
}

#[cfg(feature = "azure")]
fn get_azure_storage(config: &config::AzureCacheConfig) -> Result<Arc<dyn Storage>> {
    debug!(
        "Init azure cache with container {}, key_prefix {}",
        config.container, config.key_prefix
    );
    let storage = AzureBlobCache::build(
        &config.connection_string,
        &config.container,
        &config.key_prefix,
    )
    .map_err(|err| anyhow!("create azure cache failed: {err:?}"))?;
    Ok(Arc::new(storage))
}

#[cfg(feature = "gcs")]
fn get_gcs_storage(config: &config::GCSCacheConfig) -> Result<Arc<dyn Storage>> {
    debug!(
        "Init gcs cache with bucket {}, key_prefix {}",
        config.bucket, config.key_prefix
    );

    let storage = GCSCache::build(
        &config.bucket,
        &config.key_prefix,
        config.cred_path.as_deref(),
        config.service_account.as_deref(),
        config.rw_mode.into(),
        config.credential_url.as_deref(),
    )
    .map_err(|err| anyhow!("create gcs cache failed: {err:?}"))?;

    Ok(Arc::new(storage))
}

#[cfg(feature = "gha")]
fn get_gha_storage(config: &config::GHACacheConfig) -> Result<Arc<dyn Storage>> {
    debug!("Init gha cache with version {}", config.version);

    let storage = GHACache::build(&config.version)
        .map_err(|err| anyhow!("create gha cache failed: {err:?}"))?;
    Ok(Arc::new(storage))
}

#[cfg(feature = "memcached")]
fn get_memcached_storage(config: &config::MemcachedCacheConfig) -> Result<Arc<dyn Storage>> {
    debug!("Init memcached cache with url {}", config.url);
    let storage = MemcachedCache::build(
        &config.url,
        config.username.as_deref(),
        config.password.as_deref(),
        &config.key_prefix,
        config.expiration,
    )
    .map_err(|err| anyhow!("create memcached cache failed: {err:?}"))?;
    Ok(Arc::new(storage))
}

#[cfg(feature = "redis")]
fn get_redis_storage(config: &config::RedisCacheConfig) -> Result<Arc<dyn Storage>> {
    debug!("Init redis cache with endpoint {:?}", config.endpoint);
    let storage = RedisCache::build_single(
        config
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("redis endpoint is required"))?,
        config.username.as_deref(),
        config.password.as_deref(),
        config.db,
        &config.key_prefix,
        config.ttl,
    )
    .map_err(|err| anyhow!("create redis cache failed: {err:?}"))?;
    Ok(Arc::new(storage))
}

#[cfg(feature = "s3")]
fn get_s3_storage(config: &config::S3CacheConfig) -> Result<Arc<dyn Storage>> {
    debug!(
        "Init s3 cache with bucket {}, endpoint {:?}",
        config.bucket, config.endpoint
    );
    let storage_builder = S3Cache::new(
        config.bucket.clone(),
        config.key_prefix.clone(),
        config.no_credentials,
    );
    let storage = storage_builder
        .with_region(config.region.clone())
        .with_endpoint(config.endpoint.clone())
        .with_use_ssl(config.use_ssl)
        .with_server_side_encryption(config.server_side_encryption)
        .with_enable_virtual_host_style(config.enable_virtual_host_style)
        .build()
        .map_err(|err| anyhow!("create s3 cache failed: {err:?}"))?;

    Ok(Arc::new(storage))
}

#[cfg(feature = "webdav")]
fn get_webdav_storage(config: &config::WebdavCacheConfig) -> Result<Arc<dyn Storage>> {
    debug!("Init webdav cache with endpoint {}", config.endpoint);
    let storage = WebdavCache::build(
        &config.endpoint,
        &config.key_prefix,
        config.username.as_deref(),
        config.password.as_deref(),
        config.token.as_deref(),
    )
    .map_err(|err| anyhow!("create webdav cache failed: {err:?}"))?;
    Ok(Arc::new(storage))
}

#[cfg(feature = "oss")]
fn get_oss_storage(config: &config::OSSCacheConfig) -> Result<Arc<dyn Storage>> {
    debug!(
        "Init oss cache with bucket {}, endpoint {:?}",
        config.bucket, config.endpoint
    );
    let storage = OSSCache::build(
        &config.bucket,
        &config.key_prefix,
        config.endpoint.as_deref(),
        config.no_credentials,
    )
    .map_err(|err| anyhow!("create oss cache failed: {err:?}"))?;
    Ok(Arc::new(storage))
}

fn get_disk_storage(
    config: &DiskCacheConfig,
    pool: &tokio::runtime::Handle,
) -> Result<Arc<dyn Storage>> {
    let (dir, size) = (&config.dir, config.size);
    let rw_mode = config.rw_mode.into();
    debug!("Init disk cache with dir {:?}, size {}", dir, size);
    Ok(Arc::new(DiskCache::new(dir, size, pool, rw_mode)))
}

/// Get a suitable cache `Storage` implementation from configuration.
fn get_storage(config: &Config, pool: &tokio::runtime::Handle) -> Result<Arc<dyn Storage>> {
    if let Some(cache_type) = &config.cache {
        match cache_type {
            #[cfg(feature = "azure")]
            CacheType::Azure(azure_config) => return get_azure_storage(azure_config),
            #[cfg(feature = "gcs")]
            CacheType::GCS(gcs_config) => return get_gcs_storage(gcs_config),
            #[cfg(feature = "gha")]
            CacheType::GHA(gha_config) => return get_gha_storage(gha_config),
            #[cfg(feature = "memcached")]
            CacheType::Memcached(memcached_config) => {
                return get_memcached_storage(memcached_config);
            }
            #[cfg(feature = "redis")]
            CacheType::Redis(redis_config) => return get_redis_storage(redis_config),
            #[cfg(feature = "s3")]
            CacheType::S3(s3_config) => return get_s3_storage(s3_config),
            #[cfg(feature = "webdav")]
            CacheType::Webdav(webdav_config) => return get_webdav_storage(webdav_config),
            #[cfg(feature = "oss")]
            CacheType::OSS(oss_config) => return get_oss_storage(oss_config),
            #[cfg(feature = "cos")]
            CacheType::COS(c) => {
                debug!(
                    "Init cos cache with bucket {}, endpoint {:?}",
                    c.bucket, c.endpoint
                );

                let storage = COSCache::build(&c.bucket, &c.key_prefix, c.endpoint.as_deref())
                    .map_err(|err| anyhow!("create cos cache failed: {err:?}"))?;

                return Ok(Arc::new(storage));
            }
            #[allow(unreachable_patterns)]
            // if we build only with `cargo build --no-default-features`
            // we only want to use sccache with a local cache (no remote storage)
            _ => {}
        }
    }

    get_disk_storage(&config.fallback_cache, pool)
}

pub fn get_storage_from_config(
    config: &Config,
    pool: &tokio::runtime::Handle,
) -> Result<(Arc<dyn Storage>, Arc<dyn PreprocessorCacheStorage>)> {
    Ok((
        get_storage(config, pool)?,
        get_preprocessor_cache_storage(config)?,
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::PreprocessorCacheEntry;
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
            let (cache, preprocessor_cache) =
                get_storage_from_config(&config, runtime.handle()).unwrap();

            runtime.block_on(async move {
                cache.put("test1", CacheWrite::default()).await.unwrap();
                preprocessor_cache
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .await
                    .unwrap();
            });
        }

        // Test Read-only
        config.fallback_cache.rw_mode = CacheModeConfig::ReadOnly;
        config.preprocessor_cache.rw_mode = CacheModeConfig::ReadOnly;

        {
            let (cache, preprocessor_cache) =
                get_storage_from_config(&config, runtime.handle()).unwrap();

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
                    preprocessor_cache
                        .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
            });
        }
    }
}
