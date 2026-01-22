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

use std::{
    io::BufWriter,
    sync::{Arc, Mutex},
};

use crate::{
    cache::{LazyDiskCache, utils::normalize_key},
    compiler::PreprocessorCacheEntry,
    config::{CacheModeConfig, PreprocessorCacheModeConfig},
    errors::*,
};
use async_trait::async_trait;

#[async_trait]
pub trait PreprocessorCacheStorage: Send + Sync {
    /// Return the config for preprocessor cache mode if applicable
    fn get_config(&self) -> &PreprocessorCacheModeConfig;

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

/// Store the hashed source file as preprocessor cache entries.
/// If preprocessor cache mode is enabled,
pub(crate) struct PreprocessorCache {
    cache: Option<Arc<Mutex<LazyDiskCache>>>,
    config: PreprocessorCacheModeConfig,
}

impl PreprocessorCache {
    pub fn new(config: &PreprocessorCacheModeConfig) -> PreprocessorCache {
        info!("Creating PreprocessorCache with config: {:?}", config);
        PreprocessorCache {
            cache: if config.use_preprocessor_cache_mode {
                Some(Arc::new(Mutex::new(LazyDiskCache::Uninit {
                    root: config.dir.join("preprocessor").into_os_string(),
                    max_size: config.max_size,
                })))
            } else {
                None
            },
            config: config.clone(),
        }
    }
}

#[async_trait]
impl PreprocessorCacheStorage for PreprocessorCache {
    /// Return the config for preprocessor cache mode if applicable
    fn get_config(&self) -> &PreprocessorCacheModeConfig {
        &self.config
    }

    /// Return the preprocessor cache entry for a given preprocessor key,
    /// if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn get_preprocessor_cache_entry(
        &self,
        key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        match self.cache {
            None => Ok(None),
            Some(ref cache) => {
                assert!(self.config.use_preprocessor_cache_mode);
                let key = normalize_key(key);
                Ok(cache.lock().unwrap().get_or_init()?.get(key).ok())
            }
        }
    }

    /// Insert a preprocessor cache entry at the given preprocessor key,
    /// overwriting the entry if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn put_preprocessor_cache_entry(
        &self,
        key: &str,
        preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        if self.config.rw_mode == CacheModeConfig::ReadOnly {
            bail!("Cannot write to a read-only cache");
        }
        match self.cache {
            None => Ok(()),
            Some(ref cache) => {
                assert!(self.config.use_preprocessor_cache_mode);
                let key = normalize_key(key);
                info!("PreprocessorCache: put_preprocessor_cache_entry({})", key);
                let mut f = cache.lock().unwrap().get_or_init()?.prepare_add(key, 0)?;
                preprocessor_cache_entry.serialize_to(BufWriter::new(f.as_file_mut()))?;
                Ok(cache.lock().unwrap().get().unwrap().commit(f)?)
            }
        }
    }
}
