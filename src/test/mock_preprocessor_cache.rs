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

use async_trait::async_trait;

use crate::cache::preprocessor_cache::PreprocessorCacheStorage;
use crate::config::PreprocessorCacheModeConfig;

/// A mock `PreprocessorCacheStorage` implementation.
pub struct MockPreprocessorCacheStorage {
    config: PreprocessorCacheModeConfig,
}

impl MockPreprocessorCacheStorage {
    /// Create a new `MockPreprocessorCacheStorage`.
    pub(crate) fn new(use_preprocessor_cache_mode: bool) -> MockPreprocessorCacheStorage {
        Self {
            config: PreprocessorCacheModeConfig {
                use_preprocessor_cache_mode,
                ..Default::default()
            },
        }
    }
}

#[async_trait]
impl PreprocessorCacheStorage for MockPreprocessorCacheStorage {
    fn get_config(&self) -> &PreprocessorCacheModeConfig {
        &self.config
    }

    // TODO Implement get_preprocessor_cache_entry and put_preprocessor_cache_entry
}
