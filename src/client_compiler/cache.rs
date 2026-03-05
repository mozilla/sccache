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

//! Client-side compiler information caching.

use crate::compiler::Compiler;
use crate::mock_command::CommandCreatorSync;
use filetime::FileTime;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Cache entry for a compiler.
struct CompilerCacheEntry<C> {
    /// The compiler information.
    pub compiler: Arc<Box<dyn Compiler<C>>>,
    /// Modification time of the compiler executable.
    pub mtime: FileTime,
}

/// Client-side cache for compiler information.
///
/// This cache stores compiler detection results keyed by (path, mtime)
/// to avoid re-detecting the same compiler multiple times.
pub struct CompilerCache<C> {
    /// Map of (compiler_path, mtime) to compiler info.
    cache: RwLock<HashMap<(PathBuf, FileTime), Arc<Box<dyn Compiler<C>>>>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C> CompilerCache<C>
where
    C: CommandCreatorSync,
{
    /// Create a new empty compiler cache.
    pub fn new() -> Self {
        CompilerCache {
            cache: RwLock::new(HashMap::new()),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get a cached compiler or return None.
    pub fn get(&self, path: &Path, mtime: FileTime) -> Option<Arc<Box<dyn Compiler<C>>>> {
        let cache = self.cache.read().unwrap();
        cache.get(&(path.to_path_buf(), mtime)).cloned()
    }

    /// Insert a compiler into the cache.
    pub fn insert(
        &self,
        path: PathBuf,
        mtime: FileTime,
        compiler: Box<dyn Compiler<C>>,
    ) -> Arc<Box<dyn Compiler<C>>> {
        let mut cache = self.cache.write().unwrap();
        let arc = Arc::new(compiler);
        cache.insert((path, mtime), arc.clone());
        arc
    }

    /// Clear the cache.
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
}

impl<C> Default for CompilerCache<C>
where
    C: CommandCreatorSync,
{
    fn default() -> Self {
        Self::new()
    }
}
