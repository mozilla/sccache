// Copyright 2022 Bitski Inc.
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

use std::path::PathBuf;

use opendal::layers::LoggingLayer;
use opendal::services::Ghac;
use opendal::Operator;

use crate::config::Config;
use crate::errors::*;
use crate::VERSION;

const FULL_GHA_CACHE_ROOT: &str = "sccache-full";

/// A cache that stores entries in GHA Cache Services.
pub struct GHACache;

impl GHACache {
    pub fn build(version: &str) -> Result<Operator> {
        let mut builder = Ghac::default();
        // This is the prefix of gha cache.
        // From user side, cache key will be like `sccache/f/c/b/fcbxxx`
        //
        // User customization is theoretically supported, but I decided
        // to see the community feedback first.
        builder.root("/sccache");

        if version.is_empty() {
            builder.version(&format!("sccache-v{VERSION}"));
        } else {
            builder.version(&format!("sccache-v{VERSION}-{version}"));
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }

    /// Download a copy of the entire GHA cache from the given version
    /// and return the path to the root folder on the local disk.
    ///
    /// It is the user's responsibility to split the caches according
    /// to anything relevant like architecture, OS, etc. by using the `version`.
    pub async fn download_to_local(config: &Config, version: &str) -> Result<Option<PathBuf>> {
        let tarball_path = local_cache_tarball_path(config);
        let mut builder = Ghac::default();

        // TODO somehow loop over decreasingly "fresh" versions of the cache
        // like in
        // https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#matching-a-cache-key
        // For now the behavior is to match the same version, which would
        // speed up rebuilds in the same (Git) branch.
        //
        // A few things to note that make this difficult, plus ideas:
        // - GHA's cache is immutable (meaning you cannot modify a given path
        // for a given version), so we cannot reuse a "global version"
        // - GHA's cache doesn't allow for listing items in a version
        // - GHA's cache is not shared across branches, except for branches
        //   that are directly from the default branch, which can use the
        //   default cache.
        // - Maybe only using the default branch cache with a way of renewing
        //   it periodically is already a benefit.
        // - This maybe could be done as a fallback if the current branch cache
        //   is empty, though this is unclear to me at the time of writing.
        if version.is_empty() {
            builder.version(&format!("sccache-v{VERSION}"));
        } else {
            builder.version(&format!("sccache-v{VERSION}-{version}"));
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();

        if !op.is_exist(FULL_GHA_CACHE_ROOT).await? {
            info!("Remote full gha cache does not exist: nothing to do");
            return Ok(None);
        }
        debug!("Found full gha cache");

        let mut reader = op.reader(FULL_GHA_CACHE_ROOT).await?;
        std::fs::create_dir_all(tarball_path.parent().expect("root path"))?;

        let mut writer = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&tarball_path)
            .await
            .context("opening the local tarball for writing")?;

        if let Err(error) = tokio::io::copy(&mut reader, &mut writer).await {
            match error.kind() {
                std::io::ErrorKind::NotFound => {
                    debug!("Remote full gha cache was deleted: nothing to do");
                    // TOCTOU race with the above existence check and the cache
                    // being cleared.
                    return Ok(None);
                }
                _ => {
                    bail!(error)
                }
            }
        };

        let cache = local_cache_path(config);
        let tarball =
            std::fs::File::open(tarball_path).context("Failed to open the GHA cache tarball")?;
        tar::Archive::new(tarball)
            .unpack(&cache)
            .context("Failed to extract the GHA cache tarball")?;

        Ok(Some(cache))
    }

    /// Upload a tarball of the local cache
    pub async fn upload_local_cache(config: &Config) -> Result<()> {
        let cache = local_cache_path(config);
        if !cache.exists() {
            info!("Local cache does not exist: nothing to do");
            return Ok(());
        }
        debug!("Found local gha cache at {}", cache.display());

        let op = Operator::new(Ghac::default())?
            .layer(LoggingLayer::default())
            .finish();

        // GHA cache is immutable, if the path has already been written within
        // a given version, it cannot be changed again.
        if op.is_exist(FULL_GHA_CACHE_ROOT).await? {
            info!("Remote cache of this version already exists, cannot upload");
            return Ok(());
        }

        let mut tar_builder = tar::Builder::new(vec![]);
        tar_builder
            .append_dir_all(local_cache_path(config), ".")
            .context("Failed to create GHA local cache tarball")?;
        let source = local_cache_tarball_path(config);
        std::fs::write(&source, tar_builder.into_inner()?)
            .context("Failed to write the GHA local cache tarball to disk")?;

        let mut writer = op
            .writer(FULL_GHA_CACHE_ROOT)
            .await
            .context("opening the remote tarball for writing")?;

        let mut reader = tokio::fs::File::open(&source)
            .await
            .context("opening the local tarball for reading")?;

        if let Err(error) = tokio::io::copy(&mut reader, &mut writer).await {
            match error.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    debug!("Remote cache of this version raced us, cannot upload");
                    // TOCTOU race with the above existence check and the cache
                    // being uploaded by another worker.
                    return Ok(());
                }
                _ => bail!(error),
            }
        }
        Ok(())
    }
}

fn local_cache_tarball_path(config: &Config) -> PathBuf {
    let mut path = config.fallback_cache.dir.join(FULL_GHA_CACHE_ROOT);
    path.set_extension(".tar");
    path
}

fn local_cache_path(config: &Config) -> PathBuf {
    config.fallback_cache.dir.join(FULL_GHA_CACHE_ROOT)
}
