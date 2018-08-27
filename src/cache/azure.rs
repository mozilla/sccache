// Copyright 2018 Benjamin Bader
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

use azure::BlobContainer;
use azure::*;
use cache::{Cache, CacheRead, CacheWrite, Storage};
use futures::future::Future;
use std::io;
use std::rc::Rc;
use std::time::{Instant, Duration};
use tokio_core::reactor::Handle;

use errors::*;

pub struct AzureBlobCache {
    container: Rc<BlobContainer>,
    credentials: AzureCredentials
}

impl AzureBlobCache {
    pub fn new(handle: &Handle) -> Result<AzureBlobCache> {
        let credentials = match EnvironmentProvider.provide_credentials() {
            Ok(creds) => creds,
            Err(_) => bail!("Could not find Azure credentials in the environment")
        };

        let container = match BlobContainer::new(credentials.azure_blob_endpoint(), credentials.blob_container_name(), handle) {
            Ok(container) => container,
            Err(e) => bail!("Error instantiating BlobContainer: {:?}", e)
        };

        Ok(AzureBlobCache {
            container: Rc::new(container),
            credentials: credentials
        })
    }
}

impl Storage for AzureBlobCache {
    fn get(&self, key: &str) -> SFuture<Cache> {
        Box::new(self.container.get(key, &self.credentials).then(|result| {
            match result {
                Ok(data) => {
                    let hit = CacheRead::from(io::Cursor::new(data))?;
                    Ok(Cache::Hit(hit))
                }
                Err(e) => {
                    warn!("Got Azure error: {:?}", e);
                    Ok(Cache::Miss)
                }
            }
        }))
    }

    fn put(&self, key: &str, entry: CacheWrite) -> SFuture<Duration> {
        let start = Instant::now();
        let data = match entry.finish() {
            Ok(data) => data,
            Err(e) => return f_err(e),
        };

        let response = self.container.put(key, data, &self.credentials).chain_err(|| {
            "Failed to put cache entry in Azure"
        });

        Box::new(response.map(move |_| start.elapsed()))
    }

    fn location(&self) -> String {
        format!("Azure, container: {}", self.container)
    }

    fn current_size(&self) -> SFuture<Option<u64>> { f_ok(None) }
    fn max_size(&self) -> SFuture<Option<u64>> { f_ok(None) }
}
