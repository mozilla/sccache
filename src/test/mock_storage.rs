// Copyright 2017 Mozilla Foundation
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

use crate::cache::{Cache, CacheWrite, Storage};
use crate::errors::*;
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use std::future::Future;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use core::pin::Pin;

pub(crate) trait StorageNextVal<T>: Future<Output=Result<T>> + Send + Sync + 'static {}

impl<Z,T> StorageNextVal<T> for Z where Z: Future<Output=Result<T>> + Send + Sync + 'static {}

/// A mock `Storage` implementation.
pub struct MockStorage {
    rx: Arc<Mutex<UnboundedReceiver<Pin<Box<dyn StorageNextVal<Cache>>>>>>,
    tx: UnboundedSender<Pin<Box<dyn StorageNextVal<Cache>>>>,
}

impl MockStorage {
    /// Create a new `MockStorage`.
    pub(crate) fn new() -> MockStorage {
        let (tx, rx) = mpsc::unbounded::<Pin<Box<dyn StorageNextVal<Cache>>>>();
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Queue up `res` to be returned as the next result from `Storage::get`.
    pub(crate) fn next_get(&self, res: Pin<Box<dyn StorageNextVal<Cache>>>) {
        self.tx.unbounded_send(res).unwrap();
    }
}

#[async_trait::async_trait]
impl Storage for MockStorage {
    async fn get(&self, _key: &str) -> Result<Cache> {
        let mut fut = self.rx.lock().unwrap().try_next().ok().flatten().expect("MockStorage get called, but no get results available");
        fut.await
    }
    async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
        Ok(Duration::from_secs(0))
    }
    fn location(&self) -> String {
        "Mock Storage".to_string()
    }
    async fn current_size(&self) -> Result<Option<u64>> {
       Ok(None)
    }
    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}
