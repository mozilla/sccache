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
use crate::config::PreprocessorCacheModeConfig;
use crate::errors::*;
use async_trait::async_trait;
use bytes::Bytes;
use futures::channel::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// A mock `Storage` implementation.
pub struct MockStorage {
    rx: Arc<Mutex<mpsc::UnboundedReceiver<Result<Cache>>>>,
    tx: mpsc::UnboundedSender<Result<Cache>>,
    raw_rx: Mutex<mpsc::UnboundedReceiver<Result<Option<Bytes>>>>,
    raw_tx: mpsc::UnboundedSender<Result<Option<Bytes>>>,
    delay: Option<Duration>,
    preprocessor_cache_mode: bool,
}

impl MockStorage {
    /// Create a new `MockStorage`. if `delay` is `Some`, wait for that amount of time before returning from operations.
    pub(crate) fn new(delay: Option<Duration>, preprocessor_cache_mode: bool) -> MockStorage {
        let (tx, rx) = mpsc::unbounded();
        let (raw_tx, raw_rx) = mpsc::unbounded();
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
            delay,
            raw_tx,
            raw_rx: Mutex::new(raw_rx),
            preprocessor_cache_mode,
        }
    }

    /// Queue up `res` to be returned as the next result from `Storage::get`.
    pub(crate) fn next_get(&self, res: Result<Cache>) {
        self.tx.unbounded_send(res).unwrap();
    }

    /// Queue up `res` to be returned as the next result from `Storage::get_raw`.
    pub(crate) fn next_get_raw(&self, res: Result<Option<Bytes>>) {
        self.raw_tx.unbounded_send(res).unwrap();
    }
}

#[async_trait]
impl Storage for MockStorage {
    async fn get(&self, _key: &str) -> Result<Cache> {
        if let Some(delay) = self.delay {
            sleep(delay).await;
        }
        let next = self.rx.lock().await.try_next().unwrap();

        next.expect("MockStorage get called but no get results available")
    }
    async fn get_raw(&self, _key: &str) -> Result<Option<Bytes>> {
        let next = self.raw_rx.lock().await.try_next().unwrap();
        next.expect("MockStorage get_raw called but no get_raw results available")
    }
    async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
        Ok(if let Some(delay) = self.delay {
            sleep(delay).await;
            delay
        } else {
            Duration::from_secs(0)
        })
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
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: self.preprocessor_cache_mode,
            ..Default::default()
        }
    }
}
