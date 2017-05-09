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

use cache::{Cache,CacheWrite,Storage};
use errors::*;
use std::cell::RefCell;
use std::time::Duration;

/// A mock `Storage` implementation.
pub struct MockStorage {
    gets: RefCell<Vec<SFuture<Cache>>>,
    puts: RefCell<Vec<Result<CacheWrite>>>,
}

impl MockStorage {
    /// Create a new `MockStorage`.
    pub fn new() -> MockStorage {
        MockStorage {
            gets: RefCell::new(vec![]),
            puts: RefCell::new(vec![]),
        }
    }

    /// Queue up `res` to be returned as the next result from `Storage::get`.
    pub fn next_get(&self, res: SFuture<Cache>) {
        self.gets.borrow_mut().push(res)
    }

    /// Queue up `res` to be returned as the next result from `Storage::start_put`.
    pub fn next_put(&self, res: Result<CacheWrite>) {
        self.puts.borrow_mut().push(res)
    }
}

impl Storage for MockStorage {
    fn get(&self, _key: &str) -> SFuture<Cache> {
        let mut g = self.gets.borrow_mut();
        assert!(g.len() > 0, "MockStorage get called, but no get results available");
        g.remove(0)
    }
    fn start_put(&self, _key: &str) -> Result<CacheWrite> {
        let mut p = self.puts.borrow_mut();
        assert!(p.len() > 0, "MockStorage start_put called, but no put results available");
        p.remove(0)
    }
    fn finish_put(&self, _key: &str, _entry: CacheWrite) -> SFuture<Duration> {
        f_ok(Duration::from_secs(0))
    }
    fn location(&self) -> String { "Mock Storage".to_string() }
    fn current_size(&self) -> Option<usize> { None }
    fn max_size(&self) -> Option<usize> { None }
}
