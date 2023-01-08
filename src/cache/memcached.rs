// Copyright 2016 Mozilla Foundation
// Copyright 2017 David Michael Barr <b@rr-dav.id.au>
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

use std::time::Duration;

use opendal::layers::LoggingLayer;
use opendal::services::memcached;
use opendal::Operator;

use crate::errors::*;

#[derive(Clone)]
pub struct MemcachedCache;

impl MemcachedCache {
    pub fn build(url: &str) -> Result<Operator> {
        let mut builder = memcached::Builder::default();
        builder.endpoint(url);
        // Set default ttl to 24 hours.
        builder.default_ttl(Duration::from_secs(24 * 3600));

        let op: Operator = builder.build()?.into();
        Ok(op.layer(LoggingLayer::default()))
    }
}
