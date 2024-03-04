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
use opendal::services::Memcached;
use opendal::Operator;

use crate::errors::*;

#[derive(Clone)]
pub struct MemcachedCache;

impl MemcachedCache {
    pub fn build(
        url: &str,
        username: Option<&str>,
        password: Option<&str>,
        key_prefix: &str,
        expiration: u32,
    ) -> Result<Operator> {
        let mut builder = Memcached::default();
        builder.endpoint(url);

        if let Some(username) = username {
            builder.username(username);
        }
        if let Some(password) = password {
            builder.password(password);
        }

        builder.root(key_prefix);
        builder.default_ttl(Duration::from_secs(expiration.into()));

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
