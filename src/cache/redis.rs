// Copyright 2016 Mozilla Foundation
// Copyright 2016 Felix Obenhuber <felix@obenhuber.de>
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

use crate::errors::*;
use opendal::layers::LoggingLayer;
use opendal::services::Redis;
use opendal::Operator;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// A cache that stores entries in a Redis.
pub struct RedisCache;

impl RedisCache {
    /// Create a new `RedisCache` for the given URL.
    pub fn build_from_url(url: &str, key_prefix: &str, ttl: u64) -> Result<Operator> {
        let parsed = Url::parse(url)?;

        let mut builder = Redis::default();
        builder.endpoint(parsed.as_str());
        builder.username(parsed.username());
        builder.password(parsed.password().unwrap_or_default());
        builder.root(key_prefix);
        if ttl != 0 {
            builder.default_ttl(Duration::from_secs(ttl));
        }

        let options: HashMap<_, _> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        builder.db(options
            .get("db")
            .map(|v| v.parse().unwrap_or_default())
            .unwrap_or_default());

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }

    /// Create a new `RedisCache` for the given single instance.
    pub fn build_single(
        endpoint: &str,
        username: Option<&str>,
        password: Option<&str>,
        db: u32,
        key_prefix: &str,
        ttl: u64,
    ) -> Result<Operator> {
        let mut builder = Redis::default();
        builder.endpoint(endpoint);

        Self::build_common(builder, username, password, db, key_prefix, ttl)
    }

    /// Create a new `RedisCache` for the given cluster.
    pub fn build_cluster(
        endpoints: &str,
        username: Option<&str>,
        password: Option<&str>,
        db: u32,
        key_prefix: &str,
        ttl: u64,
    ) -> Result<Operator> {
        let mut builder = Redis::default();
        builder.cluster_endpoints(endpoints);

        Self::build_common(builder, username, password, db, key_prefix, ttl)
    }

    fn build_common(
        mut builder: Redis,
        username: Option<&str>,
        password: Option<&str>,
        db: u32,
        key_prefix: &str,
        ttl: u64,
    ) -> Result<Operator> {
        builder.username(username.unwrap_or_default());
        builder.password(password.unwrap_or_default());
        builder.root(key_prefix);
        if ttl != 0 {
            builder.default_ttl(Duration::from_secs(ttl));
        }
        builder.db(db.into());

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
