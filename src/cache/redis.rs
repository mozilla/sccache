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
use anyhow::anyhow;
use opendal::Operator;
use opendal::layers::LoggingLayer;
use opendal::services::Redis;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// A cache that stores entries in a Redis.
pub struct RedisCache;

impl RedisCache {
    /// Create a new `RedisCache` for the given URL.
    pub fn build_from_url(url: &str, key_prefix: &str, ttl: u64) -> Result<Operator> {
        let parsed = Url::parse(url)?;

        let mut builder = Redis::default()
            .endpoint(parsed.as_str())
            .username(parsed.username())
            .password(parsed.password().unwrap_or_default())
            .root(key_prefix);
        if ttl != 0 {
            builder = builder.default_ttl(Duration::from_secs(ttl));
        }

        let options: HashMap<_, _> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        builder = builder.db(options
            .get("db")
            .map(|v| v.parse().unwrap_or_default())
            .unwrap_or_default());

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }

    /// Create a new `RedisCache` for the given sentinel.
    pub fn build_sentinel(url: &str, key_prefix: &str, ttl: u64) -> Result<Operator> {
        use std::net::ToSocketAddrs;

        debug!("Building Redis Sentinel cache from URL: {}", url);

        // Basic parsing for: redis-sentinel://[:password@]host1[:port1][,host2[:port2],...]/master_name[/db]
        let clean_url = url.trim_start_matches("redis-sentinel://");
        let parts: Vec<&str> = clean_url.split('/').collect();
        if parts.len() < 2 {
            return Err(anyhow!(
                "Invalid sentinel URL format: expected redis-sentinel://host:port/master_name"
            ));
        }

        let nodes_part = parts[0];
        let master_name = parts[1];

        debug!(
            "Sentinel nodes: {}, master_name: {}",
            nodes_part, master_name
        );

        // Handle password if present
        let (password, nodes_str) = if nodes_part.contains('@') {
            let inner_parts: Vec<&str> = nodes_part.split('@').collect();
            let pass = inner_parts[0].trim_start_matches(':');
            (Some(pass.to_string()), inner_parts[1])
        } else {
            (None, nodes_part)
        };

        let nodes_raw: Vec<&str> = nodes_str.split(',').collect();
        let mut master_addr = None;
        let mut last_error: Option<String> = None;

        debug!(
            "Attempting to discover master '{}' from {} sentinel node(s)",
            master_name,
            nodes_raw.len()
        );

        for node in &nodes_raw {
            debug!("Trying sentinel node: {}", node);

            // Resolve hostname to IP address(es)
            let resolved_addr = match node.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        debug!("Resolved {} to {}", node, addr);
                        addr.to_string()
                    } else {
                        debug!("DNS resolved {} but returned no addresses", node);
                        node.to_string()
                    }
                }
                Err(e) => {
                    debug!(
                        "DNS resolution failed for {}: {}, using hostname directly",
                        node, e
                    );
                    node.to_string()
                }
            };

            let redis_url = format!("redis://{}", resolved_addr);
            debug!("Connecting to sentinel at: {}", redis_url);

            match redis::Client::open(redis_url.as_str()) {
                Ok(client) => match client.get_connection() {
                    Ok(mut conn) => {
                        let res: redis::RedisResult<Vec<String>> = redis::cmd("SENTINEL")
                            .arg("get-master-addr-by-name")
                            .arg(master_name)
                            .query(&mut conn);

                        match res {
                            Ok(addr_parts) if addr_parts.len() >= 2 => {
                                let discovered =
                                    format!("redis://{}:{}", addr_parts[0], addr_parts[1]);
                                debug!("Discovered master '{}' at: {}", master_name, discovered);
                                master_addr = Some(discovered);
                                break;
                            }
                            Ok(addr_parts) => {
                                last_error = Some(format!(
                                    "Sentinel returned incomplete response: {:?}",
                                    addr_parts
                                ));
                                debug!("{}", last_error.as_ref().unwrap());
                            }
                            Err(e) => {
                                last_error = Some(format!("Sentinel query failed: {}", e));
                                debug!("{}", last_error.as_ref().unwrap());
                            }
                        }
                    }
                    Err(e) => {
                        last_error = Some(format!("Connection failed: {}", e));
                        debug!("{}", last_error.as_ref().unwrap());
                    }
                },
                Err(e) => {
                    last_error = Some(format!("Client creation failed: {}", e));
                    debug!("{}", last_error.as_ref().unwrap());
                }
            }
        }

        let final_endpoint = match master_addr {
            Some(addr) => addr,
            None => {
                let err_detail = last_error.unwrap_or_else(|| "no sentinels responded".to_string());
                return Err(anyhow!(
                    "Could not discover master '{}' from any sentinel. Last error: {}",
                    master_name,
                    err_detail
                ));
            }
        };

        debug!("Using Redis master endpoint: {}", final_endpoint);

        let mut builder = Redis::default().endpoint(&final_endpoint).root(key_prefix);

        if let Some(pass) = password {
            builder = builder.password(&pass);
        }

        if ttl != 0 {
            builder = builder.default_ttl(Duration::from_secs(ttl));
        }

        // Optional DB from URL
        if parts.len() > 2 {
            if let Ok(db) = parts[2].parse::<i64>() {
                builder = builder.db(db);
            }
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();

        debug!("Redis Sentinel cache initialized successfully");
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
        let builder = Redis::default().endpoint(endpoint);

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
        let builder = Redis::default().cluster_endpoints(endpoints);

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
        builder = builder
            .username(username.unwrap_or_default())
            .password(password.unwrap_or_default())
            .db(db.into())
            .root(key_prefix);
        if ttl != 0 {
            builder = builder.default_ttl(Duration::from_secs(ttl));
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
