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

    /// Create a new `RedisCache` by discovering the master via Redis Sentinel.
    ///
    /// Parses a `redis-sentinel://` URL, queries each sentinel node for the
    /// master address, then connects to the discovered master.
    ///
    /// # URL Format
    ///
    /// ```text
    /// redis-sentinel://[:password@]host1[:port1][,host2[:port2],...]/master_name[/db]
    /// ```
    ///
    /// - Multiple sentinel nodes are comma-separated
    /// - Password (if present) applies to the Redis master, not the sentinels
    /// - The `db` segment is optional and defaults to 0
    pub fn build_sentinel(url: &str, key_prefix: &str, ttl: u64) -> Result<Operator> {
        use std::net::ToSocketAddrs;

        debug!("Building Redis Sentinel cache from URL: {}", url);

        let parsed = parse_sentinel_url(url)?;

        debug!(
            "Sentinel nodes: {:?}, master_name: {}",
            parsed.nodes, parsed.master_name
        );

        let nodes_raw = parsed.nodes;
        let mut master_addr = None;
        let mut last_error: Option<String> = None;

        let master_name = &parsed.master_name;

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
                            .arg(master_name.as_str())
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
                                let msg = format!(
                                    "Sentinel returned incomplete response: {:?}",
                                    addr_parts
                                );
                                debug!("{}", msg);
                                last_error = Some(msg);
                            }
                            Err(e) => {
                                let msg = format!("Sentinel query failed: {}", e);
                                debug!("{}", msg);
                                last_error = Some(msg);
                            }
                        }
                    }
                    Err(e) => {
                        let msg = format!("Connection failed: {}", e);
                        debug!("{}", msg);
                        last_error = Some(msg);
                    }
                },
                Err(e) => {
                    let msg = format!("Client creation failed: {}", e);
                    debug!("{}", msg);
                    last_error = Some(msg);
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

        if let Some(ref pass) = parsed.password {
            builder = builder.password(pass);
        }

        if ttl != 0 {
            builder = builder.default_ttl(Duration::from_secs(ttl));
        }

        if let Some(db) = parsed.db {
            builder = builder.db(db);
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

/// Parsed components of a `redis-sentinel://` URL.
#[derive(Debug, PartialEq)]
struct SentinelUrl {
    /// Sentinel node addresses (host:port).
    nodes: Vec<String>,
    /// Sentinel master name.
    master_name: String,
    /// Optional password for the Redis master.
    password: Option<String>,
    /// Optional database number.
    db: Option<i64>,
}

/// Parse a `redis-sentinel://` URL into its components.
///
/// Format: `redis-sentinel://[:password@]host1[:port1][,host2[:port2],...]/master_name[/db]`
fn parse_sentinel_url(url: &str) -> Result<SentinelUrl> {
    let clean_url = url.trim_start_matches("redis-sentinel://");
    let parts: Vec<&str> = clean_url.splitn(3, '/').collect();
    if parts.len() < 2 || parts[1].is_empty() {
        return Err(anyhow!(
            "Invalid sentinel URL format: expected redis-sentinel://host:port/master_name"
        ));
    }

    let nodes_part = parts[0];
    let master_name = parts[1].to_string();

    // Handle password: rsplit_once so passwords containing '@' work correctly
    let (password, nodes_str) = if let Some((cred_part, nodes)) = nodes_part.rsplit_once('@') {
        let pass = cred_part.trim_start_matches(':');
        (Some(pass.to_string()), nodes)
    } else {
        (None, nodes_part)
    };

    let nodes: Vec<String> = nodes_str.split(',').map(|s| s.to_string()).collect();
    if nodes.is_empty() || nodes.iter().all(|n| n.is_empty()) {
        return Err(anyhow!("Invalid sentinel URL: no sentinel nodes specified"));
    }

    let db = if parts.len() > 2 && !parts[2].is_empty() {
        Some(
            parts[2]
                .parse::<i64>()
                .map_err(|_| anyhow!("Invalid db number in sentinel URL: '{}'", parts[2]))?,
        )
    } else {
        None
    };

    Ok(SentinelUrl {
        nodes,
        master_name,
        password,
        db,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_sentinel_url() {
        let parsed = parse_sentinel_url("redis-sentinel://host1:26379/mymaster").unwrap();
        assert_eq!(parsed.nodes, vec!["host1:26379"]);
        assert_eq!(parsed.master_name, "mymaster");
        assert_eq!(parsed.password, None);
        assert_eq!(parsed.db, None);
    }

    #[test]
    fn parse_multiple_nodes() {
        let parsed =
            parse_sentinel_url("redis-sentinel://h1:26379,h2:26379,h3:26379/mymaster").unwrap();
        assert_eq!(parsed.nodes, vec!["h1:26379", "h2:26379", "h3:26379"]);
        assert_eq!(parsed.master_name, "mymaster");
    }

    #[test]
    fn parse_with_password() {
        let parsed =
            parse_sentinel_url("redis-sentinel://:secretpass@host1:26379/mymaster").unwrap();
        assert_eq!(parsed.password, Some("secretpass".to_string()));
        assert_eq!(parsed.nodes, vec!["host1:26379"]);
    }

    #[test]
    fn parse_password_containing_at() {
        let parsed =
            parse_sentinel_url("redis-sentinel://:p@ss@word@host1:26379/mymaster").unwrap();
        assert_eq!(parsed.password, Some("p@ss@word".to_string()));
        assert_eq!(parsed.nodes, vec!["host1:26379"]);
    }

    #[test]
    fn parse_with_db() {
        let parsed = parse_sentinel_url("redis-sentinel://host1:26379/mymaster/3").unwrap();
        assert_eq!(parsed.db, Some(3));
    }

    #[test]
    fn parse_full_url() {
        let parsed =
            parse_sentinel_url("redis-sentinel://:hunter2@s1:26379,s2:26380/prod-master/5")
                .unwrap();
        assert_eq!(parsed.nodes, vec!["s1:26379", "s2:26380"]);
        assert_eq!(parsed.master_name, "prod-master");
        assert_eq!(parsed.password, Some("hunter2".to_string()));
        assert_eq!(parsed.db, Some(5));
    }

    #[test]
    fn parse_missing_master_name() {
        assert!(parse_sentinel_url("redis-sentinel://host1:26379").is_err());
        assert!(parse_sentinel_url("redis-sentinel://host1:26379/").is_err());
    }

    #[test]
    fn parse_invalid_db() {
        assert!(parse_sentinel_url("redis-sentinel://host:26379/master/notanumber").is_err());
    }

    #[test]
    fn parse_no_port() {
        let parsed = parse_sentinel_url("redis-sentinel://myhost/mymaster").unwrap();
        assert_eq!(parsed.nodes, vec!["myhost"]);
    }
}
