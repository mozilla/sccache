# Redis

If you want to use [Redis](https://redis.io/) storage for the sccache cache, you need to set the `SCCACHE_REDIS_ENDPOINT` with the single-node redis URL.
If you want to use a Redis cluster, set `SCCACHE_REDIS_CLUSTER_ENDPOINTS` instead of `SCCACHE_REDIS_ENDPOINT` with the comma-separated list of redis node URLs.

Redis endpoint URL format can be found in the [OpenDAL source code](https://github.com/apache/opendal/blob/5f1d5d1d61ed28f63d4955538b33a4d582feebef/core/src/services/redis/backend.rs#L268-L307). Some valid examples:
* `redis://127.0.0.1:6379` or `tcp://127.0.0.1:6379` or `127.0.0.1:6379` - TCP-based Redis connection (non-secure)
* `rediss://@1.2.3.4:6379` - TLS-based Redis connection over TCP (secure)
* `unix:///tmp/redis.sock` or `redis+unix:///tmp/redis.sock` - Unix socket-based Redis connection

Redis can be configured as a LRU (least recently used) cache with a fixed maximum cache size. Set `maxmemory` and `maxmemory-policy` according to the [Redis documentation](https://redis.io/topics/lru-cache). The `allkeys-lru` policy which discards the *least recently accessed or modified* key fits well for the sccache use case.

Redis over TLS is supported. Use the [`rediss://`](https://www.iana.org/assignments/uri-schemes/prov/rediss) url scheme (note `rediss` vs `redis`). Append `#insecure` the the url to disable hostname verification and accept self-signed certificates (dangerous!). Note that this also disables [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).

If you want to authenticate to Redis, set `SCCACHE_REDIS_USERNAME` and `SCCACHE_REDIS_PASSWORD` to the username and password accordingly.

`SCCACHE_REDIS_DB` is the database number to use. Default is 0.

Set `SCCACHE_REDIS_EXPIRATION` in seconds if you don't want your cache to live forever. This will override the default behavior of redis.

`SCCACHE_REDIS_TTL` is a deprecated synonym for `SCCACHE_REDIS_EXPIRATION`.

Set `SCCACHE_REDIS_KEY_PREFIX` if you want to prefix all cache keys. This can be
useful when sharing a Redis instance with another application or cache.

`SCCACHE_REDIS` is deprecated for security reasons, use `SCCACHE_REDIS_ENDPOINT` instead. See mozilla/sccache#2083 for details.
If you really want to use `SCCACHE_REDIS`, you should URL in format `redis://[[<username>]:<passwd>@]<hostname>[:port][/?db=<db>]`.

## Deprecated API Examples

Use the local Redis instance with no password:
```sh
SCCACHE_REDIS=redis://localhost
```

Use the local Redis instance on port `6379` with password `qwerty`:
```sh
SCCACHE_REDIS=redis://:qwerty@localhost:6379
```

Use the `192.168.1.10` Redis instance on port `6380` with username `alice`, password `qwerty123` and database `12` via TLS connection:
```sh
SCCACHE_REDIS=rediss://alice:qwerty123@192.168.1.10:6380/?db=12
```
