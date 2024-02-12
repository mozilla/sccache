# Redis

Set `SCCACHE_REDIS` to a [Redis](https://redis.io/) url in format `redis://[[<username>]:<passwd>@]<hostname>[:port][/?db=<db>]` to store the cache in a Redis instance. Redis can be configured as a LRU (least recently used) cache with a fixed maximum cache size. Set `maxmemory` and `maxmemory-policy` according to the [Redis documentation](https://redis.io/topics/lru-cache). The `allkeys-lru` policy which discards the *least recently accessed or modified* key fits well for the sccache use case.

Redis over TLS is supported. Use the [`rediss://`](https://www.iana.org/assignments/uri-schemes/prov/rediss) url scheme (note `rediss` vs `redis`). Append `#insecure` the the url to disable hostname verification and accept self-signed certificates (dangerous!). Note that this also disables [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).

Set `SCCACHE_REDIS_EXPIRATION` in seconds if you don't want your cache to live forever. This will override the default behavior of redis.

`SCCACHE_REDIS_TTL` is a deprecated synonym for `SCCACHE_REDIS_EXPIRATION`.

Set `SCCACHE_REDIS_KEY_PREFIX` if you want to prefix all cache keys. This can be
useful when sharing a Redis instance with another application or cache.

## Examples

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
