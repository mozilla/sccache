# Redis

Set `SCCACHE_REDIS` to a [Redis](https://redis.io/) url in format `redis://[:<passwd>@]<hostname>[:port][/<db>]` to store the cache in a Redis instance. Redis can be configured as a LRU (least recently used) cache with a fixed maximum cache size. Set `maxmemory` and `maxmemory-policy` according to the [Redis documentation](https://redis.io/topics/lru-cache). The `allkeys-lru` policy which discards the *least recently accessed or modified* key fits well for the sccache use case.

Redis over TLS is supported. Use the [`rediss://`](https://www.iana.org/assignments/uri-schemes/prov/rediss) url scheme (note `rediss` vs `redis`). Append `#insecure` the the url to disable hostname verification and accept self-signed certificates (dangerous!). Note that this also disables [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).

Set `SCCACHE_REDIS_TTL` in seconds if you don't want your cache to live forever. This will override the default behavior of redis.
