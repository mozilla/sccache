# Memcached

Set `SCCACHE_MEMCACHED_ENDPOINT` to a [Memcached](https://memcached.org/) url in format `tcp://<hostname>:<port> ...` to store the cache in a Memcached instance.

`SCCACHE_MEMCACHED` is a deprecated alias for `SCCACHE_MEMCACHED_ENDPOINT` for unifying the variable name with other remote storages.

Set `SCCACHE_MEMCACHED_USERNAME` and `SCCACHE_MEMCACHED_PASSWORD` if you want to authenticate to Memcached.

Set `SCCACHE_MEMCACHED_EXPIRATION` to the default expiration seconds of memcached. The default value is `86400` (1 day) and can up to `2592000` (30 days). Set this value to `0` will disable the expiration. memcached will purge the cache entry while it exceed 30 days or meets LRU rules.

Set `SCCACHE_MEMCACHED_KEY_PREFIX` if you want to prefix all cache keys. This can be
useful when sharing a Memcached instance with another application or cache.
