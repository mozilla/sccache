# Memcached

Set `SCCACHE_MEMCACHED` to a [Memcached](https://memcached.org/) url in format `tcp://<hostname>:<port> ...` to store the cache in a Memcached instance.

Set `SCCACHE_MEMCACHED_EXPIRATION` to the default expiration seconds of memcached. The default value is `86400` (1 day) and can up to `2592000` (30 days). Set this value to `0` will disable the expiration. memcached will purge the cache entry while it exceed 30 days or meets LRU rules.
