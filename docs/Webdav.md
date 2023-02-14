# WebDAV

Set `SCCACHE_WEBDAV_ENDPOINT` to a wevdav service endpoint to store cache in a webdav service. Set `SCCACHE_WEBDAV_KEY_PREFIX` to specify the key prefix of cache.

The webdav cache is compatible with:

- [Ccache HTTP storage backend](https://ccache.dev/manual/4.7.4.html#_http_storage_backend)
- [Bazel Remote Caching](https://bazel.build/remote/caching).
- [Gradle Build Cache](https://docs.gradle.org/current/userguide/build_cache.html)

Users can set `SCCACHE_WEBDAV_ENDPOINT` to those services directly.
