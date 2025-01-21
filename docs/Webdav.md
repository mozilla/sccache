# WebDAV

Users can configure sccache to cache incremental build artifacts in a remote WebDAV service.
The following services all expose a WebDAV interface and can be used as a backend:

- [Ccache HTTP storage backend](https://ccache.dev/manual/4.7.4.html#_http_storage_backend)
- [Bazel Remote Caching](https://bazel.build/remote/caching).
- [Gradle Build Cache](https://docs.gradle.org/current/userguide/build_cache.html)

Set `SCCACHE_WEBDAV_ENDPOINT` to an appropriate webdav service endpoint to enable remote caching.
Set `SCCACHE_WEBDAV_KEY_PREFIX` to specify the key prefix of cache.

## Credentials

Sccache is able to load credentials from the following sources:

- Set `SCCACHE_WEBDAV_USERNAME`/`SCCACHE_WEBDAV_PASSWORD` to specify the username/password pair for basic authentication.
- Set `SCCACHE_WEBDAV_TOKEN` to specify the token value for bearer token authentication.
