# WebDAV

Users can configure sccache to cache incremental build artifacts in a remote WebDAV service.
The following services all expose a WebDAV interface and can be used as a backend:

- [Ccache HTTP storage backend](https://ccache.dev/manual/4.7.4.html#_http_storage_backend)
- [Bazel Remote Caching](https://bazel.build/remote/caching).
- [Gradle Build Cache](https://docs.gradle.org/current/userguide/build_cache.html)

Set `SCCACHE_WEBDAV_ENDPOINT` to an appropriate webdav service endpoint to enable remote caching.
Set `SCCACHE_WEBDAV_KEY_PREFIX` to specify the key prefix of cache.

The `SCCACHE_WEBDAV_RW_MODE` environment variable can be set to `READ_ONLY` to make sccache use this backend in read-only mode. The default is `READ_WRITE`.

## Credentials

Sccache is able to load credentials from the following sources:

- Set `SCCACHE_WEBDAV_USERNAME`/`SCCACHE_WEBDAV_PASSWORD` to specify the username/password pair for basic authentication.
- Set `SCCACHE_WEBDAV_TOKEN` to specify the token value for bearer token authentication.

## Disable Create Dir

Some WebDAV servers don't support the `PROPFIND`/`MKCOL` methods that opendal's WebDAV
backend otherwise issues before every write to ensure the parent directory exists. Sonatype
Nexus raw repositories are one example: they only implement `GET`/`HEAD`/`PUT`/`DELETE` and
reject `MKCOL` with `405 Method Not Allowed`, which makes every cache write fail.

Set `SCCACHE_WEBDAV_DISABLE_CREATE_DIR=true` to skip these calls during writes.
