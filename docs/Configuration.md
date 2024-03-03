# Available Configuration Options

## file

```toml
[dist]
# where to find the scheduler
scheduler_url = "http://1.2.3.4:10600"
# a set of prepackaged toolchains
toolchains = []
# the maximum size of the toolchain cache in bytes
toolchain_cache_size = 5368709120
cache_dir = "/home/user/.cache/sccache-dist-client"

[dist.auth]
type = "token"
token = "secrettoken"


#[cache.azure]
# does not work as it appears

[cache.disk]
dir = "/tmp/.cache/sccache"
size = 7516192768 # 7 GiBytes

# See the local docs on more explanations about this mode
[cache.disk.preprocessor_cache_mode]
# Whether to use the preprocessor cache mode
use_preprocessor_cache_mode = true
# Whether to use file times to check for changes
file_stat_matches = true
# Whether to also use ctime (file status change) time to check for changes
use_ctime_for_stat = true
# Whether to ignore `__TIME__` when caching
ignore_time_macros = false
# Whether to skip (meaning not cache, only hash) system headers
skip_system_headers = false
# Whether hash the current working directory
hash_working_directory = true

[cache.gcs]
# optional oauth url
oauth_url = "..."
# optional deprecated url
deprecated_url = "..."
rw_mode = "READ_ONLY"
# rw_mode = "READ_WRITE"
cred_path = "/psst/secret/cred"
bucket = "bucket"
key_prefix = "prefix"

[cache.gha]
url = "http://localhost"
token = "secret"
cache_to = "sccache-latest"
cache_from = "sccache-"

[cache.memcached]
# Deprecated alias for `endpoint`
# url = "127.0.0.1:11211"
endpoint = "tcp://127.0.0.1:11211"
# Username and password for authentication
username = "user"
password = "passwd"
# Entry expiration time in seconds. Default is 86400 (24 hours)
expiration = 3600
key_prefix = "/custom/prefix/if/need"

[cache.redis]
# Deprecated, use `endpoint` instead
url = "redis://user:passwd@1.2.3.4:6379/?db=1"
## Refer to the `opendal` documentation for more information about Redis endpoint
# Single-node endpoint. Mutually exclusive with `cluster_endpoints`
endpoint = "redis://127.0.0.1:6379"
# Multiple-node list of endpoints (cluster mode). Mutually exclusive with `endpoint`
cluster_endpoints = "redis://10.0.0.1:6379,redis://10.0.0.2:6379"
username = "user"
password = "passwd"
# Database number to use. Default is 0
db = 1
# Entry expiration time in seconds. Default is 0 (never expire)
expiration = 3600
key_prefix = "/custom/prefix/if/need"

[cache.s3]
bucket = "name"
endpoint = "s3-us-east-1.amazonaws.com"
use_ssl = true
key_prefix = "s3prefix"
server_side_encryption = false

[cache.webdav]
endpoint = "http://192.168.10.42:80/some/webdav.php"
key_prefix = "/custom/webdav/subfolder/if/need"
# Basic HTTP authentication credentials.
username = "alice"
password = "secret12"
# Mutually exclusive with username & password. Bearer token value
token = "token123"

[cache.oss]
bucket = "name"
endpoint = "oss-us-east-1.aliyuncs.com"
key_prefix = "ossprefix"
no_credentials = true
```

sccache looks for its configuration file at the path indicated by env variable `SCCACHE_CONF`.

If no such env variable is set, sccache looks at default locations as below:
- Linux: `~/.config/sccache/config`
- macOS: `~/Library/Application Support/Mozilla.sccache/config`
- Windows: `%APPDATA%\Mozilla\sccache\config\config`

The latest `cache.XXX` entries may be found here: https://github.com/mozilla/sccache/blob/ffe3070f77ef3301c8ff718316e4ab017ec83042/src/config.rs#L300.

## env

Whatever is set by a file based configuration, it is overruled by the env
configuration variables

### misc

* `SCCACHE_ALLOW_CORE_DUMPS` to enable core dumps by the server
* `SCCACHE_CONF` configuration file path
* `SCCACHE_CACHED_CONF`
* `SCCACHE_IDLE_TIMEOUT` how long the local daemon process waits for more client requests before exiting, in seconds. Set to `0` to run sccache permanently
* `SCCACHE_STARTUP_NOTIFY` specify a path to a socket which will be used for server completion notification
* `SCCACHE_MAX_FRAME_LENGTH` how much data can be transferred between client and server
* `SCCACHE_NO_DAEMON` set to `1` to disable putting the server to the background
* `SCCACHE_CACHE_MULTIARCH` to disable caching of multi architecture builds.

### cache configs

#### disk (local)

* `SCCACHE_DIR` local on disk artifact cache directory
* `SCCACHE_CACHE_SIZE` maximum size of the local on disk cache i.e. `2G` - default is 10G
* `SCCACHE_DIRECT` enable/disable preprocessor caching (see [the local doc](Local.md))
* `SCCACHE_LOCAL_RW_MODE` the mode that the cache will operate in (`READ_ONLY` or `READ_WRITE`)

#### s3 compatible

* `SCCACHE_BUCKET` s3 bucket to be used
* `SCCACHE_ENDPOINT` s3 endpoint
* `SCCACHE_REGION` s3 region, required if using AWS S3
* `SCCACHE_S3_USE_SSL` s3 endpoint requires TLS, set this to `true`
* `SCCACHE_S3_KEY_PREFIX` s3 key prefix (optional)

The endpoint used then becomes `${SCCACHE_BUCKET}.s3-{SCCACHE_REGION}.amazonaws.com`.
If you are not using the default endpoint and `SCCACHE_REGION` is undefined, it
will default to `us-east-1`.

#### cloudflare r2

* `SCCACHE_BUCKET` is the name of your R2 bucket.
* `SCCACHE_ENDPOINT` must follow the format of `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`. Note that the `https://` must be included. Your account ID can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).
* `SCCACHE_REGION` should be set to `auto`.
* `SCCACHE_S3_KEY_PREFIX` s3 key prefix (optional).

#### redis

* `SCCACHE_REDIS` full redis url, including auth and access token/passwd (deprecated).
* `SCCACHE_REDIS_ENDPOINT` redis url without auth and access token/passwd - single node configuration.
* `SCCACHE_REDIS_CLUSTER_ENDPOINTS` redis cluster urls, separated by comma - shared cluster configuration.
* `SCCACHE_REDIS_USERNAME` redis username (optional).
* `SCCACHE_REDIS_PASSWORD` redis password (optional).
* `SCCACHE_REDIS_DB` redis database (optional, default is 0).
* `SCCACHE_REDIS_EXPIRATION` / `SCCACHE_REDIS_TTL` ttl for redis cache, don't set for default behavior.
* `SCCACHE_REDIS_KEY_PREFIX` key prefix (optional).

The full url appears then as `redis://user:passwd@1.2.3.4:6379/?db=1`.

#### memcached

* `SCCACHE_MEMCACHED` is a deprecated alias for `SCCACHE_MEMCACHED_ENDPOINT`.
* `SCCACHE_MEMCACHED_ENDPOINT` memcached url.
* `SCCACHE_MEMCACHED_USERNAME` memcached username (optional).
* `SCCACHE_MEMCACHED_PASSWORD` memcached password (optional).
* `SCCACHE_MEMCACHED_EXPIRATION` ttl for memcached cache, don't set for default behavior.
* `SCCACHE_MEMCACHED_KEY_PREFIX` key prefix (optional).

#### gcs

* `SCCACHE_GCS_BUCKET`
* `SCCACHE_GCS_CREDENTIALS_URL`
* `SCCACHE_GCS_KEY_PATH`
* `SCCACHE_GCS_RW_MODE`

#### azure

* `SCCACHE_AZURE_CONNECTION_STRING`

#### gha

* `SCCACHE_GHA_CACHE_URL` / `ACTIONS_CACHE_URL` GitHub Actions cache API URL
* `SCCACHE_GHA_RUNTIME_TOKEN` / `ACTIONS_RUNTIME_TOKEN` GitHub Actions access token
* `SCCACHE_GHA_CACHE_TO` cache key to write
* `SCCACHE_GHA_CACHE_FROM` comma separated list of cache keys to read from

#### webdav

* `SCCACHE_WEBDAV_ENDPOINT` a webdav service endpoint to store cache, such as `http://127.0.0.1:8080/my/webdav.php`.
* `SCCACHE_WEBDAV_KEY_PREFIX` specify the key prefix (subfolder) of cache (optional).
* `SCCACHE_WEBDAV_USERNAME` a username to authenticate with webdav service (optional).
* `SCCACHE_WEBDAV_PASSWORD` a password to authenticate with webdav service (optional).
* `SCCACHE_WEBDAV_TOKEN` a token to authenticate with webdav service (optional) - may be used instead of login & password.

#### OSS

* `SCCACHE_OSS_BUCKET`
* `SCCACHE_OSS_ENDPOINT`
* `SCCACHE_OSS_KEY_PREFIX`
* `ALIBABA_CLOUD_ACCESS_KEY_ID`
* `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
* `SCCACHE_OSS_NO_CREDENTIALS`
