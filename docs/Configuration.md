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

[cache.memcached]
url = "..."

[cache.redis]
url = "redis://user:passwd@1.2.3.4:6379/1"

[cache.s3]
bucket = "name"
endpoint = "s3-us-east-1.amazonaws.com"
use_ssl = true
key_prefix = "s3prefix"
```

## env

Whatever is set by a file based configuration, it is overruled by the env
configuration variables

### misc

* `SCCACHE_ALLOW_CORE_DUMPS` to enable core dumps by the server
* `SCCACHE_CONF` configuration file path
* `SCCACHE_CACHED_CONF`
* `SCCACHE_IDLE_TIMEOUT` how long the local daemon process waits for more client requests before exiting
* `SCCACHE_STARTUP_NOTIFY` specify a path to a socket which will be used for server completion notification
* `SCCACHE_MAX_FRAME_LENGTH` how much data can be transferred between client and server
* `SCCACHE_NO_DAEMON` set to `1` to disable putting the server to the background

### cache configs

#### disk

* `SCCACHE_DIR` local on disk artifact cache directory
* `SCCACHE_CACHE_SIZE` maximum size of the local on disk cache i.e. `10G`

#### s3 compatible

* `SCCACHE_BUCKET` s3 bucket to be used
* `SCCACHE_ENDPOINT` s3 endpoint
* `SCCACHE_REGION` s3 region
* `SCCACHE_S3_USE_SSL` s3 endpoint requires TLS, set this to `true`

The endpoint used then becomes `${SCCACHE_BUCKET}.s3-{SCCACHE_REGION}.amazonaws.com`.
If `SCCACHE_REGION` is undefined, it will default to `us-east-1`.

#### redis

* `SCCACHE_REDIS` full redis url, including auth and access token/passwd

The full url appears then as `redis://user:passwd@1.2.3.4:6379/1`.

#### memcached

* `SCCACHE_MEMCACHED` memcached url

#### gcs

* `SCCACHE_GCS_BUCKET`
* `SCCACHE_GCS_CREDENTIALS_URL`
* `SCCACHE_GCS_KEY_PATH`
* `SCCACHE_GCS_RW_MODE`

#### azure

* `SCCACHE_AZURE_CONNECTION_STRING`
