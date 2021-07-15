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
cache_dir = "/home/user/.cache/cachepot-dist-client"

[dist.auth]
type = "token"
token = "secrettoken"


#[cache.azure]
# does not work as it appears

[cache.disk]
dir = "/tmp/.cache/cachepot"
size = 7516192768 # 7 GiBytes

[cache.gcs]
# optional url
url = "..."
rw_mode = "READ_ONLY"
# rw_mode = "READ_WRITE"
cred_path = "/psst/secret/cred"
bucket = "bucket"

[cache.memcached]
url = "..."

[cache.redis]
url = "redis://user:passwd@1.2.3.4:6379/1"

[cache.s3]
bucket = "name"
endpoint = "s3-us-east-1.amazonaws.com"
use_ssl = true
```

## env

Whatever is set by a file based configuration, it is overruled by the env
configuration variables

### misc

* `CACHEPOT_ALLOW_CORE_DUMPS` to enable core dumps by the server
* `CACHEPOT_CONF` configuration file path
* `CACHEPOT_CACHED_CONF`
* `CACHEPOT_IDLE_TIMEOUT` how long the local daemon process waits for more client requests before exiting
* `CACHEPOT_STARTUP_NOTIFY` specify a path to a socket which will be used for server completion notification
* `CACHEPOT_MAX_FRAME_LENGTH` how much data can be transfered between client and server
* `CACHEPOT_NO_DAEMON` set to `1` to disable putting the server to the background

### cache configs

#### disk

* `CACHEPOT_DIR` local on disk artifact cache directory
* `CACHEPOT_CACHE_SIZE` maximum size of the local on disk cache i.e. `10G`

#### s3 compatible

* `CACHEPOT_BUCKET` s3 bucket to be used
* `CACHEPOT_ENDPOINT` s3 endpoint
* `CACHEPOT_REGION` s3 region
* `CACHEPOT_S3_USE_SSL` s3 endpoint requires TLS, set this to `true`

The endpoint used then becomes `${CACHEPOT_BUCKET}.s3-{CACHEPOT_REGION}.amazonaws.com`.
If `CACHEPOT_REGION` is undefined, it will default to `us-east-1`.

#### redis

* `CACHEPOT_REDIS` full redis url, including auth and access token/passwd

The full url appears then as `redis://user:passwd@1.2.3.4:6379/1`.

#### memcached

* `CACHEPOT_MEMCACHED` memcached url

#### gcs

* `CACHEPOT_GCS_BUCKET`
* `CACHEPOT_GCS_CREDENTIALS_URL`
* `CACHEPOT_GCS_KEY_PATH`
* `CACHEPOT_GCS_RW_MODE`

#### azure

* `CACHEPOT_AZURE_CONNECTION_STRING`
