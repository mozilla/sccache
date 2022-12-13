# Google Cloud Storage

To use [Google Cloud Storage](https://cloud.google.com/storage/), you need to set the `SCCACHE_GCS_BUCKET` environment variable to the name of the GCS bucket.

By default, SCCACHE on GCS will be read-only. To change this, set `SCCACHE_GCS_RW_MODE` to either `READ_ONLY` or `READ_WRITE`.

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the GCS bucket, effectively creating a scope. To do that use the `SCCACHE_GCS_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.

To create such account, in GCP, go in `APIs and Services` => `Cloud Storage` => `Create credentials` => `Service account`. Then, once created, click on the account then `Keys` => `Add key` => `Create new key`. Select the JSON format and here it is. This JSON file is what `SCCACHE_GCS_KEY_PATH` expects.
The service account needs `Storage Object Admin` permissions on the bucket (otherwise, sccache will fail with a simple `Permission denied`).

To verify that it works, run:

```
export SCCACHE_GCS_BUCKET=<bucket name in GCP>
export SCCACHE_GCS_KEY_PATH=secret-gcp-storage.json
./sccache --show-stats
# you should see
[...]
Cache location                  GCS, bucket: Bucket(name=<bucket name in GCP>), key_prefix: (none)
```

## Credentials

Sccache is able to load credentials from various sources. Including:

- User Input: If `SCCACHE_GCS_KEY_PATH` has been set, we will load from key path first.
- Static: `GOOGLE_APPLICATION_CREDENTIALS`
- Well-known locations:
  - Windows: `%APPDATA%\gcloud\application_default_credentials.json`
  - macOS/Linux:
    - `$XDG_CONFIG_HOME/gcloud/application_default_credentials.json`
    - `$HOME/.config/gcloud/application_default_credentials.json`
- VM Metadata: Fetch token will the specified service account.

## Deprecation

`SCCACHE_GCS_CREDENTIALS_URL` and `SCCACHE_GCS_OAUTH_URL` have been deprecated and not supported, please use `SCCACHE_GCS_SERVICE_ACCOUNT` instead.
