# Google Cloud Storage

To use [Google Cloud Storage](https://cloud.google.com/storage/), you need to set the `SCCACHE_GCS_BUCKET` environment variable to the name of the GCS bucket.

If you're using authentication, either:
- Set `SCCACHE_GCS_KEY_PATH` to the location of your JSON service account credentials
- (Deprecated) Set `SCCACHE_GCS_CREDENTIALS_URL` to a URL returning an OAuth token in non-standard `{"accessToken": "...", "expireTime": "..."}` format.
- Set `SCCACHE_GCS_OAUTH_URL` to a URL returning an OAuth token. If you are running on a Google Cloud instance, this is of the form `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/${YOUR_SERVICE_ACCOUNT}/token`

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
