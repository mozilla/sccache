# Google Cloud Storage

To use [Google Cloud Storage](https://cloud.google.com/storage/), you need to set
the `SCCACHE_GCS_BUCKET` environment variable to the name of the GCS bucket.

By default, SCCACHE on GCS will be read-only. To change this, set `SCCACHE_GCS_RW_MODE`
to either `READ_ONLY` or `READ_WRITE`.

You can also define a prefix that will be prepended to the keys of all cache objects
created and read within the GCS bucket, effectively creating a scope. To do that
use the `SCCACHE_GCS_KEY_PREFIX` environment variable. This can be useful when
sharing a bucket with another application.

## Credentials

Sccache is able to load credentials from various sources. Including:

- User Input: If `SCCACHE_GCS_KEY_PATH` has been set, we will load from this file
  first.
  - Service accounts JSONs
  - External accounts JSONs
- [Task Cluster](https://taskcluster.net/): If `SCCACHE_GCS_CREDENTIALS_URL` has
  been set, we will load token from this url first.
- Static: `GOOGLE_APPLICATION_CREDENTIALS`
- Well-known locations:
  - Windows: `%APPDATA%\gcloud\application_default_credentials.json`
  - macOS/Linux:
    - `$XDG_CONFIG_HOME/gcloud/application_default_credentials.json`
    - `$HOME/.config/gcloud/application_default_credentials.json`
- VM Metadata: Fetch token will the specified service account.

### Service accounts

To create such account, in GCP, go in `APIs and Services` => `Cloud Storage` =>
`Create credentials` => `Service account`. Then, once created, click on the account
then `Keys` => `Add key` => `Create new key`. Select the JSON format and here it
is. This JSON file is what `SCCACHE_GCS_KEY_PATH` expects.

The service account needs `Storage Object Admin` permissions on the bucket
(otherwise, sccache will fail with a simple `Permission denied`).

### External accounts

Such accounts require creating a [Workload Identity Pool and Workload Identity Provider].
This approach allows the environment (Azure, Aws, or other OIDC providers like Github)
to create a temporary service account grant without having to share a service account
JSON, which can be pretty powerful. An example on how to create such accounts is
[Google's guide on how to use it with Github].

After generating the external account JSON file, you may pass its path to `SCCACHE_GCS_KEY_PATH`.

Service accounts used by the pool must have `Storage Object Admin` permissions on
bucket as well.

## Verifying it works

To verify that it works, run:

```
export SCCACHE_GCS_BUCKET=<bucket name in GCP>
export SCCACHE_GCS_KEY_PATH=secret-gcp-storage.json
./sccache --show-stats
# you should see
[...]
Cache location                  GCS, bucket: Bucket(name=<bucket name in GCP>), key_prefix: (none)
```

## Deprecation

`SCCACHE_GCS_OAUTH_URL` have been deprecated and not supported, please use `SCCACHE_GCS_SERVICE_ACCOUNT` instead.

[Workload Identity Pool and Workload Identity Provider]: https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers
[Google's guide on how to use it with Github]: https://cloud.google.com/blog/products/identity-security/enabling-keyless-authentication-from-github-actions
