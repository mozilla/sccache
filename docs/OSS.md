# OSS

If you want to use _Object Storage Service_ (aka OSS) by Alibaba for the sccache cache, you need to set the `SCCACHE_OSS_BUCKET` environment variable to the name of the OSS bucket to use.

You **must** specify the endpoint URL using the `SCCACHE_OSS_ENDPOINT` environment variable. More details about [OSS endpoints](https://www.alibabacloud.com/help/en/oss/user-guide/regions-and-endpoints).

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the OSS bucket, effectively creating a scope. To do that use the `SCCACHE_OSS_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.

## Credentials

Sccache is able to load credentials from environment variables: `ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET`.

Alternatively, the `SCCACHE_OSS_NO_CREDENTIALS` environment variable can be set to use public readonly access to the OSS bucket, without the need for credentials. Valid values for this environment variable are `true`, `1`, `false`, and `0`. This can be useful for implementing a readonly cache for pull requests, which typically cannot be given access to credentials for security reasons.
