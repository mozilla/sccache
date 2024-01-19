# OSS

If you want to use OSS storage for the sccache cache, you need to set the `SCCACHE_OSS_BUCKET` environment variable to the name of the OSS bucket to use.

You **must** configure the region using the `SCCACHE_ENDPOINT` environment variable.

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the OSS bucket, effectively creating a scope. To do that use the `SCCACHE_OSS_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.
