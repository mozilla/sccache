# COS

If you want to use _Tencent Cloud Object Storage_ (aka COS) for the sccache cache, you need to set the `SCCACHE_COS_BUCKET` environment variable to the name of the COS bucket to use.

You **must** specify the endpoint URL using the `SCCACHE_COS_ENDPOINT` environment variable. More details are at [COS endpoints](https://www.tencentcloud.com/document/product/436/6224).

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the COS bucket, effectively creating a scope. To do that use the `SCCACHE_COS_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.

## Credentials

Sccache is able to load credentials from environment variables: `TENCENTCLOUD_SECRET_ID` and `TENCENTCLOUD_SECRET_KEY`. More details about the access of COS bucket can be found at the [introduction page](https://www.tencentcloud.com/document/product/436/7751).
