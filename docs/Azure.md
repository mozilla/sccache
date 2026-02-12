# Azure

To use Azure Blob Storage, you'll need your Azure connection string and an _existing_ Blob Storage container name.  Set the `SCCACHE_AZURE_CONNECTION_STRING`
environment variable to your connection string, and `SCCACHE_AZURE_BLOB_CONTAINER` to the name of the container to use.  Note that sccache will not create
the container for you - you'll need to do that yourself.

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the container, effectively creating a scope. To do that use the `SCCACHE_AZURE_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.

Alternatively, the `SCCACHE_AZURE_NO_CREDENTIALS` environment variable can be set to use public readonly access to the Azure Blob Storage container, without the need for credentials. Valid values for this environment variable are `true`, `1`, `false`, and `0`.

When using anonymous access, the connection string only needs to contain the endpoint, e.g. `BlobEndpoint=https://accountname.blob.core.windows.net`.

**Important:** The environment variables are only taken into account when the server starts, i.e. only on the first run.
