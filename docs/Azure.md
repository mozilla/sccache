# Azure

sccache can store its cache in an Azure Blob Storage container using either a
shared-key connection string or Microsoft Entra ID (passwordless) authentication.
In both cases set `SCCACHE_AZURE_BLOB_CONTAINER` to the name of an _existing_
container — sccache will not create it for you.

## Shared key (connection string)

Set the `SCCACHE_AZURE_CONNECTION_STRING` environment variable to your storage
account connection string.

## Microsoft Entra ID (passwordless)

Use this when the storage account has shared-key access disabled. Instead of a
connection string, tell sccache which account to talk to with one of the
following (if both are set, `SCCACHE_AZURE_ENDPOINT` takes precedence):

* `SCCACHE_AZURE_STORAGE_ACCOUNT` — the storage account name. sccache builds the
  endpoint `https://{account}.blob.core.windows.net`.
* `SCCACHE_AZURE_ENDPOINT` — a full blob endpoint, for sovereign clouds
  (`https://{account}.blob.core.usgovcloudapi.net`,
  `https://{account}.blob.core.chinacloudapi.cn`) or custom DNS. Takes
  precedence over `SCCACHE_AZURE_STORAGE_ACCOUNT`. It must use `https`; plain
  `http` is accepted only for a loopback host.

`SCCACHE_AZURE_CONNECTION_STRING` and `SCCACHE_AZURE_STORAGE_ACCOUNT` /
`SCCACHE_AZURE_ENDPOINT` are mutually exclusive.

> **Azurite:** the local emulator authenticates with its well-known shared key,
> so point sccache at it with `SCCACHE_AZURE_CONNECTION_STRING` (the shared-key
> section above), not the passwordless path — the latter would require Azurite's
> non-default OAuth mode plus an ambient Entra credential.

Credentials are then resolved from the ambient environment, in this order:

1. **Service principal** — `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
2. **Workload identity** (AKS / Kubernetes / federated OIDC) — `AZURE_TENANT_ID`,
   `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`.
3. **Managed identity** via the instance-metadata endpoint (`169.254.169.254`) —
   Azure **VM / VM Scale Sets** and self-hosted CI agents running on them. No
   variables required; set `AZURE_CLIENT_ID` to select a specific user-assigned
   identity.

> **Managed-identity limitations.** App Service, Functions, Container Apps, and
> Container Instances expose managed identity only over the `IDENTITY_ENDPOINT`
> protocol, which this backend does not use — prefer **workload identity** or a
> **service principal** on those hosts. In any environment with an HTTP proxy
> configured, add `169.254.169.254` to `NO_PROXY`, or the metadata request is
> routed to the proxy and fails. Credentials resolve lazily, so a misconfigured
> passwordless setup builds successfully and fails only on the first cache
> access, not at server startup.

For **sovereign clouds**, `AZURE_AUTHORITY_HOST` is **required** for the service
principal and workload identity flows (it defaults to
`https://login.microsoftonline.com`): use `https://login.microsoftonline.us`
(US Gov) or `https://login.partner.microsoftonline.cn` (China). Managed identity
via IMDS does not need it. The identity needs a data-plane role on the container:
**Storage Blob Data Contributor** for `READ_WRITE` (the default), or **Storage
Blob Data Reader** when `SCCACHE_AZURE_RW_MODE=READ_ONLY`. sccache does not read
or log any `AZURE_*` value — they are consumed directly by the underlying storage
SDK when signing requests with an OAuth bearer token.

> **Note:** the underlying storage SDK also honours the ambient
> `AZBLOB_ACCOUNT_KEY` / `AZBLOB_SAS_TOKEN` variables, which take precedence over
> Entra ID credentials. Unset them if you intend to authenticate passwordlessly.

## Common options

You can define a prefix that will be prepended to the keys of all cache objects
created and read within the container, effectively creating a scope. To do that
use the `SCCACHE_AZURE_KEY_PREFIX` environment variable. This can be useful when
sharing a container with another application.

The `SCCACHE_AZURE_RW_MODE` environment variable can be set to `READ_ONLY` to
make sccache use this backend in read-only mode. The default is `READ_WRITE`.

**Important:** The environment variables are only taken into account when the
server starts, i.e. only on the first run.
