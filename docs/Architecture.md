# Sccache high level architecture

Sccache supports two compilation modes: **server-side compilation** (legacy) and **client-side compilation** (new). The mode is controlled by the `SCCACHE_CLIENT_SIDE_COMPILE` environment variable.

## Server-Side Compilation (Legacy Mode)

This is the default mode when `SCCACHE_CLIENT_SIDE_COMPILE` is unset or set to `0`.

In this mode, the server performs all compilation work:

```mermaid
  flowchart TB
      Client[Client Process]
      Server[Sccache Server]
      Storage[(Cache Storage)]

      Client -->|1. Compile Request<br/>exe, args, cwd, env| Server
      Server -->|2. Detect Compiler| Server
      Server -->|3. Preprocess & Hash| Server
      Server -->|4. Check Cache| Storage
      Storage -->|Cache Hit| Server
      Storage -->|Cache Miss| Server
      Server -->|5a. Return Cached Result| Client
      Server -->|5b. Compile Locally| Server
      Server -->|6. Store Result| Storage
      Server -->|7. Return Result| Client
```

**Characteristics**:
- Server performs compiler detection, preprocessing, hash generation, and compilation
- All work happens on the server machine
- Server can become a bottleneck with many parallel clients
- Higher server CPU and memory usage

## Client-Side Compilation (New Mode)

Enabled by setting `SCCACHE_CLIENT_SIDE_COMPILE=1`.

In this mode, the client performs compilation work and the server acts as pure storage:

```mermaid
  flowchart TB
      Client[Client Process]
      Server[Sccache Server<br/>Storage Service Only]
      Storage[(Cache Storage)]

      Client -->|1. Detect Compiler| Client
      Client -->|2. Preprocess & Hash| Client
      Client -->|3. CacheGet Request<br/>cache_key| Server
      Server -->|4. Query Storage| Storage
      Storage -->|Cache Hit| Server
      Server -->|5a. Return Cache Entry| Client
      Client -->|Use Cached Result| Client
      Storage -->|Cache Miss| Server
      Server -->|5b. Cache Miss| Client
      Client -->|6. Compile Locally| Client
      Client -->|7. CachePut Request<br/>cache_key, entry| Server
      Server -->|8. Store in Cache| Storage
```

**Characteristics**:
- Client performs compiler detection, preprocessing, hash generation, and compilation
- Server only handles cache storage operations (get/put)
- Work is distributed across all clients (better scalability)
- Lower server CPU and memory usage
- Reduced network latency (single request instead of multiple round trips)

**Note**: Client-side compilation is currently in foundational stage. When enabled, the system falls back to legacy server-side compilation with a warning message. Full implementation is planned for a future release.

## Comparison

| Aspect | Server-Side (Legacy) | Client-Side (New) |
|--------|---------------------|-------------------|
| Compiler Detection | Server | Client (with caching) |
| Preprocessing | Server | Client |
| Hash Generation | Server | Client |
| Compilation | Server | Client |
| Server Role | Full compilation service | Pure storage service |
| Server CPU Usage | High | Low |
| Server Memory Usage | Moderate | Low |
| Client Overhead | Low | Moderate |
| Scalability | Limited by server | Excellent |
| Network Requests | Multiple round trips | Single request |

## Cache Key Generation

Regardless of the mode, cache keys are generated from:

```mermaid
  flowchart LR
      id1[[Environment variables]] --> hash
      id2[[Compiler binary]] --> hash
      id3[[Compiler arguments]] --> hash
      id5[[Preprocessed Files]] --> hash
      hash([BLAKE3 Hash]) --> key[Cache Key]
```

For more details about how hash generation works, see [the caching documentation](Caching.md).

## Protocol

### Server-Side Mode Protocol

- **Request**: `Compile(Compile)` - Contains executable path, arguments, working directory, environment variables
- **Response**: `CompileFinished(CompileFinished)` - Contains exit code, stdout, stderr, and output file paths

### Client-Side Mode Protocol

- **Request**: `CacheGet(CacheGetRequest)` - Contains cache key
- **Response**: `CacheGetResponse::Hit(Vec<u8>)` - Cache entry as bytes
- **Response**: `CacheGetResponse::Miss` - Cache miss
- **Request**: `CachePut(CachePutRequest)` - Contains cache key and entry bytes
- **Response**: `CachePutResponse(Duration)` - Storage duration

The protocol supports version negotiation to maintain backward compatibility during migration from server-side to client-side mode.

## Storage Backends

Both modes use the same cache storage backends:

- **Local Disk** (`SCCACHE_DIR`)
- **S3 Compatible** (`SCCACHE_BUCKET`, `SCCACHE_ENDPOINT`)
- **Redis** (`SCCACHE_REDIS_ENDPOINT`)
- **Memcached** (`SCCACHE_MEMCACHED_ENDPOINT`)
- **Google Cloud Storage** (`SCCACHE_GCS_BUCKET`)
- **Azure Blob Storage** (`SCCACHE_AZURE_CONNECTION_STRING`)
- **GitHub Actions Cache** (`SCCACHE_GHA_CACHE_URL`)
- **WebDAV** (`SCCACHE_WEBDAV_ENDPOINT`)
- **Alibaba Cloud OSS** (`SCCACHE_OSS_BUCKET`)
- **Tencent Cloud COS** (`SCCACHE_COS_BUCKET`)

See [Configuration.md](Configuration.md) for storage backend configuration details.

