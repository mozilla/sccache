# Multi-Level Cache

Multi-level caching enables hierarchical cache storage, similar to how CPUs use L1/L2/L3 caches or CDNs use edge/regional/origin tiers. This feature allows sccache to check multiple storage backends in sequence, dramatically improving cache hit rates and reducing latency.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Use Cases](#use-cases)
- [Configuration](#configuration)
- [Best Practices](#best-practices)

## Overview

Multi-level caching allows you to configure multiple cache storage backends that work together:

- **Fast, small caches** (e.g., local disk) are checked first
- **Slower, larger caches** (e.g., S3) are checked if earlier levels miss
- **Cache hits at any level** return immediately to the compiler
- **Automatic backfill** copies data from slower to faster levels for future requests
- **Write-through** ensures all levels stay synchronized on writes

This creates a cache hierarchy where frequently accessed artifacts stay in fast storage while less common ones are still available from slower storage.

## Architecture

### Cache Hierarchy

```
┌─────────────────────────────────────────────────┐
│               Compiler Request                  │
└─────────────────────┬───────────────────────────┘
                      │
         ┌────────────▼────────────┐
         │   Multi-Level Storage   │
         └────────────┬────────────┘
                      │
      ┌───────────────┼───────────────┐
      │               │               │
┌─────▼─────┐    ┌────▼────┐     ┌────▼────┐
│ Level 0   │    │ Level 1 │     │ Level 2 │
│  (Disk)   │    │ (Redis) │     │  (S3)   │
│           │    │         │     │         │
│ Fast      │    │ Medium  │     │ Slow    │
│ Small     │    │ Medium  │     │ Large   │
│ ~5ms      │    │ ~10ms   │     │ ~200ms  │
└───────────┘    └─────────┘     └─────────┘
```

### Read Path (Cache Hit at Level 2)

```
1. Check L0 (disk)    → Miss (5ms)
2. Check L1 (redis)   → Miss (10ms)
3. Check L2 (s3)      → Hit! (200ms)
4. Return to compiler (Total: 215ms)
5. Background: Backfill L2→L1 (async, non-blocking)
6. Background: Backfill L2→L0 (async, non-blocking)
7. Next request: Check L0 → Hit! (10ms)
```

### Write Path

All write operations go to **all configured levels** in parallel:

```
Compiler writes artifact
    ├─> L0 (disk)  ✓
    ├─> L1 (redis) ✓
    └─> L2 (s3)    ✓
```

If any level fails, the error is logged but the write succeeds if at least one level accepts it.

## Use Cases

### 1. CI/CD with Shared Team Cache

**Problem**: Each CI runner has isolated disk cache, no sharing across machines.

**Solution**: Add Redis or Memcached as L1
```bash
SCCACHE_MULTILEVEL_CHAIN="disk,redis"
SCCACHE_DIR="/tmp/sccache"
SCCACHE_REDIS_ENDPOINT="redis://cache.internal:6379"
```

**Result**: Fast local hits when available, team-shared cache otherwise.

### 2. Enterprise with CDN-like Architecture

**Problem**: Global team with high S3 latency, want local speed.

**Solution**: Multi-tier hierarchy
```bash
SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3"
```

- L0: Local disk (instant)
- L1: Regional Redis (5-10ms)
- L2: Global S3 bucket (50-200ms)

**Result**: 90%+ hits at L0/L1, L2 as long-term backup.

### 3. Developer Workstation with Cloud Backup

**Problem**: Local disk fills up, don't want to lose cache history.

**Solution**: Disk + cloud storage
```bash
SCCACHE_MULTILEVEL_CHAIN="disk,s3"
SCCACHE_DIR="$HOME/.cache/sccache"
SCCACHE_BUCKET="my-personal-sccache"
SCCACHE_CACHE_SIZE="5G"  # Keep disk small
```

**Result**: Unlimited cloud storage, fast local hits.

## Configuration

### Via Environment Variables

The primary configuration is `SCCACHE_MULTILEVEL_CHAIN`:

```bash
export SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3"
```

**Format**: Comma-separated list of cache backend names
**Order**: Left-to-right is fast-to-slow (L0, L1, L2, ...)
**Valid names**: `disk`, `redis`, `memcached`, `s3`, `gcs`, `azure`, `gha`, `webdav`, `oss`, `cos`

### Write Policy Configuration

Control how sccache handles write failures across cache levels using `SCCACHE_MULTILEVEL_WRITE_POLICY`:

**Available policies**:
- **`ignore`** - Never fail on write errors, log warnings only (most permissive)
- **`l0`** - Fail only if L0 (first level) write fails (default - balances reliability and performance)
- **`all`** - Fail if any read-write level write fails (most strict)

**Note**: Read-only levels are always skipped during writes and never cause failures.

#### Write Policy Examples

**Example 1: Default Behavior (l0 policy)**
```bash
export SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3"
export SCCACHE_MULTILEVEL_WRITE_POLICY="l0"  # or omit, it's the default
```
Compilation succeeds if disk write succeeds. Redis/S3 failures are logged but don't block compilation. Ensures local cache is always populated. **Best for most use cases.**

**Example 2: Best Effort (ignore policy)**
```bash
export SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3"
export SCCACHE_MULTILEVEL_WRITE_POLICY="ignore"
```
Compilation always succeeds, even if all writes fail. Write failures are logged as warnings. **Best for unstable cache backends** where you don't want cache issues blocking builds.

**Example 3: Strict Consistency (all policy)**
```bash
export SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3"
export SCCACHE_MULTILEVEL_WRITE_POLICY="all"
```
Compilation succeeds only if all read-write levels succeed. Any write failure fails the compilation. **Best for critical environments** where cache consistency is mandatory.

#### Read-Only Levels

Any level configured as read-only (e.g., `SCCACHE_LOCAL_RW_MODE=READ_ONLY`) is automatically skipped during writes, regardless of write policy:

```bash
export SCCACHE_MULTILEVEL_CHAIN="disk,redis"
export SCCACHE_MULTILEVEL_WRITE_POLICY="all"
export SCCACHE_LOCAL_RW_MODE="READ_ONLY"  # Disk is read-only
# Compilation succeeds if Redis write succeeds (disk is skipped)
```

### Complete Example

```bash
# Multi-level configuration
export SCCACHE_MULTILEVEL_CHAIN="disk,redis,s3"
export SCCACHE_MULTILEVEL_WRITE_POLICY="l0"  # Default: fail only if disk fails

# Level 0: Disk cache
export SCCACHE_DIR="/var/cache/sccache"
export SCCACHE_CACHE_SIZE="10G"

# Level 1: Redis cache
export SCCACHE_REDIS_ENDPOINT="redis://localhost:6379"
export SCCACHE_REDIS_EXPIRATION="86400"  # 24 hours

# Level 2: S3 cache
export SCCACHE_BUCKET="my-sccache-bucket"
export SCCACHE_REGION="us-east-1"
export SCCACHE_S3_USE_SSL="true"
```

### Via Configuration File

```toml
# ~/.config/sccache/config
[cache.multilevel]
chain = ["disk", "redis", "s3"]
write_policy = "l0"  # Optional: ignore, l0 (default), or all

[cache.disk]
dir = "/var/cache/sccache"
size = 10737418240  # 10GB

[cache.redis]
endpoint = "redis://localhost:6379"
expiration = 86400

[cache.s3]
bucket = "my-sccache-bucket"
endpoint = "s3-us-east-1.amazonaws.com"
use_ssl = true
```

### Single Level (No Multi-Level)

If `SCCACHE_MULTILEVEL_CHAIN` is not set, sccache uses the first configured cache backend (legacy behavior):

```bash
# Just uses disk (backwards compatible)
export SCCACHE_DIR="/tmp/cache"
```

## Best Practices

### 1. Order Levels by Latency (Fastest First)

**Good**: `disk,redis,s3` (10ms → 50ms → 200ms)
**Bad**: `s3,disk,redis` (slow L0 blocks every request)

### 2. Match Cache Sizes to Access Patterns

- **L0 (disk)**: Small, hot data (5-10GB)
- **L1 (redis)**: Team shared, medium (50-100GB)
- **L2 (s3)**: Unlimited, cold storage

## See Also

- [Configuration Options](Configuration.md) - Full config reference
- [Local Cache](Local.md) - Disk cache details
- [Redis Cache](Redis.md) - Redis configuration
- [S3 Cache](S3.md) - S3 configuration
- [Caching](Caching.md) - How cache keys are computed
