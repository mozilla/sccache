# FileClone Storage

## Overview

The `file_clone` option enables uncompressed cache storage with Copy-on-Write (CoW) filesystem support for faster cache hits.

## Configuration

Add to your sccache config file (e.g., `~/.config/sccache/config`):

```toml
[cache.disk]
file_clone = true
```

Or set via environment variable:

```bash
export SCCACHE_FILE_CLONE=true
```

## How it Works

When `file_clone` is enabled:

1. **Detection**: sccache checks if the cache directory is on a CoW filesystem (APFS on macOS, Btrfs/XFS on Linux)
2. **Uncompressed Storage**: Cache entries are stored as directories with raw files instead of ZIP+zstd
3. **Reflink Extraction**: On cache hit, files are copied using reflink (near-instant on CoW filesystems)
4. **Fallback**: If CoW is not supported, automatically falls back to traditional compressed storage

## Performance Benefits

On CoW filesystems:
- Near-zero copy time for cached files (reflink uses filesystem-level COW)
- Reduced CPU usage (no decompression step)
- Trade-off: Slightly higher disk usage (uncompressed files)

## Compatibility

Works on:
- macOS with APFS
- Linux with Btrfs
- Linux with XFS
- Other filesystems with reflink support

If the filesystem doesn't support reflink, sccache automatically uses compressed storage and logs a warning.

## Implementation Details

- Cache entries stored as directories under `cache/a/b/{hash}/`
- Each directory contains: `{object_name}`, `stdout`, `stderr`
- Original ZIP+zstd format still supported for backwards compatibility
