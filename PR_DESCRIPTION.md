# Fix panic on edge-case file paths in LRU disk cache init

## Problem

`LruDiskCache::init()` in `src/lru_disk_cache/mod.rs` calls `.expect("Bad path?")` on `file.file_name()`, which panics if the path ends in `..` or is otherwise unusual. A build cache tool should handle unexpected file system states gracefully rather than crashing.

## Root Cause

`Path::file_name()` returns `None` when the path terminates in `..` or consists solely of a root or prefix. The `.expect()` call converts this into a panic. While uncommon, symlinks or filesystem corruption could produce such paths in the cache directory.

## Fix

Replaced `.expect("Bad path?").starts_with(TEMPFILE_PREFIX)` with `.map_or(false, |name| name.starts_with(TEMPFILE_PREFIX))`. Paths without a valid file name component are now treated as non-temporary files (skipping the cleanup branch) rather than crashing.

## Testing

- Create a cache directory containing a path component ending in `..`.
- Previously: sccache panics during cache init. Now: the entry is handled gracefully.
- Normal cache operation should be unaffected.

## Impact

Affects sccache users whose cache directories may contain unusual file paths. A panic in cache init prevents the entire build cache from working.
