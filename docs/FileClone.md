# File clone (reflink / copy-on-write) disk cache

`file_clone` is an **opt-in** mode for sccache's **local disk cache** that stores
cache entries **uncompressed** and restores them using filesystem **reflinks**
(copy-on-write, "CoW"):

* `FICLONE` on Linux (Btrfs, XFS with reflink support, bcachefs, ...),
* `clonefile` on macOS (APFS),
* block cloning on Windows (ReFS / Dev Drives).

On a copy-on-write filesystem a reflink makes the new file share the source
file's on-disk blocks until one of them is modified. This means:

* **Cache writes are near-free** – when a compile misses, sccache reflinks the
  freshly produced object files straight into the cache instead of reading and
  zstd-compressing them. The cache entry shares blocks with your build tree.
* **Cache hits are near-instant** – on a hit, sccache reflinks the cached files
  back out to your build tree. No decompression, no data copy.
* **The cache uses almost no extra disk** – because the cache entry, the original
  build output, and every future restoration all share the same physical extents
  until something modifies them.

This implements the idea from issues
[#1053](https://github.com/mozilla/sccache/issues/1053) and
[#1174](https://github.com/mozilla/sccache/issues/1174) and PR
[#2640](https://github.com/mozilla/sccache/pull/2640) (credit to @quake), reusing
its good ideas (opt-in config, marker-based directory entries, mixed-format
reads) while fixing the bugs found in review.

The default remains the compressed cache; nothing changes unless you opt in.

## Enabling it

Config file (`[cache.disk]`):

```toml
[cache.disk]
file_clone = true
```

Or via environment variable:

```bash
export SCCACHE_FILE_CLONE=true
```

Restart the sccache server after changing this (`sccache --stop-server`).

## ⚠️ Same copy-on-write filesystem requirement

To get the disk-saving and speed benefits, **both** of these must live on the
**same copy-on-write filesystem**:

1. the sccache cache directory (`SCCACHE_DIR` / `[cache.disk] dir`), and
2. the directory where the compiler writes its output (your build tree).

Reflinks cannot span filesystems. If the cache and the build tree are on
different filesystems, or on a filesystem without reflink support
(ext4, tmpfs, overlayfs, NTFS, ...), sccache transparently falls back to a plain
byte copy. In that case:

* `file_clone` still avoids compression/decompression work, **but**
* restored artifacts are full copies (normal disk usage), and
* the cache stores entries **uncompressed**, so it will be **larger** on disk
  than the default compressed cache.

So on a non-CoW filesystem the default (compressed) cache is usually the better
choice. `file_clone` is for when your cache and build trees share a CoW volume.

## Verifying that reflinks are happening

`sccache --show-stats` reports two counters:

```
Objects restored by reflink            123
Objects restored by copy                 0
```

* **Objects restored by reflink** – objects materialised by sharing blocks
  (the fast/cheap CoW path). A non-zero value confirms reflinks are working.
* **Objects restored by copy** – objects that fell back to a byte copy because
  reflinking wasn't possible (different filesystem, no CoW support, ...).

The same numbers are available as `objects_reflinked` and
`objects_copied_fallback` in `sccache --show-stats --stats-format=json`.

At server start, if `file_clone` is enabled but the cache directory's filesystem
does not support reflinks, sccache logs a warning so you know you'll only get the
copy-fallback behaviour.

To *see* the block sharing on a CoW filesystem, note that plain `du` does **not**
reflect reflink/extent sharing (a reflinked file still reports its full
`st_blocks`, and the sharing is between `target/` and the *cache* directory, which
`du target/` can't see). On btrfs, use [`compsize`](https://github.com/kilobyte/compsize),
which reports the *actual* on-disk usage with shared extents counted once:

```bash
# Measure the cache and the restored build tree TOGETHER. "Disk Usage" counts each
# physical extent once, so when the restore reflinks the cache it stays near one copy
# while "Referenced" (the logical size) is ~two copies.
compsize "$SCCACHE_DIR" target/

# The cleanest reflink proof is the *marginal* disk the restore adds: the on-disk
# usage of (cache + restore) minus that of the cache alone is ~0 when the restore
# reflinks, and ~the full restored size when it falls back to copying. This also
# cancels out any btrfs transparent compression, which affects both terms equally.
compsize "$SCCACHE_DIR"            # cache only
compsize "$SCCACHE_DIR" target/    # cache + restored artifacts
```

The bundled `scripts/bench-file-clone.sh` automates this `compsize` comparison
across one or more projects and prints a markdown table.

## Why reflinks are safe (unlike hardlinks)

A natural alternative would be to hardlink cache entries into the build tree, but
that is unsafe: a hardlink and the cache entry are the *same* inode, so if a later
build step modifies the file **in place** (for example `strip`, `install -s`, or
an incremental linker), it corrupts the cached copy too.

Reflinks do not have this problem. A reflink is copy-on-write: the cache entry and
the restored file start out sharing blocks, but the moment either one is written
to, the filesystem transparently forks the modified blocks. The cache copy is
never affected. This is why `file_clone` is the safe subset of the hardlink idea
from #1053 / #1174 and needs no read-only juggling.

## On-disk format

* **Compressed entries** (the default) are unchanged: a single file at
  `{cache}/{c0}/{c1}/{key}`. Enabling or disabling `file_clone` does **not**
  invalidate an existing compressed cache.
* **Uncompressed (`file_clone`) entries** are a directory at the same key path,
  `{cache}/{c0}/{c1}/{key}/`, containing an `objects/` subdirectory with one plain
  file per cached object (`objects/obj`, `objects/d`, ...), optional
  `stdout`/`stderr` files, and a marker file `.sccache_dir_entry`. Objects are
  namespaced under `objects/` so an object key can never collide with the reserved
  `stdout`/`stderr`/marker names. The marker file also stores a small manifest of
  each object's original output mode.

Cache object files (and `stdout`/`stderr`/marker) are written `0600`, and the
entry and cache-root directories are kept user-private, matching the compressed
path (whose blobs are `0600` temp files). The *restored build output* still gets
its correct original mode, taken from the manifest — not from the private cache
copy. See "Security" below.

Both formats coexist, so the two modes can be switched back and forth without
wiping the cache; lookups check for a directory entry first and fall back to the
compressed file. The first compressed write to a key that previously held a
directory entry (i.e. after turning `file_clone` *off*) transparently removes the
stale directory before writing the compressed file. Entries are written into a
temporary directory and atomically renamed into place, so concurrent builds never
observe a half-written entry.

The preprocessor cache (a separate cache nested under the main cache directory) is
never stored as directory entries and is left completely untouched by
`file_clone`.

## Security

`file_clone` cache objects are stored uncompressed, so on Unix they are written
`0600` and the directories holding them are created `0700` regardless of the
process umask: the cache root, each entry directory, its `objects/` subdirectory,
and the immediate `{c0}/{c1}` parent. Because POSIX unlink/rename is governed by
the *parent directory's* write permission, the `0700` directories — not just the
`0600` files — are what prevent another user on a shared host from reading,
unlinking or replacing cached objects (cache poisoning → arbitrary code).

When `file_clone` is enabled on a cache directory that is currently
group/other-accessible, sccache tightens the root to `0700` and logs a warning,
since this can lock out a genuinely shared cache. Keep the cache directory
user-private; do **not** point `SCCACHE_DIR` at a world/group-writable location
when using `file_clone` (the compressed cache already stores its blobs `0600`).
Cache-entry sources are opened without following symlinks on Linux as
defence-in-depth.

## Caveats / limitations

* **Multi-level caches**: `file_clone` only affects a *single-level local disk*
  cache. A disk level used inside a `[cache.multilevel]` chain always stores
  **compressed** entries (writes go through `put_raw`); the flag is not honoured
  there. If a stray uncompressed entry is ever encountered at a multilevel disk
  level, its `get_raw` returns `None`, so it is counted as a hit but never used as
  a backfill source. Reflink-based storage at a multilevel L1 is out of scope.
* **Remote backends** (S3, Redis, GCS, ...) are unaffected; reflink is an
  inherently local, same-filesystem concept.
* On a non-CoW filesystem the uncompressed cache is larger than the compressed
  one; prefer the default there.
* `file_clone` does not change cache keys, so it is safe to toggle on and off
  (mixed compressed/uncompressed entries coexist).

## Benchmarking

See `scripts/bench-file-clone.sh` for a self-contained tool that compares cold
builds, warm (compressed) rebuilds and warm (`file_clone`) rebuilds, and reports
cache sizes, restored-artifact disk usage, and reflink/copy counts. Run it with:

```bash
# Offline C project target (no network):
scripts/bench-file-clone.sh

# Also benchmark real cargo projects (needs network):
BENCH_REPOS="ripgrep=https://github.com/BurntSushi/ripgrep \
             fd=https://github.com/sharkdp/fd \
             bat=https://github.com/sharkdp/bat" \
  scripts/bench-file-clone.sh
```

It is a manual performance tool and is intentionally **not** wired into CI.

### Example results

Measured on a Btrfs (copy-on-write) filesystem with a debug `sccache`. Times in
seconds; sizes in KiB. `cache+restore on disk` is the [`compsize`](https://github.com/kilobyte/compsize)
disk usage of the file_clone cache and the restored artifacts together (shared extents
counted once); `restore marginal disk` is that minus the cache's own on-disk usage — the
NEW disk a restore consumes, which is ~0 when the artifacts reflink the cache. `reflink/copy`
is `objects_reflinked`/`objects_copied_fallback`.

| target  | cold  | warm (compressed) | warm (file_clone) | compressed cache | file_clone cache | restored (logical) | cache+restore on disk | restore marginal disk | reflink/copy |
|---------|------:|------------------:|------------------:|-----------------:|-----------------:|-------------------:|----------------------:|----------------------:|:-----------:|
| local-c |  2.33 |  0.23 |  0.22 |   2400 |   8160 |   6899 |   2069 |      0 | 120/0 |
| ripgrep |  6.77 |  4.76 |  4.33 |  29404 | 111320 | 349005 | 152064 | 118329 |  75/0 |
| fd      | 38.51 | 15.54 | 14.58 |  91044 | 356280 | 350839 | 164360 |  59556 | 434/0 |
| bat     | 12.35 | 10.63 |  7.81 | 144016 | 514384 | 925313 | 317167 | 155235 | 758/0 |

For comparison, the *compressed* cache's `restore marginal disk` (the same compsize
measurement, run against the compressed cache) is much higher — local-c 1920, ripgrep
152056, fd 118952, bat 313963 KiB — because a compressed-cache restore writes fresh,
unshared blocks. The gap is the disk the reflink sharing saves on every restore.

Notes: every object was reflinked (`copy = 0`) on this CoW filesystem; `file_clone`
warm rebuilds were as fast as or faster than the compressed cache (no decompression).
The compressed cache is smaller on disk (the trade-off). The offline `local-c` target —
a pure-compilation workload with no link/bookkeeping step — restores with `restore
marginal disk = 0`, i.e. the restored artifacts share **all** their blocks with the
cache. For the cargo targets the small marginal remainder is the freshly linked binary
and cargo's fingerprint/incremental files, which sccache does not cache.
