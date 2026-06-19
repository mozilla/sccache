#!/bin/bash
set -euo pipefail

# Integration test for the `file_clone` (uncompressed reflink / copy-on-write) disk cache.
# Mirrors test-zstd.sh: build (miss) -> cargo clean -> rebuild (hit) with SCCACHE_FILE_CLONE=true.
#
# FS-guarded: the test asserts a correct miss -> hit round-trip on ANY filesystem. On a CoW
# filesystem (Btrfs/XFS/APFS) restored objects are reflinked; elsewhere they fall back to copies.
# Either way `objects_reflinked + objects_copied_fallback` must be > 0 on the hit (a compressed hit
# would leave both at 0), which proves the uncompressed path actually ran.

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: file_clone (reflink) disk cache"
echo "=========================================="

echo "Copying test crate to writable location..."
cp -r /sccache/tests/test-crate /build/
cd /build/test-crate

export SCCACHE_DIR=/build/file-clone-cache
export SCCACHE_FILE_CLONE=true
TEST_ENV_VAR="test_value_$(date +%s)" && export TEST_ENV_VAR

"$SCCACHE" --stop-server >/dev/null 2>&1 || true
"$SCCACHE" --start-server

echo "Build with file_clone (cache miss)..."
cargo build

echo "Stats after first build:"
"$SCCACHE" --show-stats

echo "Build again (cache hit)..."
cargo clean
cargo build

echo "Stats after second build:"
"$SCCACHE" --show-stats

STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
read_stat() {
    echo "$STATS_JSON" | python3 -c "import sys, json; d=json.load(sys.stdin).get('stats', {}); print($1)"
}

HITS=$(read_stat "d.get('cache_hits', {}).get('counts', {}).get('Rust', 0)")
REFLINKED=$(read_stat "d.get('objects_reflinked', 0)")
COPIED=$(read_stat "d.get('objects_copied_fallback', 0)")

echo "file_clone cache hits (Rust): $HITS"
echo "objects reflinked: $REFLINKED, objects copied (fallback): $COPIED"

if [ "$HITS" -eq 0 ]; then
    echo "ERROR: No cache hits with file_clone"
    exit 1
fi

RESTORED=$((REFLINKED + COPIED))
if [ "$RESTORED" -eq 0 ]; then
    echo "ERROR: file_clone hit restored 0 objects via reflink/copy (uncompressed path did not run)"
    exit 1
fi

if [ "$REFLINKED" -gt 0 ]; then
    echo "Restored via reflink (copy-on-write filesystem detected)."
else
    echo "Restored via copy fallback (filesystem does not support reflinks)."
fi

"$SCCACHE" --stop-server >/dev/null 2>&1 || true

echo "=========================================="
echo "PASS: file_clone disk cache test"
echo "Cache hits: $HITS, reflinked: $REFLINKED, copied: $COPIED"
echo "=========================================="
