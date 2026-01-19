#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: ZSTD Compression Levels"
echo "=========================================="

echo "Copying test crate to writable location..."
cp -r /workspace/tests/test-crate /build/

cd /build/test-crate

echo "=========================================="
echo "Test 1: Default compression level"
echo "=========================================="

TEST_ENV_VAR="test_value_$(date +%s)" && export TEST_ENV_VAR
export SCCACHE_DIR=/build/zstd-level/default
"$SCCACHE" --start-server || true

echo "Build with default compression (cache miss)..."
cargo build

echo "Stats after first build:"
"$SCCACHE" --show-stats

echo "Build again (cache hit)..."
cargo clean
cargo build

echo "Stats after second build:"
"$SCCACHE" --show-stats

STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
DEFAULT_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('cache_hits', {}).get('counts', {}).get('Rust', 0))")
echo "Default compression cache hits: $DEFAULT_HITS"

if [ "$DEFAULT_HITS" -eq 0 ]; then
    echo "ERROR: No cache hits with default compression"
    exit 1
fi

echo "=========================================="
echo "Test 2: Compression level 10"
echo "=========================================="

# Stop server and change to level 10
"$SCCACHE" --stop-server > /dev/null 2>&1 || true
sleep 1

export SCCACHE_DIR=/build/zstd-level/10
export SCCACHE_CACHE_ZSTD_LEVEL=10
"$SCCACHE" --start-server || true

cargo clean

echo "Build with compression level 10 (cache miss)..."
cargo build

echo "Stats after first build:"
"$SCCACHE" --show-stats

echo "Build again (cache hit)..."
cargo clean
cargo build

echo "Stats after second build:"
"$SCCACHE" --show-stats

STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
LV10_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('cache_hits', {}).get('counts', {}).get('Rust', 0))")
echo "Level 10 compression cache hits: $LV10_HITS"

if [ "$LV10_HITS" -eq 0 ]; then
    echo "ERROR: No cache hits with compression level 10"
    exit 1
fi

echo "=========================================="
echo "PASS: ZSTD compression levels test"
echo "Default compression hits: $DEFAULT_HITS"
echo "Level 10 compression hits: $LV10_HITS"
echo "=========================================="
