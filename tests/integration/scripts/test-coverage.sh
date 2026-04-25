#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="${LLVM_PROFILE_FILE:-coverage-%p-%m.profraw}"
export CARGO_INCREMENTAL=0

echo "=========================================="
echo "Testing: Rust Coverage Instrumentation"
echo "=========================================="

echo "Copying test crate to writable location..."
cp -r /sccache/tests/test-crate /build/

cd /build/test-crate

# Start sccache server
"$SCCACHE" --start-server || true

echo "Build 1: Cache miss expected (with coverage instrumentation)"
TEST_ENV_VAR="test_value_$(date +%s)" && export TEST_ENV_VAR
cargo clean
cargo build

echo "Checking stats after first build..."
"$SCCACHE" --show-stats

echo "Build 2: Cache hit expected"
cargo clean
cargo build

echo "Verifying cache hits..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('cache_hits', {}).get('counts', {}).get('Rust', 0))")

echo "Cache hits: $CACHE_HITS"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: Coverage test"
    exit 0
else
    echo "FAIL: Coverage test - No cache hits detected"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi
