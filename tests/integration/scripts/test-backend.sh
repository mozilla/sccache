#!/bin/bash
set -euo pipefail

TEST_NAME="${TEST_NAME:-unknown}"
BACKEND_CHECK="${BACKEND_CHECK:-}"
SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: $TEST_NAME"
echo "=========================================="

echo "Copying test crate to writable location..."
cp -r /workspace/tests/test-crate /build/

cd /build/test-crate

echo "Build 1: Cache miss expected"
TEST_ENV_VAR="test_value_$(date +%s)" && export TEST_ENV_VAR
cargo clean
cargo build

# Use pythong to parse JSON output, installing jq each time is slow and unreliable
# The difference python vs jq is 55 seconds vs 90 seconds
echo "Checking stats after first build..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
if [ -n "$BACKEND_CHECK" ]; then
    CACHE_LOCATION=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cache_location', ''))")
    if ! echo "$CACHE_LOCATION" | grep -qi "$BACKEND_CHECK"; then
        echo "ERROR: Backend '$BACKEND_CHECK' not found in cache_location: $CACHE_LOCATION"
        echo "$STATS_JSON" | python3 -m json.tool
        exit 1
    fi
    echo "Backend detected: $CACHE_LOCATION"
fi

echo "Build 2: Cache hit expected"
cargo clean
cargo build

echo "Verifying cache hits..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('cache_hits', {}).get('counts', {}).get('Rust', 0))")

echo "Cache hits: $CACHE_HITS"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: $TEST_NAME"
    exit 0
else
    echo "FAIL: $TEST_NAME - No cache hits detected"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi
