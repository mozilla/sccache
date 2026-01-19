#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: Autotools Integration"
echo "=========================================="

# Copy autotools project to writable location
echo "Copying Autotools project..."
cp -r /workspace/tests/integration/autotools /build/

# Start sccache server
"$SCCACHE" --start-server || true

echo "Build 1: Cache miss expected"
cd /build/autotools
autoreconf || true
automake --add-missing
./configure CXX="$SCCACHE g++"
make

echo "Checking stats after first build..."
"$SCCACHE" --show-stats

echo "Build 2: Cache hit expected"
make distclean
./configure CXX="$SCCACHE g++"
make

echo "Verifying cache hits..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

echo "Cache hits: $CACHE_HITS"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: Autotools test"
    exit 0
else
    echo "FAIL: Autotools test - No cache hits detected"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi
