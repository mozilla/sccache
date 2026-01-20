#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: CMake Integration"
echo "=========================================="

# Copy cmake project to writable location
echo "Copying CMake project..."
cp -r /sccache/tests/integration/cmake /build/

# Start sccache server
"$SCCACHE" --start-server || true

echo "Build 1: Cache miss expected"
cd /build/cmake
mkdir -p build
cd build
cmake -DCMAKE_C_COMPILER_LAUNCHER="$SCCACHE" \
      -DCMAKE_CXX_COMPILER_LAUNCHER="$SCCACHE" \
      ..
make

echo "Checking stats after first build..."
"$SCCACHE" --show-stats

echo "Build 2: Cache hit expected"
cd /build/cmake
rm -rf build
mkdir build
cd build
cmake -DCMAKE_C_COMPILER_LAUNCHER="$SCCACHE" \
      -DCMAKE_CXX_COMPILER_LAUNCHER="$SCCACHE" \
      ..
make

echo "Verifying cache hits..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

echo "Cache hits: $CACHE_HITS"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: CMake test"
    exit 0
else
    echo "FAIL: CMake test - No cache hits detected"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi
