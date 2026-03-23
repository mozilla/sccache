#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: CMake C++20 Modules Integration"
echo "=========================================="

# Copy cmake-modules project to writable location
cp -r /sccache/tests/integration/cmake-modules /build/cmake-modules

# Start sccache server
"$SCCACHE" --start-server || true

echo "Build 1: Cache miss expected"
cd /build/cmake-modules
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_COMPILER_LAUNCHER="$SCCACHE" \
    -DCMAKE_CXX_COMPILER_LAUNCHER="$SCCACHE"
cmake --build build

echo "Checking stats after first build..."
"$SCCACHE" --show-stats

echo ""
echo "Build 2: Cache hit expected"
cd /build/cmake-modules
rm -rf build
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_COMPILER_LAUNCHER="$SCCACHE" \
    -DCMAKE_CXX_COMPILER_LAUNCHER="$SCCACHE"
cmake --build build

echo "Verifying cache hits..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

echo "Cache hits: $CACHE_HITS"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: CMake C++20 modules test"
    exit 0
else
    echo "FAIL: CMake C++20 modules test - No cache hits detected"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi
