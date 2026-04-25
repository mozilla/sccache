#!/bin/bash
set -euo pipefail

# XFAIL: cmake 4.x generates arguments that trigger sccache's @ response file
# rejection in gcc.rs:349. This test tracks the issue and captures the actual
# compiler commands for debugging.

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: CMake 4.x C++20 Modules (XFAIL)"
echo "=========================================="

echo "cmake version: $(cmake --version | head -1)"
echo "clang version: $(clang++ --version | head -1)"

# Copy cmake-modules project to writable location
cp -r /sccache/tests/integration/cmake-modules /build/cmake-modules

# Start sccache server
"$SCCACHE" --start-server || true

echo ""
echo "Build 1: Capture compiler commands"
cd /build/cmake-modules
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_COMPILER_LAUNCHER="$SCCACHE" \
    -DCMAKE_CXX_COMPILER_LAUNCHER="$SCCACHE"

echo ""
echo "=== Ninja build rules (grep for @ in commands) ==="
grep '@' build/build.ninja || echo "(no @ found in build.ninja)"

echo ""
echo "=== Full compiler commands (ninja -v) ==="
cmake --build build -- -v 2>&1 | cat

echo ""
echo "=== sccache stats ==="
"$SCCACHE" --show-stats

STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
NOT_CACHED=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('not_cached', {}).get('@', 0))")
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

echo ""
echo "Cache hits: $CACHE_HITS"
echo "Non-cacheable @: $NOT_CACHED"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "XPASS: CMake 4.x C++20 modules now cacheable! Remove XFAIL status."
    exit 1
fi

if [ "$NOT_CACHED" -gt 0 ]; then
    echo "XFAIL: cmake 4.x @ issue reproduced (expected failure)"
    exit 0
fi

echo "FAIL: Unexpected failure"
echo "$STATS_JSON" | python3 -m json.tool
exit 1
