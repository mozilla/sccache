#!/bin/bash
set -euo pipefail

# cmake 4.x drives C++20 modules through @response files (e.g. the generated
# `.modmap` files). These used to be rejected by sccache's @ response-file
# handling in gcc.rs, making such builds non-cacheable. Now that response files
# are expanded and spliced into the argument list, these builds are cacheable.

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "=========================================="
echo "Testing: CMake 4.x C++20 Modules"
echo "=========================================="

echo "cmake version: $(cmake --version | head -1)"
echo "clang version: $(clang++ --version | head -1)"

# Copy cmake-modules project to writable location
cp -r /sccache/tests/integration/cmake-modules /build/cmake-modules

# Start sccache server
"$SCCACHE" --start-server || true

echo ""
echo "Build 1: Cache miss expected"
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
cmake --build build | cat  # unfold output

echo ""
echo "=== sccache stats ==="
"$SCCACHE" --show-stats

STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
NOT_CACHED=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('not_cached', {}).get('@', 0))")
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

echo ""
echo "Cache hits: $CACHE_HITS"
echo "Non-cacheable @: $NOT_CACHED"

if [ "$NOT_CACHED" -gt 0 ]; then
    echo "FAIL: cmake 4.x @ response files were rejected as non-cacheable"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: CMake 4.x C++20 modules test"
    exit 0
fi

echo "FAIL: CMake 4.x C++20 modules test - No cache hits detected"
echo "$STATS_JSON" | python3 -m json.tool
exit 1
