#!/bin/bash
set -euo pipefail

# Regression test for mozilla/sccache#2650 — CMake 4.3+ writes quoted modmap
# content (`-fmodule-file="key=value"`) into `@<file>.modmap` arguments on
# clang++ command lines. Before the fix, sccache's response-file expander
# (gcc.rs `ExpandIncludeFile`) bailed on any quoted content and the raw
# `@file` arg surfaced as `Non-cacheable: @`. After the fix, the response
# file is tokenised via the MSVC `CommandLineToArgvW`-style splitter and the
# inlined `-fmodule-file=…` reaches the C++20 modules parser like on cmake
# 3.31/4.1/4.2. This test asserts the success path; any non-zero @ counter
# is treated as a regression.

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

if [ "$NOT_CACHED" -gt 0 ]; then
    echo "FAIL (regression): sccache reported $NOT_CACHED non-cacheable compile(s)"
    echo "                    due to '@' response files — see mozilla/sccache#2650."
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi

# Build 1 was a cold run, so we expect cache_misses, not hits. Re-run the
# build against a clean build dir while keeping the on-disk cache populated
# so we can also assert the warm-path hit rate.
echo ""
echo "Build 2: warm pass (build dir wiped, sccache disk cache persists)"
rm -rf build
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_COMPILER_LAUNCHER="$SCCACHE" \
    -DCMAKE_CXX_COMPILER_LAUNCHER="$SCCACHE"
cmake --build build

STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
WARM_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")
WARM_NOT_CACHED=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('stats', {}).get('not_cached', {}).get('@', 0))")

echo ""
echo "Warm cache hits: $WARM_HITS"
echo "Warm non-cacheable @: $WARM_NOT_CACHED"

if [ "$WARM_NOT_CACHED" -gt 0 ]; then
    echo "FAIL (regression): warm pass produced $WARM_NOT_CACHED '@' bailout(s)"
    exit 1
fi

if [ "$WARM_HITS" -lt 2 ]; then
    echo "FAIL: warm pass expected at least 2 cache hits, got $WARM_HITS"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi

echo "PASS: CMake 4.x C++20 modules cache correctly (cold misses + warm hits)."
exit 0
