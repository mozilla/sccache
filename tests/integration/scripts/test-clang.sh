#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
TEST_FILE="/workspace/tests/test_clang_multicall.c"

echo "=========================================="
echo "Testing: Clang Compiler"
echo "=========================================="

# Start sccache server
"$SCCACHE" --start-server || true

echo "Test 1: Compile C++ file (cache miss)"
rm -f /tmp/test.o
CXX="$SCCACHE clang++"
$CXX -c "$TEST_FILE" -o /tmp/test.o
test -f /tmp/test.o || { echo "ERROR: No compiler output found"; exit 1; }

echo "Checking stats after first build..."
"$SCCACHE" --show-stats
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)

echo "Test 2: Compile again (cache hit expected)"
rm -f /tmp/test.o
$CXX -c "$TEST_FILE" -o /tmp/test.o
test -f /tmp/test.o || { echo "ERROR: No compiler output found"; exit 1; }

echo "Verifying cache hits..."
STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

echo "Cache hits: $CACHE_HITS"

if [ "$CACHE_HITS" -gt 0 ]; then
    echo "PASS: Clang test"
else
    echo "FAIL: Clang test - No cache hits detected"
    echo "$STATS_JSON" | python3 -m json.tool
    exit 1
fi

echo "Test 3: Test ASM"
ASM="$SCCACHE clang++"
$ASM -c /workspace/tests/integration/test_intel_asm.s

echo "Test 4: Test ASM with preprocessor"
$ASM -c /workspace/tests/integration/test_intel_asm_to_preproc.S
