#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
TEST_FILE="/sccache/tests/test_clang_multicall.c"

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
$ASM -c /sccache/tests/integration/test_intel_asm.s

DEPFILE="/tmp/test.o.d"
rm -f $DEPFILE
$ASM -c /sccache/tests/integration/test_intel_asm.s -MD -MF $DEPFILE
test ! -f $DEPFILE || { echo "ERROR: Dependency file found"; exit 1; }

echo "Test 4: Test ASM with preprocessor"
$ASM -c /sccache/tests/integration/test_intel_asm_to_preproc.S

$ASM -c /sccache/tests/integration/test_intel_asm_to_preproc.S -MD -MF $DEPFILE
test -f $DEPFILE || { echo "ERROR: Dependency file not found"; exit 1; }
rm -f $DEPFILE

echo "Test 5: Test preprocessed C++ file with dependency arguments (cache miss)"
$CXX -c /sccache/tests/integration/test_preprocessed.ii -o /tmp/test.o -MD -MF $DEPFILE
test -f /tmp/test.o || { echo "ERROR: No compiler output found"; exit 1; }
test ! -f $DEPFILE || { echo "ERROR: Dependency file found"; exit 1; }

echo "Test 6: Test preprocessed C++ file with dependency arguments (cache hit expected)"
$CXX -c /sccache/tests/integration/test_preprocessed.ii -o /tmp/test.o -MD -MF $DEPFILE
test -f /tmp/test.o || { echo "ERROR: No compiler output found"; exit 1; }
test ! -f $DEPFILE || { echo "ERROR: Dependency file found"; exit 1; }

echo "Test 7: Test ASM with coverage flags (no .gcno is emitted)"
# Assembly accepts the coverage flags but never emits a .gcno note file, so
# sccache has to treat that output as optional -- otherwise storing the result
# fails with "failed to zip up compiler outputs" (see issue #2275).
cache_hits() {
    "$SCCACHE" --show-stats --stats-format=json | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('$1', 0))"
}

for SRC in test_intel_asm.s test_intel_asm_to_preproc.S; do
    for COV in --coverage -ftest-coverage; do
        echo "Compiling $SRC with $COV"
        HITS_BEFORE=$(cache_hits Assembler)

        rm -f /tmp/test_cov.o /tmp/test_cov.gcno
        $ASM $COV -c "/sccache/tests/integration/$SRC" -o /tmp/test_cov.o
        test -f /tmp/test_cov.o || { echo "ERROR: No compiler output found"; exit 1; }
        test ! -f /tmp/test_cov.gcno || { echo "ERROR: Note file found for assembly"; exit 1; }

        rm -f /tmp/test_cov.o
        $ASM $COV -c "/sccache/tests/integration/$SRC" -o /tmp/test_cov.o
        test -f /tmp/test_cov.o || { echo "ERROR: No compiler output found"; exit 1; }

        HITS_AFTER=$(cache_hits Assembler)
        if [ "$HITS_AFTER" -le "$HITS_BEFORE" ]; then
            echo "ERROR: $SRC with $COV was not cached ($HITS_BEFORE -> $HITS_AFTER)"
            "$SCCACHE" --show-stats
            exit 1
        fi
    done
done

echo "Test 8: Test C++ with coverage flags (the .gcno is required and cached)"
HITS_BEFORE=$(cache_hits C/C++)

rm -f /tmp/test_cov.o /tmp/test_cov.gcno
$CXX --coverage -c "$TEST_FILE" -o /tmp/test_cov.o
test -f /tmp/test_cov.o || { echo "ERROR: No compiler output found"; exit 1; }
test -f /tmp/test_cov.gcno || { echo "ERROR: No note file found"; exit 1; }

rm -f /tmp/test_cov.o /tmp/test_cov.gcno
$CXX --coverage -c "$TEST_FILE" -o /tmp/test_cov.o
test -f /tmp/test_cov.o || { echo "ERROR: No compiler output found"; exit 1; }
test -f /tmp/test_cov.gcno || { echo "ERROR: Note file not restored from cache"; exit 1; }

HITS_AFTER=$(cache_hits C/C++)
if [ "$HITS_AFTER" -le "$HITS_BEFORE" ]; then
    echo "ERROR: $TEST_FILE with --coverage was not cached ($HITS_BEFORE -> $HITS_AFTER)"
    "$SCCACHE" --show-stats
    exit 1
fi
