#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
SRC=/sccache/tests/integration/file-prefix-map

echo "==================================================================="
echo "Testing: basedirs strip -ffile-prefix-map out of the hashed arguments"
echo "==================================================================="

# Two checkouts of the same tree, at different paths.
setup_dirs() {
    rm -rf /build/dir1 /build/dir2
    cp -r "$SRC" /build/dir1
    cp -r "$SRC" /build/dir2
}

# A fresh cache and a fresh server, so each phase starts from zero.
restart_server() {
    "$SCCACHE" --stop-server &>/dev/null || true
    rm -rf /build/sccache
    mkdir -p /build/sccache
    "$SCCACHE" --start-server
}

stat_of() {
    "$SCCACHE" --show-stats --stats-format=json | python3 -c \
        "import sys, json; print(json.load(sys.stdin)['stats']['$1']['counts'].get('C/C++', 0))"
}

check_stats() {
    local want_hits="$1" want_misses="$2" hits misses
    hits=$(stat_of cache_hits)
    misses=$(stat_of cache_misses)
    echo "Cache hits: $hits (want $want_hits), misses: $misses (want $want_misses)"
    if [ "$hits" != "$want_hits" ] || [ "$misses" != "$want_misses" ]; then
        echo "✗ FAIL: $3"
        "$SCCACHE" --show-stats --stats-format=json | python3 -m json.tool
        exit 1
    fi
}

# Compile one checkout.  Every path on the command line is absolute, and
# -ffile-prefix-map names the checkout so that the object file does not depend
# on where it lives: the two calls below must produce identical objects.
compile() {
    local dir="$1" out="$2"
    shift 2
    rm -f "$out"
    "$SCCACHE" g++ -c "$dir/main.cpp" -I"$dir/include" \
        "-ffile-prefix-map=$dir=." -g -o "$out" "$@"
}

echo ""
echo "=========================================="
echo "Test 1: without basedirs, the flag ties the entry to one checkout"
echo "=========================================="
setup_dirs
unset SCCACHE_BASEDIRS
export SCCACHE_DIR=/build/sccache
restart_server

compile /build/dir1 /build/out1.o
compile /build/dir2 /build/out2.o

# The objects are identical - the flag exists precisely for that - so the
# second build is work the cache should have saved, and does not.
cmp /build/out1.o /build/out2.o || {
    echo "✗ FAIL: -ffile-prefix-map did not make the object independent of the path"
    exit 1
}
echo "✓ The two checkouts produce identical objects"
check_stats 0 2 "expected two misses without basedirs, one per checkout"
echo "✓ PASS: no sharing without basedirs, as expected"

echo ""
echo "=========================================="
echo "Test 2: with basedirs, the second checkout hits"
echo "=========================================="
setup_dirs
export SCCACHE_BASEDIRS="/build/dir1:/build/dir2"
restart_server

compile /build/dir1 /build/out1.o
check_stats 0 1 "expected a miss on the first checkout"

compile /build/dir2 /build/out2.o
check_stats 1 1 "expected the second checkout to hit the first checkout's entry"

cmp /build/out1.o /build/out2.o || {
    echo "✗ FAIL: the cached object differs from the one the compiler produced"
    exit 1
}
echo "✓ PASS: basedirs strip -ffile-prefix-map from the hashed arguments"

echo ""
echo "=========================================="
echo "Test 3: a path the compiler bakes in verbatim still counts"
echo "=========================================="
setup_dirs
restart_server

# -DROOT="<path>" is not a pathname position: the path ends up in the object
# file as it is written, so the two checkouts differ and must not share.
compile /build/dir1 /build/out1.o '-DROOT="/build/dir1"'
check_stats 0 1 "expected a miss on the first checkout"

compile /build/dir2 /build/out2.o '-DROOT="/build/dir2"'
check_stats 0 2 "expected a miss: -DROOT is baked into the object verbatim"

if cmp -s /build/out1.o /build/out2.o; then
    echo "✗ FAIL: the objects are identical, so -DROOT is not the thing under test"
    exit 1
fi
echo "✓ PASS: a basedir outside a pathname position is left alone"

"$SCCACHE" --stop-server &>/dev/null || true

echo ""
echo "=========================================="
echo "All -ffile-prefix-map tests completed successfully!"
echo "=========================================="
