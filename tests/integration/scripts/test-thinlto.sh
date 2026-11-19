#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
PROJECT=/build/thinlto
CXX_FLAGS="-O2 -flto=thin"
LAUNCHER=$SCCACHE

echo "=========================================="
echo "Testing: ThinLTO backend jobs (lld DTLTO)"
echo "=========================================="

for dir in /build/thinlto /build/dir1 /build/dir2; do
    cp -r /sccache/tests/integration/thinlto "$dir"
done

"$SCCACHE" --start-server || true

# lld hands every ThinLTO backend job to the distributor, which runs it as
# `sccache clang -c <module> -fthinlto-index=<index> -o <native object>`.
# lld 21 has no --thinlto-remote-compiler-prepend-arg, so the distributor
# puts sccache in front.
# The library is a thin archive: lld would extract members of a regular one
# under per-link names, which end up in the indexes.
build() {
    local factor=$1
    rm -rf "$PROJECT/build"
    cmake -S "$PROJECT" -B "$PROJECT/build" \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_CXX_COMPILER_LAUNCHER="$LAUNCHER" \
        -DCMAKE_CXX_FLAGS="$CXX_FLAGS" \
        -DCMAKE_AR="$(command -v llvm-ar)" \
        -DCMAKE_CXX_ARCHIVE_CREATE="<CMAKE_AR> qcT <TARGET> <LINK_FLAGS> <OBJECTS>" \
        -DCMAKE_CXX_ARCHIVE_APPEND="<CMAKE_AR> qT <TARGET> <LINK_FLAGS> <OBJECTS>" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld \
            -fthinlto-distributor=$(command -v python3) \
            -Xthinlto-distributor=$PROJECT/distributor.py \
            -Xthinlto-distributor=$SCCACHE" \
        -DHELPER_FACTOR="$factor" >/dev/null
    "$SCCACHE" --zero-stats >/dev/null
    cmake --build "$PROJECT/build" -- VERBOSE=1
}

# stat <cache_hits|cache_misses> <language>
stat() {
    "$SCCACHE" --show-stats --stats-format=json |
        python3 -c "import sys, json; print(json.load(sys.stdin)['stats']['$1']['counts'].get('$2', 0))"
}

check() {
    local what=$1 expected=$2 actual
    actual=$(stat "${what%% *}" "${what#* }")
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: expected $expected $what, got $actual"
        "$SCCACHE" --show-stats
        exit 1
    fi
}

check_output() {
    local actual
    actual=$("$PROJECT/build/app")
    if [ "$actual" != "$1" ]; then
        echo "FAIL: app printed $actual, expected $1"
        exit 1
    fi
}

echo "Build 1: everything misses"
build 3
check "cache_misses LLVM IR" 2
check "cache_hits LLVM IR" 0
check_output 3

echo "Build 2: from scratch, everything hits"
build 3
check "cache_hits C/C++" 2
check "cache_hits LLVM IR" 2
check "cache_misses LLVM IR" 0
check_output 3

echo "Build 3: only helper.cpp changes, but main imports from it"
build 5
check "cache_hits C/C++" 1
check "cache_misses LLVM IR" 2
check_output 5

echo "Build 4: back to the first build, everything hits"
build 3
check "cache_hits LLVM IR" 2
check "cache_misses LLVM IR" 0
check_output 3

echo "Basedirs: the same project in two directories, with debug info"
"$SCCACHE" --stop-server >/dev/null 2>&1 || true
rm -rf "$SCCACHE_DIR"
SCCACHE_BASEDIRS=/build/dir1:/build/dir2 "$SCCACHE" --start-server
CXX_FLAGS="-O2 -g -flto=thin"

echo "Build 5: first directory, everything misses"
PROJECT=/build/dir1 build 3
check "cache_misses LLVM IR" 2

echo "Build 6: second directory, everything hits"
# The compile step hits and returns the bitcode built in the first directory,
# so the backend jobs see the same modules and indexes.
PROJECT=/build/dir2 build 3
check "cache_hits C/C++" 2
check "cache_hits LLVM IR" 2
check "cache_misses LLVM IR" 0
PROJECT=/build/dir2 check_output 3

echo "Build 7: second directory, bitcode compiled without sccache"
# The bitcode records the absolute source path as the module's source file
# name, even with -ffile-prefix-map, so it differs between the directories and
# the backend jobs miss.
CXX_FLAGS="$CXX_FLAGS -ffile-prefix-map=/build/dir2=."
PROJECT=/build/dir2 LAUNCHER="" build 3
check "cache_hits LLVM IR" 0
check "cache_misses LLVM IR" 2
PROJECT=/build/dir2 check_output 3

echo "PASS: ThinLTO test"
