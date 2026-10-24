#!/usr/bin/env bash
#
# Compare two sccache binaries (typically a plain release build and the PGO one
# from scripts/build-pgo.sh) with hyperfine, on the paths that dominate real
# builds: C cache hits in preprocessor and direct mode, and a fully cached
# cargo build.
#
# Each binary gets its own server, port and cache directory, warmed up before
# measuring, so only the client and server code differ between the two runs.
#
# Usage:
#   scripts/bench-pgo.sh BASELINE CANDIDATE [--runs N]

set -euo pipefail

if [ $# -lt 2 ]; then
    sed -n '3,12p' "${BASH_SOURCE[0]}"
    exit 2
fi
BASELINE="$1"
CANDIDATE="$2"
shift 2
RUNS=50
while [ $# -gt 0 ]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v hyperfine >/dev/null || { echo "hyperfine not found on PATH" >&2; exit 1; }
# hyperfine >= 2 takes a per-command --env. Prefixing the command with `env`
# instead would double the time of a cache hit, so older versions go through
# their default shell, which costs less.
HYPERFINE_ENV=0
if hyperfine --help | grep -q -- '--env <'; then HYPERFINE_ENV=1; fi
for b in "$BASELINE" "$CANDIDATE"; do
    [ -x "$b" ] || { echo "not an executable: ${b}" >&2; exit 1; }
done
CC_BIN="$(command -v "${CC:-cc}" || command -v gcc || command -v clang || true)"
[ -n "$CC_BIN" ] || { echo "no C compiler found" >&2; exit 1; }
CXX_BIN="$(command -v "${CXX:-c++}" || command -v g++ || command -v clang++ || true)"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"

# Isolated from whatever sccache the user may run.
while IFS= read -r var; do unset "$var"; done < <(env | sed -n 's/^\(SCCACHE_[A-Za-z0-9_]*\)=.*/\1/p')
unset RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER
: > "${WORK}/config"
export SCCACHE_CONF="${WORK}/config"
export SCCACHE_IDLE_TIMEOUT=0

# The copies keep the name `sccache`: under any other name the binary acts as a
# compiler wrapper rather than as sccache itself.
NAMES=(baseline pgo)
mkdir -p "${WORK}/baseline" "${WORK}/pgo"
cp "$BASELINE" "${WORK}/baseline/sccache"
cp "$CANDIDATE" "${WORK}/pgo/sccache"

# The environment selecting a binary's own server and cache, as a shell prefix.
env_of() {
    local port=4298
    [ "$1" = pgo ] && port=4297
    printf 'SCCACHE_SERVER_PORT=%s SCCACHE_DIR=%q' "$port" "${WORK}/$1/cache"
}
# Runs `sccache ARGS...` for binary $1 against its own server.
run_sccache() {
    local name="$1"
    shift
    eval "$(env_of "$name")" '"${WORK}/${name}/sccache"' '"$@"'
}
# `--stop-server` with no server running does not return, so only stop the
# servers once they have been started.
SERVERS_UP=0
stop_servers() {
    local name
    [ "$SERVERS_UP" -eq 1 ] || return 0
    for name in "${NAMES[@]}"; do run_sccache "$name" --stop-server >/dev/null 2>&1 || true; done
    SERVERS_UP=0
}
restart_servers() {
    # $1: value of SCCACHE_DIRECT
    local name
    stop_servers
    for name in "${NAMES[@]}"; do
        SCCACHE_DIRECT="$1" run_sccache "$name" --start-server >/dev/null
    done
    SERVERS_UP=1
}
cleanup() {
    stop_servers
    rm -rf "$WORK"
}
trap cleanup EXIT

# Runs hyperfine on a command template, `@` standing for the binary's name.
bench() {
    # $1 title, $2 runs, $3 warmup runs, $4 template
    local title="$1" runs="$2" warmup="$3" template="$4"
    local args=() name
    for name in "${NAMES[@]}"; do
        if [ "$HYPERFINE_ENV" -eq 1 ]; then
            args+=(-n "$name" --env "$(env_of "$name")" "${template//@/${name}}")
        else
            args+=(-n "$name" "$(env_of "$name") ${template//@/${name}}")
        fi
    done
    echo
    echo "=== ${title} ==="
    if [ "$HYPERFINE_ENV" -eq 1 ]; then
        # -N: no intermediate shell, whose startup would dwarf a cache hit.
        hyperfine -N --warmup "$warmup" --runs "$runs" "${args[@]}"
    else
        hyperfine --warmup "$warmup" --runs "$runs" "${args[@]}"
    fi
}

# One translation unit pulling in enough headers for hashing to matter.
cat > "${WORK}/unit.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
int f(const char *s) { return (int)strlen(s) + (int)sqrt((double)time(NULL)); }
int main(void) { printf("%d\n", f("hello")); return 0; }
EOF
C_CMD="$(printf '%q' "${WORK}")/@/sccache $(printf '%q -c %q -o %q' "$CC_BIN" "${WORK}/unit.c" "${WORK}/@/unit.o")"

# A header-heavy C++ unit: about a megabyte of preprocessed output to hash in
# preprocessor mode, and hundreds of headers to stat and hash in direct mode.
# This is where sccache's own code, rather than process startup, takes the time.
cat > "${WORK}/unit.cpp" <<'EOF'
#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
int main() {
    std::map<std::string, std::vector<int>> m;
    m["a"].push_back(1);
    std::cout << std::regex_match("abc", std::regex("a.c")) << m.size() << std::endl;
}
EOF
CXX_CMD=""
if [ -n "$CXX_BIN" ]; then
    CXX_CMD="$(printf '%q' "${WORK}")/@/sccache $(printf '%q -std=c++17 -c %q -o %q' "$CXX_BIN" "${WORK}/unit.cpp" "${WORK}/@/unit-cxx.o")"
fi

for direct in false true; do
    mode="preprocessor mode"
    [ "$direct" = true ] && mode="direct mode"
    restart_servers "$direct"
    bench "C cache hit (${mode})" "$RUNS" 5 "$C_CMD"
    [ -z "$CXX_CMD" ] || bench "C++ cache hit, heavy headers (${mode})" "$RUNS" 5 "$CXX_CMD"
done

# Most of this one is cargo's own time, but every crate goes through sccache's
# Rust argument parsing and hashing.
for name in "${NAMES[@]}"; do cp -r "${REPO_ROOT}/tests/test-crate" "${WORK}/${name}/crate"; done
RUST_RUNS=$((RUNS / 5))
[ "$RUST_RUNS" -ge 3 ] || RUST_RUNS=3
bench "cargo build, all cache hits" "$RUST_RUNS" 2 \
    "sh -c 'rm -rf ${WORK}/@/target && RUSTC_WRAPPER=${WORK}/@/sccache CARGO_INCREMENTAL=0 TEST_ENV_VAR=bench CARGO_TARGET_DIR=${WORK}/@/target cargo build --quiet --manifest-path ${WORK}/@/crate/Cargo.toml'"
