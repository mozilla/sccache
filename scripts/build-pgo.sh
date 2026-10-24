#!/usr/bin/env bash
#
# Build sccache with Profile-Guided Optimization.
#
#   1. build an instrumented sccache (-Cprofile-generate), together with the
#      integration tests that drive it
#   2. run those integration tests, then a synthetic C/C++ corpus (cache misses
#      followed by hits)
#   3. merge the raw profiles with llvm-profdata
#   4. build the optimized binary (-Cprofile-use), unless --train-only
#   5. with --bench, also build it without the profile and compare the two with
#      scripts/bench-pgo.sh (needs hyperfine)
#
# Runs on Linux, macOS and Windows (git-bash). The integration tests pick the
# compilers they find on their own; the corpus uses $CC/$CXX, or the first of
# cc/gcc/clang (c++/g++/clang++) found on PATH, and is skipped when there is none.
#
# Usage:
#   scripts/build-pgo.sh [--target TRIPLE] [--target-dir DIR] [--features LIST]
#                        [--train-only] [--bench] [--llvm-profdata PATH]

set -euo pipefail

# On Windows the instrumented binary, rustc and the profiler runtime are all
# native programs that do not understand git-bash's `/d/a/...` paths, while bash
# itself does not understand `D:\a\...`. `cygpath -m` yields `D:/a/...`, which
# both sides accept, so every path the script builds goes through it.
norm_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}

REPO_ROOT="$(norm_path "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)")"
TARGET_DIR="${REPO_ROOT}/target/sccache-pgo"
FEATURES=""
TARGET=""
TRAIN_ONLY=0
BENCH=0
LLVM_PROFDATA=""

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --target-dir) TARGET_DIR="$2"; shift 2 ;;
        --features) FEATURES="$2"; shift 2 ;;
        --llvm-profdata) LLVM_PROFDATA="$2"; shift 2 ;;
        --train-only) TRAIN_ONLY=1; shift ;;
        --bench) BENCH=1; shift ;;
        -h|--help) sed -n '3,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$TRAIN_ONLY" -eq 1 ] && [ "$BENCH" -eq 1 ]; then
    echo "--bench needs the optimized build, it cannot be combined with --train-only" >&2
    exit 2
fi
if [ "$BENCH" -eq 1 ] && ! command -v hyperfine >/dev/null; then
    echo "--bench needs hyperfine on PATH" >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"
TARGET_DIR="$(norm_path "$(cd "$TARGET_DIR" && pwd)")"

HOST="$(rustc --print host-tuple)"
[ -n "$TARGET" ] || TARGET="$HOST"
case "$TARGET" in *windows*) EXE=".exe" ;; *) EXE="" ;; esac
echo "target: ${TARGET} (host: ${HOST})"

SCRIPT_START=$SECONDS

fmt_duration() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }
begin_step() {
    STEP_NAME="$1"
    STEP_START=$SECONDS
    echo
    echo "=== ${STEP_NAME} ==="
}
end_step() { echo "--- ${STEP_NAME}: $(fmt_duration $((SECONDS - STEP_START))) ---"; }

PROFILE_DIR="${TARGET_DIR}/profiles"
MERGED="${TARGET_DIR}/sccache.profdata"

# llvm-profdata must come from the *active* toolchain: its version has to match
# the rustc that instrumented the binary.
if [ -z "$LLVM_PROFDATA" ]; then
    SYSROOT="$(norm_path "$(rustc --print sysroot)")"
    # llvm-profdata ships for the host, whatever we are cross-building for.
    case "$HOST" in *windows*) PROFDATA_EXE=".exe" ;; *) PROFDATA_EXE="" ;; esac
    LLVM_PROFDATA="${SYSROOT}/lib/rustlib/${HOST}/bin/llvm-profdata${PROFDATA_EXE}"
fi
if [ ! -x "$LLVM_PROFDATA" ]; then
    echo "llvm-profdata not found at ${LLVM_PROFDATA}" >&2
    echo "Run: rustup component add llvm-tools" >&2
    exit 1
fi
echo "llvm-profdata: ${LLVM_PROFDATA}"

# Integration tests used for training. They start their own servers and must
# run sequentially; the dist ones need Docker and are left out.
TRAINING_TESTS=(system sccache_cargo sccache_rustc cache_hit_rate sccache_args)

cargo_run() {
    # $1: target dir, $2: extra rustflags, rest: cargo subcommand and its args
    local dir="$1" flags="$2"
    shift 2
    local feature_args=()
    if [ -n "$FEATURES" ]; then feature_args=(--features="$FEATURES"); fi
    (
        cd "$REPO_ROOT"
        export CARGO_TARGET_DIR="$dir"
        export CARGO_INCREMENTAL=0
        export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }${flags}"
        # bash 3.2 (macOS) errors on an empty array expansion under `set -u`,
        # hence the `[@]+` guard on both expansions below.
        echo "Running: cargo $1 --locked --release --target=${TARGET} ${feature_args[*]+${feature_args[*]}} ${*:2}"
        echo "  RUSTFLAGS=${RUSTFLAGS}"
        cargo "$1" --locked --release --target="$TARGET" ${feature_args[@]+"${feature_args[@]}"} "${@:2}"
    )
}

begin_step "Step 1: instrumented build"
INSTR_DIR="${TARGET_DIR}/instrumented"
rm -rf "$PROFILE_DIR"
mkdir -p "$PROFILE_DIR"
# The instrumented build must use the same LTO and codegen-unit settings as the
# final one. Inlining happens before instrumentation, so building it with LTO
# off yields counters for functions that no longer exist once the final build
# runs whole-program codegen, and the profile is then largely wasted on it.
#
# `--cfg pgo_training` makes the binary flush its own counters before exiting:
# it always leaves through `std::process::exit`, which on Windows is
# `ExitProcess` and skips the `atexit` handler the profiling runtime would
# otherwise write the profile from.
INSTR_FLAGS="-Cprofile-generate=${PROFILE_DIR} --cfg pgo_training"

# The integration tests run `CARGO_BIN_EXE_sccache`, i.e. the sccache built by
# `cargo test` into this target dir. That one must not be trained on, though:
# under `cargo test`, dev-dependencies unify extra features into libc, serde,
# rustls, ... which changes their `-C metadata`, and with it the symbol names of
# those crates and of sccache itself, so its profile would barely match the
# final `cargo build`. Hence the test executables are built first, then
# `cargo build` overwrites the binary at the path they use with the exact one
# the final build will match, and the tests are run directly (`cargo test`
# would rebuild it).
test_args=()
for t in "${TRAINING_TESTS[@]}"; do test_args+=(--test "$t"); done
TEST_EXES=()
while IFS= read -r exe; do
    TEST_EXES+=("$(norm_path "$exe")")
done < <(cargo_run "$INSTR_DIR" "$INSTR_FLAGS" test --no-run --message-format=json "${test_args[@]}" \
    | sed -n 's/.*"kind":\["test"\].*"executable":"\([^"]*\)".*/\1/p' | sed 's/\\\\/\\/g')
if [ ${#TEST_EXES[@]} -ne ${#TRAINING_TESTS[@]} ]; then
    echo "expected ${#TRAINING_TESTS[@]} test executables, found ${#TEST_EXES[@]}" >&2
    exit 1
fi
cargo_run "$INSTR_DIR" "$INSTR_FLAGS" build --bin sccache

BIN="${INSTR_DIR}/${TARGET}/release/sccache${EXE}"
[ -x "$BIN" ] || { echo "instrumented binary not found: ${BIN}" >&2; exit 1; }
# Training runs the binary we just built, so a foreign target only works where
# the host can execute it (x86_64 on arm64 macOS needs Rosetta, for instance).
if ! "$BIN" --version >/dev/null 2>&1; then
    echo "cannot run the instrumented ${TARGET} binary on this ${HOST} host" >&2
    exit 1
fi
end_step

begin_step "Step 2: integration tests"
# The test harnesses are instrumented as well, and their counters (assert_cmd,
# serde_json parsing the stats...) must not end up in sccache's profile. `%m`
# names each file after the signature of the binary that wrote it, and merges
# all processes of the same binary into it online, so sccache's profile is the
# one file named like what a lone `sccache --version` run produces.
PROBE_DIR="${TARGET_DIR}/probe"
rm -rf "$PROBE_DIR"
mkdir -p "$PROBE_DIR"
LLVM_PROFILE_FILE="${PROBE_DIR}/%m.profraw" "$BIN" --version >/dev/null
SCCACHE_PROFRAW="$(cd "$PROBE_DIR" && ls)"
rm -rf "$PROBE_DIR"
[ -n "$SCCACHE_PROFRAW" ] || { echo "the instrumented binary wrote no profile" >&2; exit 1; }
echo "sccache profile: ${SCCACHE_PROFRAW}"
export LLVM_PROFILE_FILE="${PROFILE_DIR}/%m.profraw"

# Isolated from whatever sccache the user may run: no inherited backend
# settings or config file.
while IFS= read -r var; do unset "$var"; done < <(env | sed -n 's/^\(SCCACHE_[A-Za-z0-9_]*\)=.*/\1/p')
unset RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER

# What `cargo test` would provide: the tests run from the package root and
# drive cargo through $CARGO.
export CARGO="${CARGO:-$(command -v cargo)}"
export CARGO_MANIFEST_DIR="$REPO_ROOT"
# Some tests depend on compilers or setups this machine may not have; a failing
# test still leaves a usable profile, and step 4 catches a run that did nothing.
for exe in "${TEST_EXES[@]}"; do
    name="$(basename "$exe")"
    echo "test: ${name}"
    (cd "$REPO_ROOT" && "$exe" --test-threads 1) >"${TARGET_DIR}/test-${name}.log" 2>&1 \
        || echo "  some tests failed, see ${TARGET_DIR}/test-${name}.log"
done
end_step

begin_step "Step 3: corpus"
# The tests cover many code paths but mostly once each; real builds are
# dominated by repeated compilations and cache hits, which this corpus adds.
# Kept inside the target dir rather than under TMPDIR: git-bash may hand back a
# Windows-style TMPDIR that neither sccache nor the compilers would agree on.
WORK="${TARGET_DIR}/work"
rm -rf "$WORK"
mkdir -p "$WORK"
: > "${WORK}/config"
export SCCACHE_CONF="${WORK}/config"
export SCCACHE_DIR="${WORK}/cache"
export SCCACHE_SERVER_PORT=4299
export SCCACHE_IDLE_TIMEOUT=0
# Keep the server a plain child process rather than a forked daemon, so that
# its counters end up in a profile of their own when it is stopped.
export SCCACHE_NO_DAEMON=1

find_tool() {
    # $1: preferred value (may be empty), then candidate names
    local preferred="$1"
    shift
    if [ -n "$preferred" ]; then
        command -v "$preferred" 2>/dev/null && return 0
    fi
    local c
    for c in "$@"; do
        command -v "$c" 2>/dev/null && return 0
    done
    return 1
}
CC_BIN="$(find_tool "${CC:-}" cc gcc clang || true)"
CXX_BIN="$(find_tool "${CXX:-}" c++ g++ clang++ || true)"
echo "C compiler: ${CC_BIN:-none}"
echo "C++ compiler: ${CXX_BIN:-none}"

# Generated rather than copied from the system, so the profile does not depend
# on the machine. Standard headers make the preprocessed output large enough
# for hashing to dominate, as it does on real code.
SRC="${WORK}/src"
mkdir -p "$SRC"
N_SOURCES=40
for ((i = 0; i < N_SOURCES; i++)); do
    {
        printf '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include "common.h"\n'
        printf 'static int table_%d[] = {' "$i"
        for ((j = 0; j < 64; j++)); do printf '%d,' $(((i * 31 + j * 17) % 1000)); done
        printf '};\n'
        printf 'int func_%d(const char *s) {\n' "$i"
        printf '    int acc = COMMON_SEED;\n'
        printf '    for (size_t k = 0; k < strlen(s); k++) acc += s[k] * table_%d[k %% 64];\n' "$i"
        printf '    return acc;\n}\n'
    } > "${SRC}/unit${i}.c"
    {
        printf '#include <string>\n#include <vector>\n#include <map>\n#include <algorithm>\n#include "common.h"\n'
        printf 'int cxx_func_%d(const std::vector<std::string> &v) {\n' "$i"
        printf '    std::map<std::string, int> m;\n'
        printf '    for (const auto &s : v) m[s] += COMMON_SEED + %d;\n' "$i"
        printf '    return static_cast<int>(std::count_if(m.begin(), m.end(), [](const auto &p) { return p.second > %d; }));\n' "$i"
        printf '}\n'
    } > "${SRC}/unit${i}.cpp"
done
printf '#define COMMON_SEED 7\n' > "${SRC}/common.h"

"$BIN" --start-server
# Whatever happens below, never leave the training server behind.
trap '"$BIN" --stop-server >/dev/null 2>&1 || true' EXIT

# Individual compilations are allowed to fail (a flag may not be supported by
# the compiler at hand); a partial profile is still a usable profile.
compile_all() {
    # $1: compiler, $2: source extension, $3: output dir, rest: extra flags
    local compiler="$1" ext="$2" out="$3"
    shift 3
    mkdir -p "$out"
    local i
    for ((i = 0; i < N_SOURCES; i++)); do
        "$BIN" "$compiler" -c "${SRC}/unit${i}.${ext}" -o "${out}/unit${i}.o" -I"$SRC" "$@" \
            >/dev/null 2>&1 || true
    done
}

c_workloads() {
    # $1: label for the output dirs
    if [ -n "$CC_BIN" ]; then
        compile_all "$CC_BIN" c "${WORK}/obj/$1/c-O2" -O2
        compile_all "$CC_BIN" c "${WORK}/obj/$1/c-g" -O0 -g -Wall -DDEBUG=1
        compile_all "$CC_BIN" c "${WORK}/obj/$1/c-dep" -O1 -MD -MP
    fi
    if [ -n "$CXX_BIN" ]; then
        compile_all "$CXX_BIN" cpp "${WORK}/obj/$1/cxx-O2" -O2 -std=c++17
        compile_all "$CXX_BIN" cpp "${WORK}/obj/$1/cxx-g" -O0 -g -std=c++17
    fi
}

# Preprocessor mode: preprocess, hash, look up. First pass misses and stores,
# second pass hits.
echo "C/C++ (preprocessor mode, miss)"
c_workloads pp-miss
echo "C/C++ (preprocessor mode, hit)"
c_workloads pp-hit

# Direct mode: the preprocessor cache skips preprocessing entirely on a hit.
"$BIN" --stop-server >/dev/null 2>&1 || true
export SCCACHE_DIRECT=true
"$BIN" --start-server
echo "C/C++ (direct mode, populate)"
c_workloads direct-1
echo "C/C++ (direct mode, hit)"
c_workloads direct-2
# Touch the shared header so direct mode has to fall back and re-validate.
printf '#define COMMON_SEED 11\n' > "${SRC}/common.h"
echo "C/C++ (direct mode, header changed)"
c_workloads direct-3
unset SCCACHE_DIRECT

"$BIN" --show-stats || true
"$BIN" --show-stats --stats-format=json >/dev/null 2>&1 || true
"$BIN" --zero-stats >/dev/null 2>&1 || true
# Stopping the server is what writes its profile.
"$BIN" --stop-server >/dev/null 2>&1 || true
trap - EXIT
rm -rf "$WORK"

echo "Workloads complete."
end_step

begin_step "Step 4: merging profiles"
RAW="${PROFILE_DIR}/${SCCACHE_PROFRAW}"
if [ ! -s "$RAW" ]; then
    echo "no sccache profile at ${RAW}" >&2
    ls -l "$PROFILE_DIR" >&2
    exit 1
fi
"$LLVM_PROFDATA" merge -sparse "$RAW" -o "$MERGED"
echo "Merged profile: ${MERGED}"

# A profile that covers almost nothing still builds fine and silently produces a
# barely-optimized binary, so fail loudly instead: every test and compilation
# is allowed to fail individually, and without this a broken setup would ship.
"$LLVM_PROFDATA" show "$MERGED" | head -6
COVERED="$("$LLVM_PROFDATA" show "$MERGED" | sed -n 's/^Total functions: *//p')"
MIN_FUNCTIONS=2000
if [ -z "$COVERED" ] || [ "$COVERED" -lt "$MIN_FUNCTIONS" ]; then
    echo "profile covers only ${COVERED:-0} functions (expected >= ${MIN_FUNCTIONS})" >&2
    echo "the training workloads probably did not run; refusing to ship this profile" >&2
    echo "--- raw profiles in ${PROFILE_DIR}:" >&2
    ls -l "$PROFILE_DIR" >&2
    exit 1
fi
echo "Profile covers ${COVERED} functions."
end_step

# CI needs the absolute, natively-spelled path to put in RUSTFLAGS; it cannot
# reconstruct it portably because of the Windows path rewriting above.
printf '%s\n' "$MERGED" > "${TARGET_DIR}/profdata-path.txt"

if [ "$TRAIN_ONLY" -eq 1 ]; then
    echo
    echo "To use the profile in a release build, add to RUSTFLAGS:"
    echo "  -Cprofile-use=${MERGED}"
    echo "Total: $(fmt_duration $((SECONDS - SCRIPT_START)))"
    exit 0
fi

begin_step "Step 5: optimized build"
cargo_run "$TARGET_DIR" "-Cprofile-use=${MERGED}" build --bin sccache
end_step
PGO_BIN="${TARGET_DIR}/${TARGET}/release/sccache${EXE}"

if [ "$BENCH" -eq 1 ]; then
    begin_step "Step 6: baseline build and benchmark"
    BASELINE_DIR="${TARGET_DIR}/baseline"
    cargo_run "$BASELINE_DIR" "" build --bin sccache
    "${REPO_ROOT}/scripts/bench-pgo.sh" "${BASELINE_DIR}/${TARGET}/release/sccache${EXE}" "$PGO_BIN"
    end_step
fi

echo
echo "Optimized binary: ${PGO_BIN}"
echo "Total: $(fmt_duration $((SECONDS - SCRIPT_START)))"
