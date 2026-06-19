#!/usr/bin/env bash
# =============================================================================
# bench-file-clone.sh - Benchmark sccache's `file_clone` (reflink) disk cache.
#
# This is a MANUAL performance tool (not wired into CI). It compares, per target
# repository/project, three scenarios:
#
#   * cold    - a clean build with sccache disabled (no cache),
#   * warm    - a rebuild served entirely from the DEFAULT (compressed) disk cache,
#   * clone   - a rebuild served entirely from the `file_clone` (uncompressed
#               reflink) disk cache.
#
# and reports, per target:
#
#   * the wall-clock time of each scenario,
#   * the on-disk size of the compressed vs. file_clone cache,
#   * the *actual* disk space used by the cache and the restored build artifacts
#     together, measured with `compsize` (the authoritative btrfs tool): when they
#     share blocks via reflink, the combined on-disk usage stays near one copy while
#     the logical "referenced" size is ~two copies, and the difference is the disk saved, and
#   * how many restored objects were reflinked vs. copied (from `--show-stats`).
#
# The methodology mirrors PR https://github.com/mozilla/sccache/pull/2640, which
# benchmarked ripgrep/fd/bat.
#
# IMPORTANT: the block-sharing / near-zero-disk benefit only materialises when the
# cache directory AND the build directory live on the SAME copy-on-write filesystem
# (Btrfs, XFS w/ reflink, APFS, ReFS). On other filesystems file_clone still works
# (no decompression on read) but falls back to plain copies, so disk usage will not
# shrink. The script prints which case it observed.
#
# Usage:
#   scripts/bench-file-clone.sh [extra cargo repos ...]
#
# Environment:
#   SCCACHE     Path to the sccache binary. Default: build ./target/release/sccache.
#   WORKDIR     Scratch directory. Default: a fresh mktemp dir (removed on exit).
#   C_FILES     Number of generated C files for the offline target. Default: 120.
#   BENCH_REPOS Space-separated "name=git-url" entries to additionally benchmark
#               with `cargo build` (requires network + cargo). Example:
#                 BENCH_REPOS="ripgrep=https://github.com/BurntSushi/ripgrep \
#                              fd=https://github.com/sharkdp/fd" \
#                 scripts/bench-file-clone.sh
#
# The offline C target ("local-c") always runs and needs no network, so the tool
# can be verified end-to-end in an isolated environment.
#
# Platform: this script is Linux/GNU-oriented (it uses `du --apparent-size`, `df -Pk`,
# `stat -f -c`, `nproc`). On btrfs it uses `compsize` for the authoritative on-disk /
# disk-savings measurement; install it from https://github.com/kilobyte/compsize (or
# your distro's `compsize` package). It is a manual perf tool, not part of CI.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ----- locate / build sccache --------------------------------------------------
if [[ -z "${SCCACHE:-}" ]]; then
  echo ">> Building sccache (release)..."
  (cd "${REPO_ROOT}" && cargo build --release --bin sccache >/dev/null)
  SCCACHE="${REPO_ROOT}/target/release/sccache"
fi
echo ">> Using sccache: ${SCCACHE}"
"${SCCACHE}" --version

# ----- scratch dir -------------------------------------------------------------
CLEANUP_WORKDIR=0
if [[ -z "${WORKDIR:-}" ]]; then
  WORKDIR="$(mktemp -d)"
  CLEANUP_WORKDIR=1
fi
mkdir -p "${WORKDIR}"
echo ">> Work directory: ${WORKDIR}"

if ! command -v compsize >/dev/null 2>&1; then
  echo ">> WARNING: 'compsize' not found; the disk-savings columns will show n/a." >&2
  echo ">>          Install it for the authoritative btrfs measurement: https://github.com/kilobyte/compsize" >&2
fi

cleanup() {
  "${SCCACHE}" --stop-server >/dev/null 2>&1 || true
  if [[ "${CLEANUP_WORKDIR}" == "1" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

C_FILES="${C_FILES:-120}"

# Results, one markdown row per target.
declare -a RESULTS

# Print wall-clock seconds (float) of running "$@". Aborts (non-zero exit) if the timed command
# fails, so a broken build can't masquerade as a fast "warm" time.
time_cmd() {
  local start end status
  start="$(date +%s.%N)"
  if "$@" >/dev/null 2>&1; then
    status=0
  else
    status=$?
  fi
  end="$(date +%s.%N)"
  if [ "${status}" -ne 0 ]; then
    echo "ERROR: timed command failed (exit ${status}): $*" >&2
    return "${status}"
  fi
  awk -v s="${start}" -v e="${end}" 'BEGIN { printf "%.2f", e - s }'
}

# Directory size in KiB (actual blocks used).
dir_kib() {
  du -sk "$1" 2>/dev/null | awk '{print $1}'
}

# `du` apparent size in KiB (logical size, ignores block sharing).
dir_apparent_kib() {
  du -sk --apparent-size "$1" 2>/dev/null | awk '{print $1}'
}

# Available space in KiB on the filesystem containing $1.
fs_avail_kib() {
  df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

# Authoritative on-disk measurement via `compsize` (btrfs). Given one or more paths, prints
# "DISK_KIB REFERENCED_KIB": DISK = physical blocks actually allocated, with shared/reflinked
# extents counted ONCE; REFERENCED = logical bytes referenced, counting every reference.
# Measuring the cache and the restored artifacts together, DISK far below REFERENCED proves
# they share blocks via reflink, and REFERENCED-DISK is the disk saved. Empty if compsize is
# unavailable or a path is not on btrfs.
compsize_disk_ref() {
  command -v compsize >/dev/null 2>&1 || return 0
  compsize -b "$@" 2>/dev/null \
    | awk '/^TOTAL/ { printf "%d %d", int($3 / 1024), int($5 / 1024) }'
}

# Extract a top-level numeric stat from `sccache --show-stats --stats-format=json`.
stat_json() {
  local dir="$1" key="$2"
  SCCACHE_DIR="${dir}" "${SCCACHE}" --show-stats --stats-format=json 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('stats',{}).get('${key}',0))" 2>/dev/null \
    || echo 0
}

# Total cache hits across all languages (sum of cache_hits.counts).
cache_hits_total() {
  local dir="$1"
  SCCACHE_DIR="${dir}" "${SCCACHE}" --show-stats --stats-format=json 2>/dev/null \
    | python3 -c "import sys,json; print(sum(json.load(sys.stdin).get('stats',{}).get('cache_hits',{}).get('counts',{}).values()))" 2>/dev/null \
    || echo 0
}

start_server() {
  local dir="$1"; shift
  local extra_env=("$@")
  "${SCCACHE}" --stop-server >/dev/null 2>&1 || true
  env SCCACHE_DIR="${dir}" "${extra_env[@]}" "${SCCACHE}" --start-server >/dev/null 2>&1
}

stop_server() {
  "${SCCACHE}" --stop-server >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# Generate a self-contained C project (no network) with $C_FILES translation
# units plus a Makefile that compiles them through "$SCCACHE gcc".
# -----------------------------------------------------------------------------
gen_c_project() {
  local dir="$1"
  rm -rf "${dir}"
  mkdir -p "${dir}/src"
  # Each unit gets a long, data-dependent arithmetic body so the optimizer has
  # real work to do (otherwise sccache's per-call overhead dwarfs the compile and
  # the warm build can look slower than the cold one).
  local stmts="${C_FILE_STMTS:-600}"
  local i j
  for ((i = 0; i < C_FILES; i++)); do
    {
      cat <<EOF
#include <stdint.h>
#include <stddef.h>
static uint64_t table_${i}[256];
uint64_t compute_${i}(uint64_t x) {
    uint64_t a = ${i}u, b = 0x9e3779b97f4a7c15ull ^ x, c = x;
    for (size_t k = 0; k < 256; ++k) {
        table_${i}[k] = (x ^ (k * 2654435761u)) + a;
        a = (a << 7) ^ (a >> 3) ^ table_${i}[k];
    }
EOF
      for ((j = 0; j < stmts; j++)); do
        echo "    a = a * 6364136223846793005ull + b; b = (b ^ (a >> 17)) + c; c = (c << 5) - a;"
      done
      echo "    return a ^ b ^ c;"
      echo "}"
    } >"${dir}/src/mod_${i}.c"
  done
  {
    echo "CC ?= gcc"
    echo "SCCACHE ?= sccache"
    echo "CFLAGS ?= -O2 -g"
    printf 'OBJS ='
    for ((i = 0; i < C_FILES; i++)); do printf ' build/mod_%d.o' "${i}"; done
    echo
    echo
    echo "all: \$(OBJS)"
    echo
    echo "build/%.o: src/%.c"
    echo "	@mkdir -p build"
    echo "	\$(SCCACHE) \$(CC) \$(CFLAGS) -c \$< -o \$@"
    echo
    echo "clean:"
    echo "	rm -rf build"
  } >"${dir}/Makefile"
}

# -----------------------------------------------------------------------------
# Benchmark one target.
#   $1 = display name
#   $2 = project directory
#   $3 = cold build command (sccache disabled)
#   $4 = warm build command (uses $SCCACHE for the compiler)
#   $5 = clean command
#   $6 = build output subdirectory (for measuring restored-artifact disk usage)
# -----------------------------------------------------------------------------
bench_target() {
  local name="$1" proj="$2" cold_cmd="$3" warm_cmd="$4" clean_cmd="$5" out_subdir="$6"
  echo
  echo "============================================================"
  echo ">> Target: ${name}"
  echo "============================================================"

  local comp_cache="${WORKDIR}/cache-compressed-${name}"
  local clone_cache="${WORKDIR}/cache-fileclone-${name}"
  rm -rf "${comp_cache}" "${clone_cache}"

  # ---- cold build (no sccache) ----
  (cd "${proj}" && eval "${clean_cmd}") >/dev/null 2>&1 || true
  stop_server
  local cold
  cold="$(cd "${proj}" && time_cmd bash -c "${cold_cmd}")"
  echo "   cold (no cache):        ${cold}s"

  local out_dir="${proj}/${out_subdir}"

  # ---- warm build, compressed cache ----
  start_server "${comp_cache}"
  (cd "${proj}" && eval "${clean_cmd}") >/dev/null 2>&1 || true
  (cd "${proj}" && eval "${warm_cmd}") >/dev/null 2>&1   # populate (miss)
  (cd "${proj}" && eval "${clean_cmd}") >/dev/null 2>&1 || true
  sync
  local avail_before_comp
  avail_before_comp="$(fs_avail_kib "${proj}")"
  local warm
  warm="$(cd "${proj}" && time_cmd bash -c "${warm_cmd}")"  # hit
  sync
  local comp_restore_delta=$(( avail_before_comp - $(fs_avail_kib "${proj}") ))
  local comp_size
  comp_size="$(dir_kib "${comp_cache}")"
  # compsize on btrfs: the compressed cache and the restored artifacts share no blocks, so
  # restoring adds ~the full restored size of new disk (comp_marginal = union disk - cache disk).
  local comp_cs comp_cache_cs comp_disk="n/a" comp_marginal="n/a"
  comp_cs="$(compsize_disk_ref "${comp_cache}" "${out_dir}")"
  comp_cache_cs="$(compsize_disk_ref "${comp_cache}")"
  if [[ -n "${comp_cs}" && -n "${comp_cache_cs}" ]]; then
    comp_disk="${comp_cs%% *}"
    comp_marginal=$(( comp_disk - ${comp_cache_cs%% *} ))
  fi
  # The warm run must be a genuine cache hit, otherwise the time is meaningless.
  if [ "$(cache_hits_total "${comp_cache}")" -eq 0 ]; then
    echo "ERROR: compressed warm build for ${name} produced no cache hits" >&2
    stop_server
    exit 1
  fi
  echo "   warm (compressed):      ${warm}s   cache=${comp_size} KiB   df-delta=${comp_restore_delta} KiB   compsize: cache+restore on-disk=${comp_disk} KiB  restore-marginal=${comp_marginal} KiB"
  stop_server

  # ---- warm build, file_clone cache ----
  start_server "${clone_cache}" SCCACHE_FILE_CLONE=true
  (cd "${proj}" && eval "${clean_cmd}") >/dev/null 2>&1 || true
  (cd "${proj}" && eval "${warm_cmd}") >/dev/null 2>&1   # populate (miss)
  (cd "${proj}" && eval "${clean_cmd}") >/dev/null 2>&1 || true
  sync
  local avail_before_clone
  avail_before_clone="$(fs_avail_kib "${proj}")"
  local clone
  clone="$(cd "${proj}" && time_cmd bash -c "${warm_cmd}")"  # hit (reflink/copy)
  sync
  local clone_restore_delta=$(( avail_before_clone - $(fs_avail_kib "${proj}") ))
  local clone_size
  clone_size="$(dir_kib "${clone_cache}")"

  # Logical (apparent) size of the restored artifacts, for reference.
  local restored_apparent
  restored_apparent="$(dir_apparent_kib "${out_dir}")"

  # Authoritative disk-savings measurement on btrfs via compsize. Measuring the file_clone
  # cache and the restored artifacts TOGETHER counts shared (reflinked) extents once, so the
  # marginal disk the restore adds = compsize_disk(cache+restore) - compsize_disk(cache) is
  # ~0 when (and only when) the restore reflinks the cache. This isolates block sharing from
  # any btrfs transparent compression, which affects both terms equally.
  local clone_cs clone_cache_cs clone_disk="n/a" clone_ref="n/a" clone_cache_disk="n/a" restore_marginal="n/a"
  clone_cs="$(compsize_disk_ref "${clone_cache}" "${out_dir}")"
  clone_cache_cs="$(compsize_disk_ref "${clone_cache}")"
  if [[ -n "${clone_cs}" && -n "${clone_cache_cs}" ]]; then
    clone_disk="${clone_cs%% *}"
    clone_ref="${clone_cs##* }"
    clone_cache_disk="${clone_cache_cs%% *}"
    restore_marginal=$(( clone_disk - clone_cache_disk ))
  fi

  # The warm run must be a genuine cache hit.
  if [ "$(cache_hits_total "${clone_cache}")" -eq 0 ]; then
    echo "ERROR: file_clone warm build for ${name} produced no cache hits" >&2
    stop_server
    exit 1
  fi
  # Reflink vs copy counters from the file_clone server.
  local reflinked copied
  reflinked="$(stat_json "${clone_cache}" objects_reflinked)"
  copied="$(stat_json "${clone_cache}" objects_copied_fallback)"
  stop_server

  echo "   warm (file_clone):      ${clone}s   cache=${clone_size} KiB   df-delta=${clone_restore_delta} KiB"
  echo "   restored artifacts:     logical=${restored_apparent} KiB"
  echo "   compsize (cache+restore): on-disk=${clone_disk} KiB  referenced=${clone_ref} KiB  (cache-only on-disk=${clone_cache_disk} KiB)"
  echo "   restore marginal disk:  ${restore_marginal} KiB  (~0 => restore reflinks the cache; compressed was ${comp_marginal} KiB)"
  echo "   reflinked objects:      ${reflinked}   copied (fallback): ${copied}"

  RESULTS+=("| ${name} | ${cold} | ${warm} | ${clone} | ${comp_size} | ${clone_size} | ${restored_apparent} | ${clone_disk} | ${restore_marginal} | ${reflinked}/${copied} |")
}

# ----- offline C target (always) ----------------------------------------------
C_PROJ="${WORKDIR}/local-c"
gen_c_project "${C_PROJ}"
bench_target "local-c" "${C_PROJ}" \
  'make -j"$(nproc)" SCCACHE=' \
  'make -j"$(nproc)" SCCACHE="$SCCACHE"' \
  'make clean' \
  "build"

# ----- optional cargo repos (network) -----------------------------------------
REPO_SPECS=("$@")
if [[ -n "${BENCH_REPOS:-}" ]]; then
  # shellcheck disable=SC2206
  REPO_SPECS+=(${BENCH_REPOS})
fi
for spec in "${REPO_SPECS[@]:-}"; do
  [[ -z "${spec}" ]] && continue
  name="${spec%%=*}"
  url="${spec#*=}"
  echo
  echo ">> Cloning ${name} from ${url} ..."
  if ! git clone --depth 1 "${url}" "${WORKDIR}/${name}" >/dev/null 2>&1; then
    echo "   !! clone failed (offline?), skipping ${name}"
    continue
  fi
  # Use RUSTC_WRAPPER so cargo routes rustc through sccache.
  bench_target "${name}" "${WORKDIR}/${name}" \
    'cargo build' \
    'RUSTC_WRAPPER="$SCCACHE" cargo build' \
    'cargo clean' \
    "target/debug"
done

# ----- markdown summary -------------------------------------------------------
echo
echo "## file_clone benchmark results"
echo
echo "Filesystem of work dir: $(stat -f -c '%T' "${WORKDIR}" 2>/dev/null || echo unknown)"
echo
echo "Times in seconds; sizes in KiB. 'cache+restore on disk' is the compsize disk usage of"
echo "the file_clone cache and the restored artifacts together (shared/reflinked extents counted"
echo "once). 'restore marginal disk' = that minus the compsize disk of the cache alone, i.e. the"
echo "NEW disk the restore consumes; ~0 means the restored artifacts reflink the cache (this"
echo "isolates block sharing from any btrfs transparent compression). 'reflink/copy' ="
echo "objects_reflinked/objects_copied_fallback from --show-stats (the proof CoW engaged)."
echo
echo "| target | cold | warm (compressed) | warm (file_clone) | compressed cache | file_clone cache | restored (logical) | cache+restore on disk | restore marginal disk | reflink/copy |"
echo "|--------|-----:|------------------:|------------------:|-----------------:|-----------------:|-------------------:|----------------------:|----------------------:|:------------:|"
for row in "${RESULTS[@]}"; do
  echo "${row}"
done
