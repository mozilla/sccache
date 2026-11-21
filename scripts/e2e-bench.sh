#!/usr/bin/env bash
#
# End-to-end check of two sccache binaries on a real C project (FFmpeg).
#
# Builds the project through each binary, in server and client-side mode, with
# an empty cache and then a warm one, alternating the binaries so that they see
# the same machine load. Then:
#
#   * fails on what is deterministic: a build that fails or hangs, a warm build
#     that is not all hits, a cache write error, client-side and server mode
#     disagreeing on what they counted, or, with --large-entries, a client-side
#     build with entries over the frame limit not being cached;
#   * reports the build times, and fails only when a median regresses by more
#     than --max-regression against the baseline (times on shared CI runners
#     are noisy).
#
# Usage:
#   scripts/e2e-bench.sh --baseline PATH --candidate PATH [--reps N]
#                        [--jobs N] [--work DIR] [--max-regression PCT]
#                        [--large-entries]
#
# Needs clang, make, curl and jq. Writes a markdown report to $GITHUB_STEP_SUMMARY
# when it is set, and to stdout otherwise.

set -euo pipefail
# printf and bc have to agree on the decimal separator.
export LC_ALL=C

FFMPEG_VERSION=n7.1.1
FFMPEG_URL=https://github.com/FFmpeg/FFmpeg/archive/refs/tags/$FFMPEG_VERSION.tar.gz
# Enough of FFmpeg for a few hundred translation units: the per-compile overhead
# is what this is about, not the size of any one of them.
# shellcheck disable=SC2054 # the commas separate FFmpeg components
FFMPEG_CONFIGURE=(--cc=clang --disable-programs --disable-doc --disable-x86asm
    --disable-everything --enable-decoder=h264,hevc,vp9,aac,opus --enable-parser=h264,hevc,vp9
    --enable-demuxer=mov,matroska --disable-avdevice --disable-swresample --disable-avfilter)
# Small enough that some objects go over it, to exercise the path that passes
# them outside of a message in client-side mode.
SMALL_FRAME_LENGTH=262144
BUILD_TIMEOUT=1800

large_entries='' baseline='' candidate='' reps=2 jobs=$(nproc 2>/dev/null || sysctl -n hw.ncpu) work=${TMPDIR:-/tmp}/sccache-e2e max_regression=30
while [ $# -gt 0 ]; do
    case $1 in
    --baseline) baseline=$(realpath "$2"); shift ;;
    --candidate) candidate=$(realpath "$2"); shift ;;
    --reps) reps=$2; shift ;;
    --jobs) jobs=$2; shift ;;
    --work) work=$2; shift ;;
    --max-regression) max_regression=$2; shift ;;
    --large-entries) large_entries=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
[ -x "$baseline" ] && [ -x "$candidate" ] || { echo "--baseline and --candidate must be sccache binaries" >&2; exit 2; }

mkdir -p "$work"
work=$(realpath "$work")
src=$work/ffmpeg-src
results=$work/results.tsv
# A file rather than an array: `build` runs in a subshell.
failures=$work/failures.txt
: >"$failures"
fail() { echo "$*" >>"$failures"; }

if [ ! -f "$src/configure" ]; then
    rm -rf "$src"
    mkdir -p "$src"
    curl -sSfL "$FFMPEG_URL" | tar xz -C "$src" --strip-components=1
fi
if [ ! -f "$src/ffbuild/config.mak" ]; then
    (cd "$src" && ./configure "${FFMPEG_CONFIGURE[@]}" >"$work/configure.log" 2>&1) || {
        tail -30 "$work/configure.log" >&2
        exit 1
    }
fi

# sccache masquerades as the compiler it is named after, so each binary has to
# be called `sccache`.
for name in baseline candidate; do
    mkdir -p "$work/bin/$name"
    cp "${!name}" "$work/bin/$name/sccache"
done

# Print "<seconds>\t<hits>\t<misses>\t<write errors>" for one build, hits and
# misses as JSON objects of counts per language, sorted so that they compare:
# the stats serialize a HashMap.
build() { # name mode state [frame length]
    local name=$1 mode=$2 state=$3 frame=${4:-}
    local bin=$work/bin/$name/sccache
    export SCCACHE_DIR=$work/cache-$name-$mode${frame:+-$frame}
    export SCCACHE_SERVER_PORT=${SCCACHE_E2E_PORT:-4321} SCCACHE_IDLE_TIMEOUT=0 SCCACHE_CACHE_SIZE=20G
    local client_side=false
    [ "$mode" = client ] && client_side=true
    export SCCACHE_CLIENT_SIDE=$client_side
    if [ -n "$frame" ]; then export SCCACHE_MAX_FRAME_LENGTH=$frame; else unset SCCACHE_MAX_FRAME_LENGTH; fi
    unset SCCACHE_LOG SCCACHE_ERROR_LOG
    [ "$state" = cold ] && rm -rf "$SCCACHE_DIR"
    "$bin" --stop-server >/dev/null 2>&1 || true
    "$bin" --start-server >/dev/null
    make -C "$src" clean >/dev/null 2>&1
    # A log per build: the runs of every rep and the frame limit checks would
    # otherwise overwrite the one a failure points at.
    local log=make-$name-$mode-$state-${rep:-0}${frame:+-frame$frame}.log
    local t0 t1 rc=0
    t0=$(date +%s.%N)
    timeout "$BUILD_TIMEOUT" make -C "$src" -j"$jobs" CC="$bin clang" >"$work/$log" 2>&1 || rc=$?
    t1=$(date +%s.%N)
    local stats
    stats=$("$bin" --show-stats --stats-format json 2>/dev/null || echo '{}')
    "$bin" --stop-server >/dev/null 2>&1 || true
    if [ "$rc" = 124 ]; then
        fail "$name $mode $state${frame:+ (frame limit $frame)}: build hung, killed after ${BUILD_TIMEOUT}s"
    elif [ "$rc" != 0 ]; then
        fail "$name $mode $state${frame:+ (frame limit $frame)}: build failed, see $log"
    fi
    jq -nr --arg t "$(echo "$t1 - $t0" | bc)" --argjson s "$stats" \
        'def counts: . // {} | to_entries | sort_by(.key) | from_entries | tojson;
        "\($t)\t\($s.stats.cache_hits.counts | counts)\t\($s.stats.cache_misses.counts | counts)\t\($s.stats.cache_write_errors // -1)"'
}

sum() { jq -r 'to_entries | map(.value) | add // 0' <<<"$1"; }

# A warm build has to hit everything its cold build compiled. Counting the
# misses is not enough: a process whose connection broke loses its stats, and
# with them the misses that would have shown the entry was never stored.
check_warm() { # what hits misses <variable holding the number of compiles>
    local compiles=${!4}
    [ "$3" = 0 ] || fail "$1 warm: $3 misses on a warm cache"
    [ "$2" = "$compiles" ] || fail "$1 warm: $2 hits, the cold build compiled $compiles"
}

printf 'name\tmode\tstate\trep\tseconds\thits\tmisses\twrite_errors\n' >"$results"
for rep in $(seq "$reps"); do
    for state in cold warm; do
        for mode in server client; do
            # Alternate which binary goes first.
            order=(baseline candidate)
            [ $((rep % 2)) = 0 ] && order=(candidate baseline)
            for name in "${order[@]}"; do
                IFS=$'\t' read -r secs hits misses werr < <(build "$name" "$mode" "$state")
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$mode" "$state" "$rep" "$secs" "$hits" "$misses" "$werr" >>"$results"
                echo "$name $mode $state #$rep: ${secs}s hits=$(sum "$hits") misses=$(sum "$misses") write_errors=$werr" >&2
                [ "$werr" = 0 ] || fail "$name $mode $state: $werr cache write errors"
                # Server mode counts every compile, which client-side mode may not.
                if [ "$state" = cold ] && [ "$mode" = server ]; then
                    eval "compiles_$name=$(sum "$misses")"
                elif [ "$state" = warm ]; then
                    check_warm "$name $mode" "$(sum "$hits")" "$(sum "$misses")" "compiles_$name"
                fi
            done
        done
    done
done

# Client-side and server mode see the same compiles, so they have to count the
# same hits and misses per language.
for name in baseline candidate; do
    for state in cold warm; do
        s=$(awk -F'\t' -v n=$name -v st=$state '$1==n && $2=="server" && $3==st && $4==1 {print $6 " " $7}' "$results")
        c=$(awk -F'\t' -v n=$name -v st=$state '$1==n && $2=="client" && $3==st && $4==1 {print $6 " " $7}' "$results")
        [ "$s" = "$c" ] || fail "$name $state: server counted $s, client-side counted $c"
    done
done

# Entries over the frame limit, in client-side mode: stored cold, hit warm. Only
# with --large-entries: a candidate without a way to pass them outside of a
# message loses them.
if [ -n "$large_entries" ]; then
    IFS=$'\t' read -r _ _ _ werr < <(build candidate client cold "$SMALL_FRAME_LENGTH")
    IFS=$'\t' read -r _ hits misses _ < <(build candidate client warm "$SMALL_FRAME_LENGTH")
    [ "$werr" = 0 ] || fail "candidate client-side, frame limit $SMALL_FRAME_LENGTH: $werr cache write errors"
    check_warm "candidate client-side, frame limit $SMALL_FRAME_LENGTH" "$(sum "$hits")" "$(sum "$misses")" compiles_candidate
fi

median() { sort -n | awk '{a[NR]=$1} END {print (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2}'; }
median_time() { awk -F'\t' -v n=$1 -v m=$2 -v st=$3 '$1==n && $2==m && $3==st {print $5}' "$results" | median; }

report() {
    echo "### sccache end-to-end: FFmpeg $FFMPEG_VERSION, make -j$jobs, $reps runs"
    echo
    echo "| mode | cache | baseline (s) | candidate (s) | candidate / baseline |"
    echo "|---|---|---|---|---|"
    for mode in server client; do
        for state in cold warm; do
            b=$(median_time baseline $mode $state) c=$(median_time candidate $mode $state)
            r=$(echo "scale=3; $c / $b" | bc)
            printf '| %s | %s | %.2f | %.2f | %.2f |\n' "$mode" "$state" "$b" "$c" "$r"
            if [ "$(echo "scale=3; $r > 1 + $max_regression / 100" | bc)" = 1 ]; then
                fail "candidate $mode $state is ${r}x the baseline, over the ${max_regression}% allowed"
            fi
        done
    done
    echo
    for name in baseline candidate; do
        for state in cold warm; do
            s=$(median_time $name server $state) c=$(median_time $name client $state)
            printf -- '- %s, %s: client-side / server = %.2f\n' "$name" "$state" "$(echo "scale=3; $c / $s" | bc)"
        done
    done
    echo
    if [ -s "$failures" ]; then
        echo "**Failed checks:**"
        sed 's/^/- /' "$failures"
    else
        echo "All checks passed."
    fi
}

# Leave only the configured source behind, which CI caches.
make -C "$src" clean >/dev/null 2>&1 || true

report >"$work/report.md"
cat "$work/report.md" >>"${GITHUB_STEP_SUMMARY:-/dev/stdout}"
[ ! -s "$failures" ]
