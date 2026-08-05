#!/usr/bin/env bash
#
# Try out `sccache --monitor` against a throwaway server.
#
# Builds sccache with the `monitor` feature, starts a server on its own port
# with its own cache directory, compiles in bursts in the background so the
# dashboard has something to plot, and opens the monitor.
#
# Everything is torn down on exit; your real sccache server and cache are left
# alone. Press `q` in the dashboard to quit.
#
# Usage: scripts/try-monitor.sh [--release] [--port N] [--interval SECS]
#        JOBS=8 scripts/try-monitor.sh    # compile 8 files at a time

set -euo pipefail

PROFILE=debug
PORT=4299
INTERVAL=0.5

while [ $# -gt 0 ]; do
    case "$1" in
        --release) PROFILE=release; shift ;;
        --port) PORT="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        # Print the header comment, i.e. everything between the shebang and the
        # first blank line, rather than a hard-coded line range.
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.."
ROOT=$(pwd)

echo "==> building sccache --features monitor ($PROFILE)"
if [ "$PROFILE" = release ]; then
    cargo build --release --features monitor
else
    cargo build --features monitor
fi
SCCACHE="$ROOT/target/$PROFILE/sccache"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sccache-monitor-demo.XXXXXX")
export SCCACHE_DIR="$WORK/cache"
export SCCACHE_SERVER_PORT="$PORT"
export SCCACHE_CACHE_SIZE=200M
# Keep the server around even while the load generator is idle.
export SCCACHE_IDLE_TIMEOUT=0
unset SCCACHE_SERVER_UDS

LOAD_PID=

cleanup() {
    set +e
    if [ -n "$LOAD_PID" ]; then
        # The load generator runs in its own process group (see `set -m`
        # below), so signal the group: killing just the subshell would leave a
        # compile it had already started running.
        kill -- -"$LOAD_PID" 2>/dev/null || kill "$LOAD_PID" 2>/dev/null
    fi
    "$SCCACHE" --stop-server >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

CC=${CC:-cc}
if ! command -v "$CC" >/dev/null; then
    echo "no C compiler found (set CC to override)" >&2
    exit 1
fi

echo "==> starting a server on 127.0.0.1:$PORT with cache in $SCCACHE_DIR"
"$SCCACHE" --start-server

# Background load: a mix of misses (fresh sources), hits (recompiling the same
# source), a non-cacheable call (-E) and a compile failure, so that every pane
# of the dashboard has data in it.
cat > "$WORK/hit.c" <<'EOF'
#include <stdio.h>
int hit(void) { return 42; }
EOF
printf 'int broken(void) {\n' > "$WORK/broken.c"

# Compile several files at a time, so the rates are large enough to see. Cache
# hits are quick, so a burst of them makes a clear spike.
JOBS=${JOBS:-4}

# Job control, so that the background loop below becomes the leader of its own
# process group and `cleanup` can tear the whole thing down at once.
set -m
(
    # A failing compile and a `-E` call are part of the demo, and the sccache
    # calls run under `wait`; none of that should take the loop down, so drop
    # the errexit and pipefail inherited from above.
    set +e +o pipefail
    cd "$WORK"
    i=0
    while true; do
        i=$((i + 1))

        # Burst of misses: fresh sources, so each one is compiled and written to
        # the cache.
        for j in $(seq 1 "$JOBS"); do
            printf '#include <stdio.h>\nint f%d_%d(void) { return %d; }\n' \
                "$i" "$j" "$i" > "miss$i-$j.c"
            "$SCCACHE" "$CC" -c "miss$i-$j.c" -o "miss$i-$j.o" >/dev/null 2>&1 &
        done
        wait
        rm -f "miss$i-"*.c "miss$i-"*.o

        # Burst of hits: the same source over and over, which is much faster and
        # shows up as a taller, narrower spike than the misses.
        for j in $(seq 1 $((JOBS * 3))); do
            "$SCCACHE" "$CC" -c hit.c -o "hit$j.o" >/dev/null 2>&1 &
        done
        wait
        rm -f hit*.o

        if [ $((i % 3)) -eq 0 ]; then
            # Non-cacheable call: shows up in the Reasons pane.
            "$SCCACHE" "$CC" -E hit.c >/dev/null 2>&1
        fi
        if [ $((i % 5)) -eq 0 ]; then
            # Failed compilation.
            "$SCCACHE" "$CC" -c broken.c -o broken.o >/dev/null 2>&1
        fi

        # Idle beat, so the plots have troughs as well as peaks instead of a
        # flat line at the top.
        sleep 2
    done
) &
LOAD_PID=$!
# Back to the default, so the monitor keeps the terminal's foreground group.
set +m

echo "==> opening the dashboard (q to quit, ? for help, 1-5 for panes)"
sleep 1
"$SCCACHE" --monitor --monitor-interval "$INTERVAL"
