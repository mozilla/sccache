#!/usr/bin/env bash
#
# Try out `sccache --monitor` against a throwaway server.
#
# Builds sccache with the `monitor` feature, starts a server on its own port
# with its own cache directory, generates a trickle of compilations in the
# background so the dashboard has something to plot, and opens the monitor.
#
# Everything is torn down on exit; your real sccache server and cache are left
# alone. Press `q` in the dashboard to quit.
#
# Usage: scripts/try-monitor.sh [--release] [--port N] [--interval SECS]

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

# Job control, so that the background loop below becomes the leader of its own
# process group and `cleanup` can tear the whole thing down at once.
set -m
(
    cd "$WORK"
    i=0
    while true; do
        i=$((i + 1))
        printf '#include <stdio.h>\nint f%d(void) { return %d; }\n' "$i" "$i" > "miss$i.c"
        "$SCCACHE" "$CC" -c "miss$i.c" -o "miss$i.o" >/dev/null 2>&1
        rm -f "miss$i.c" "miss$i.o"
        # Two cache hits per miss.
        "$SCCACHE" "$CC" -c hit.c -o hit.o >/dev/null 2>&1
        "$SCCACHE" "$CC" -c hit.c -o hit.o >/dev/null 2>&1
        if [ $((i % 7)) -eq 0 ]; then
            # Non-cacheable call: shows up in the Reasons pane.
            "$SCCACHE" "$CC" -E hit.c >/dev/null 2>&1
        fi
        if [ $((i % 11)) -eq 0 ]; then
            # Failed compilation.
            "$SCCACHE" "$CC" -c broken.c -o broken.o >/dev/null 2>&1
        fi
        sleep 0.3
    done
) &
LOAD_PID=$!
# Back to the default, so the monitor keeps the terminal's foreground group.
set +m

echo "==> opening the dashboard (q to quit, ? for help, 1-5 for panes)"
sleep 1
"$SCCACHE" --monitor --monitor-interval "$INTERVAL"
