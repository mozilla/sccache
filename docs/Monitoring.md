# Monitoring a running server

`sccache --monitor` attaches a terminal dashboard to a running sccache server
and refreshes it while you build. It is an ordinary client — it does not need
any cooperation from the server beyond the existing `GetStats`, `ZeroStats` and
`DistStatus` requests — so it can be started and stopped at any point in a
build, and it can watch a server that was started by something else.

The dashboard is built with [Ratatui](https://ratatui.rs) and is behind the
`monitor` cargo feature, which is not enabled by default:

```
cargo build --release --features monitor
```

Without that feature, `sccache --monitor` reports that the UI was not compiled
in.

## Usage

```
sccache --monitor                          # poll once a second
sccache --monitor --monitor-interval 0.25  # poll four times a second
```

`--monitor-interval` accepts 0.2 to 60 seconds; anything outside that range is
rejected rather than silently clamped.

The monitor connects to the same address as every other sccache client, so
`SCCACHE_SERVER_PORT` and `SCCACHE_SERVER_UDS` are honoured:

```
env SCCACHE_SERVER_UDS=$HOME/sccache.sock sccache --monitor
```

If no server is running, the monitor does *not* start one: it shows
`disconnected` and attaches as soon as a server appears. It also survives the
server being stopped and restarted underneath it.

## Panes

| Pane | Contents |
| --- | --- |
| Overview | Overall hit rate, cache fill, per-second rates, the full counter list, and average cache-write / compile / cache-read-hit times. Sparklines plot compile requests, hits and misses per second. |
| Languages | Hits, misses, hit rate and errors per language, with a hit/miss bar. Press `a` for the per-compiler (advanced) breakdown. |
| Reasons | Why compilations were not cached, and which distributed servers ran compilations, each with its share of the total. |
| Cache | Cache location, size against the configured maximum, base directories, preprocessor cache mode, and a per-level table when [multi-level caching](MultiLevel.md) is enabled. A local disk cache also gets a used/free pie, how fast it is filling, when it will be full at that rate, and a plot of the growth; a remote one, whose size and ceiling are usually unknown, keeps a one-line gauge. Once the LRU starts trimming the cache at its ceiling, the projection gives way to a count of how much has been evicted. |
| Dist | Distributed-compilation status: scheduler URL, scheduler status, and failed distributed compilations. Only polled while this pane is open, since it can involve a round trip to the scheduler. |
| Logs | The server's log file, followed as it grows, coloured by level and filterable. See [Following the log](#following-the-log). |

## Keys

| Key | Action |
| --- | --- |
| `q`, `Esc`, `Ctrl-C`, `Ctrl-D` | quit |
| `1`–`6`, `Tab`, `←`/`→`, `h`/`l` | switch pane |
| `a` | per-compiler instead of per-language counts |
| `r` | poll now, even while paused |
| `p`, `Space` | pause / resume polling |
| `+` / `-` | double / halve the poll interval (200 ms to 60 s) |
| `z` `z` | zero the server's statistics; the second `z` confirms, any other key cancels |
| `?`, `F1` | help |

In the Logs pane:

| Key | Action |
| --- | --- |
| `↑`/`↓`, `k`/`j`, `PgUp`/`PgDn` | scroll, which stops following the tail |
| `Home` / `End` | oldest line held / back to following the tail |
| `f` | follow the tail, or stop |
| `e` | cycle the level filter: everything, then `DEBUG`, `INFO`, `WARN`, `ERROR` and worse |

## Following the log

The server has no logging RPC: it logs by having its stderr redirected to the
file named by `SCCACHE_ERROR_LOG`, with `SCCACHE_LOG` setting the verbosity (see
[Debugging](../README.md#debugging)). So start the server with a log and point
the monitor at it:

```
SCCACHE_ERROR_LOG=/tmp/sccache.log SCCACHE_LOG=debug sccache --start-server
sccache --monitor --monitor-log /tmp/sccache.log
```

`--monitor-log` defaults to `$SCCACHE_ERROR_LOG`, so exporting that variable in
the shell you run the monitor from is enough. Without either, the Logs pane
explains this rather than sitting empty.

The file is followed the way `tail -f` does: the monitor reads the last 64 KiB
at startup and appends what arrives after that, keeping the most recent 10,000
lines to scroll back through. It does not need the file to exist yet — it will
pick it up when it appears — and if the file is truncated or replaced it starts
over rather than going quiet. Lines are coloured by level, and a line with no
level of its own, such as the middle of a panic backtrace, keeps the colour of
the line above it. Any colour codes already in the file are stripped: logging is
set up before the daemon redirects its stderr, so a server started from a
terminal writes the escapes env_logger chose for a tty into the log.

Note that the monitor silences *its own* logging while the dashboard is up.
Otherwise a `SCCACHE_LOG` exported for the whole shell would have this process
writing log lines onto the terminal it is drawing the dashboard on.

## How the numbers are derived

The server only exposes cumulative counters, so per-second rates are computed
by diffing consecutive samples. A counter going backwards means the statistics
were zeroed or the server restarted, and the rate history is cleared rather
than showing a spike. Rates are therefore blank until a second sample arrives.

## Effect on the server

Each poll is a normal request, and any request resets the server's
idle-shutdown timer. A server that is being monitored will not shut down on its
own after `SCCACHE_IDLE_TIMEOUT`; press `p` to pause polling if you want the
idle timeout to apply.

The monitor connects for each poll and disconnects immediately afterwards. It
deliberately does not hold the socket open, because the server waits for
connected clients to disappear before exiting, and a persistent connection
would delay `sccache --stop-server` by the server's whole drain timeout.
