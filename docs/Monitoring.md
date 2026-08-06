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

## Keys

| Key | Action |
| --- | --- |
| `q`, `Esc`, `Ctrl-C`, `Ctrl-D` | quit |
| `1`–`5`, `Tab`, `←`/`→`, `h`/`l` | switch pane |
| `a` | per-compiler instead of per-language counts |
| `r` | poll now, even while paused |
| `p`, `Space` | pause / resume polling |
| `+` / `-` | double / halve the poll interval (200 ms to 60 s) |
| `z` `z` | zero the server's statistics; the second `z` confirms, any other key cancels |
| `?`, `F1` | help |

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
