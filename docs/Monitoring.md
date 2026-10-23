# Monitoring a running server

`sccache --monitor` attaches a terminal dashboard to a running sccache server
and refreshes it while you build. It is an ordinary client of the server, so it
can be started and stopped at any point in a build, and it can watch a server
that was started by something else.

The dashboard is behind the `monitor` cargo feature, which is part of `all`
but not of the default build:

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

`--monitor-interval` accepts 0.2 to 60 seconds.

The monitor connects to the same address as every other sccache client, so
`SCCACHE_SERVER_PORT` and `SCCACHE_SERVER_UDS` are honored:

```
env SCCACHE_SERVER_UDS=$HOME/sccache.sock sccache --monitor
```

If no server is running, the monitor does *not* start one: it shows
`disconnected` and attaches as soon as a server appears.

Press `?` in the dashboard for the key bindings.

## Effect on the server

Each poll is a normal request, and any request resets the server's
idle-shutdown timer. A server that is being monitored will not shut down on its
own after `SCCACHE_IDLE_TIMEOUT`; pause polling if you want the idle timeout to
apply.
