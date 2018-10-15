sccache distributed compilation quickstart
==========================================

This is a quick start guide to getting distributed compilation working with sccache. This guide currently only covers Linux clients, although macOS and Windows clients are supported.

Get sccache binaries
====================

Either download pre-built sccache binaries (not currently available), or build sccache locally with the `dist-client` and `dist-server` features enabled:
```
cargo build --release --features="dist-client dist-server"
```

The `target/release/sccache` binary will be used on the client, and the `target/release/sccache-dist` binary will be used on the scheduler and build server.

Configure a scheduler
=====================

The scheduler is a daemon that manages compile request from clients and parcels them out to build servers. You only need one of these per sccache setup. Currently only Linux is supported for running the scheduler.

Create a scheduler.conf file to configure client/server authentication. A minimal example looks like:
```toml
[client_auth]
type = "token"
token = "my client token"

[server_auth]
type = "token"
token = "my server token"
```

Start the scheduler by running:
```
sccache-dist scheduler --config scheduler.conf
```

If the scheduler fails to start you may need to set `RUST_LOG=trace` when starting it to get useful diagnostics.

Configure a build server
========================

A build server communicates with the scheduler and executes compiles requested by clients. Only Linux is supported for running a build server, but executing cross-compile requests from macOS/Windows clients is supported.

The build server requires [bubblewrap](https://github.com/projectatomic/bubblewrap) to sandbox execution, at least version 0.3.0. On Ubuntu 18.10+ you can `apt install bubblewrap` to install it. If you build from source you will need to first install your distro's equivalent of the `libcap-dev` package.

Create a server.conf file to configure authentication, storage locations, network addresses and the path to bubblewrap. A minimal example looks like:
```toml
# This is where client toolchains will be stored.
cache_dir = "/tmp/toolchains"
# The maximum size of the toolchain cache, in bytes.
# If unspecified the default is 10GB.
# toolchain_cache_size = 10737418240
# An IP address and port on which clients can connect to this builder.
# NOTE: you must use port 10501 here!
public_addr = "192.168.1.1:10501"
# The IP address of the scheduler.
scheduler_addr = "192.168.1.1"

[builder]
type = "overlay"
# The directory under which a sandboxed filesystem will be created for builds.
build_dir = "/tmp/build"
# The path to the bubblewrap `bwrap` binary.
bwrap_path = "/usr/bin/bwrap"

[scheduler_auth]
type = "token"
# This should match the `server_auth` section of the scheduler config.
token = "my server token"
```

Due to bubblewrap requirements currently the build server *must* be run as root. Start the build server by running:
```
sudo sccache-dist server --config server.conf
```

As with the scheduler, if the build server fails to start you may need to set `RUST_LOG=trace` to get useful diagnostics.

Configure a client
==================

A client uses `sccache` to wrap compile commands, communicates with the scheduler to find available build servers, and communicates with build servers to execute the compiles and receive the results.

Clients require the `icecc-create-env` script, which is part of `icecream` for packaging toolchains. You can install icecream to get this script (`apt install icecc` on Ubuntu), or download it from the git repository and place it in your `PATH`: `curl https://raw.githubusercontent.com/icecc/icecream/master/client/icecc-create-env.in > icecc-create-env && chmod +x icecc-create-env`.

Create a client config file in `~/.config/sccache/config`. A minimal example looks like:
```toml
[dist]
# The IP address of the scheduler.
scheduler_addr = "192.168.1.1"
# A directory in which toolchain information will be cached.
cache_dir = "/tmp/toolchains"
# Used for mapping local toolchains to remote cross-compile toolchains. Empty in
# this example where the client and build server are both Linux.
toolchains = []
# Size of the local toolchain cache, in bytes.
toolchain_cache_size = 1073741824

[dist.auth]
type = "token"
# This should match the `client_auth` section of the scheduler config.
token = "my client token"
```
