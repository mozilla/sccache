[![Build Status](https://travis-ci.org/mozilla/sccache.svg?branch=master)](https://travis-ci.org/mozilla/sccache) [![Build status](https://ci.appveyor.com/api/projects/status/h4yqo430634pmfmt?svg=true)](https://ci.appveyor.com/project/luser/sccache2)

sccache - Shared Compilation Cache
==================================

Sccache is a [ccache](https://ccache.samba.org/)-like tool. It is used as a compiler wrapper and avoids compilation when possible, storing a cache in a remote storage using the S3 API.

It works as a client-server. The client spawns a server if one is not running already, and sends the wrapped command line as a request to the server, which then does the work and returns stdout/stderr for the job.  The client-server model allows the server to be more efficient in its handling of the remote storage.

Sccache can also be used with local storage instead of remote.


Requirements
------------

sccache is a [Rust](https://www.rust-lang.org/) program. Building it requires `cargo` (and thus `rustc`). sccache currently requires **Rust 1.13**.

We recommend you install Rust via [Rustup](https://rustup.rs/). The generated binaries can be built so that they are very portable, see [scripts/build-release.sh](scripts/build-release.sh).

## Build

> $ cargo build [--release]

## Installation

> $ cargo install

Usage
-----

Running sccache is like running ccache: wrap your compilation commands with it, like so:

> $ sccache gcc -o foo.o -c foo.c

Sccache (tries to) support gcc, clang and MSVC. If you don't [specify otherwise](#storage-options), sccache will use a local disk cache.

You can run `sccache --start-server` to start the background server process without performing any compilation.

You can run `sccache --stop-server` to terminate the server. It will terminate after 10 minutes of inactivity.

Running `sccache --show-stats` will print a summary of cache statistics.

Storage Options
---------------

sccache defaults to using local disk storage. You can set the `SCCACHE_DIR` environment variable to change the disk cache location. By default it will use a sensible location for the current platform: `~/.cache/sccache` on Linux, `%LOCALAPPDATA%\Mozilla\sccache` on Windows, `~/Library/Caches/sccache` on OS X.

If you want to use S3 storage for the sccache cache, you need to set the `SCCACHE_BUCKET` environment variable to the name of the S3 bucket to use.

The environment variables are only taken into account when the server starts, so only on the first run.

Debugging
---------

You can set the `SCCACHE_LOG_LEVEL` environment variable to `debug` or `trace` (not recommended, it's *very verbose*) to cause sccache to output more fine grained logging about what it is doing. A log file named `sccache.log` will be output in the current working directory whenever sccache is invoked.

Alternately, you can run the server manually in foreground mode by running `SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 sccache`, and send logging to stderr by setting the `RUST_LOG` environment variable, the format of which is described in more detail in the [env_logger](http://burntsushi.net/rustdoc/env_logger/index.html#enabling-logging) documentation.

You can set the `SCCACHE_ERROR_LOG` environment variable to a path to cause the server process to redirect its standard error output there, in order to capture the output of unhandled panics. (The server sets `RUST_BACKTRACE=1` internally.)


Known caveats
-------------

(and possible future improvements)

* Sccache doesn't try to be smart about the command line arguments it uses when computing a key for a given compilation result (like skipping preprocessor-specific arguments)
* It doesn't support all kinds of compiler flags, and is certainly broken with a few of them. Really only the flags used during Firefox builds have been tested.
* It doesn't support ccache's direct mode.
* [It doesn't support an option like `CCACHE_BASEDIR`](https://github.com/mozilla/sccache/issues/35).
