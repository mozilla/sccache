[![Build Status](https://travis-ci.org/mozilla/sccache.svg?branch=master)](https://travis-ci.org/mozilla/sccache) [![Build status](https://ci.appveyor.com/api/projects/status/h4yqo430634pmfmt?svg=true)](https://ci.appveyor.com/project/luser/sccache2)

sccache - Shared Compilation Cache
==================================

Sccache is a [ccache](https://ccache.samba.org/)-like tool. It is used as a compiler wrapper and avoids compilation when possible, storing a cache in a remote storage using the Amazon Simple Cloud Storage Service (S3) API, the Google Cloud Storage (GCS) API, or Redis.

Sccache now includes [experimental Rust support](docs/Rust.md).

It works as a client-server. The client spawns a server if one is not running already, and sends the wrapped command line as a request to the server, which then does the work and returns stdout/stderr for the job.  The client-server model allows the server to be more efficient in its handling of the remote storage.

Sccache can also be used with local storage instead of remote.

---

Table of Contents (ToC)
======================

* [Build Requirements](#build-requirements)
* [Build](#build)
* [Installation](#installation)
* [Usage](#usage)
* [Storage Options](#storage-options)
* [Debugging](#debugging)
* [Interaction with GNU `make` jobserver](#interaction-with-gnu-make-jobserver)
* [Known Caveats](#known-caveats)

---

Build Requirements
------------------

Sccache is a [Rust](https://www.rust-lang.org/) program. Building it requires `cargo` (and thus `rustc`). sccache currently requires **Rust 1.21**.

We recommend you install Rust via [Rustup](https://rustup.rs/). The generated binaries can be built so that they are very portable, see [scripts/build-release.sh](scripts/build-release.sh). By default `sccache` supports a local disk cache. To build `sccache` with support for `S3` and/or `Redis` cache backends, add `--features=all` or select a specific feature by passing `s3`, `gcs`, and/or `redis`. Refer the [Cargo Documentation](http://doc.crates.io/manifest.html#the-features-section) for details.

## Build

> $ cargo build [--features=all|redis|s3|gcs] [--release]

## Installation

> $ cargo install

---

Usage
-----

Running sccache is like running ccache: wrap your compilation commands with it, like so:

> $ sccache gcc -o foo.o -c foo.c

or use it with rust, like so:

> $ RUSTC_WRAPPER=[path to sccache] cargo build

Sccache (tries to) support gcc, clang and MSVC. If you don't [specify otherwise](#storage-options), sccache will use a local disk cache.

You can run `sccache --start-server` to start the background server process without performing any compilation.

You can run `sccache --stop-server` to terminate the server. It will terminate after 10 minutes of inactivity.

Running `sccache --show-stats` will print a summary of cache statistics.

Some notes about using `sccache` with [Jenkins](https://jenkins.io) are [here](docs/Jenkins.md).

---

Storage Options
---------------

Sccache defaults to using local disk storage. You can set the `SCCACHE_DIR` environment variable to change the disk cache location. By default it will use a sensible location for the current platform: `~/.cache/sccache` on Linux, `%LOCALAPPDATA%\Mozilla\sccache` on Windows, and `~/Library/Caches/sccache` on OS X.

If you want to use S3 storage for the sccache cache, you need to set the `SCCACHE_BUCKET` environment variable to the name of the S3 bucket to use. You can use `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to set the S3 credentials and if you need to override the default endpoint you can set `SCCACHE_ENDPOINT`. To connect to a minio storage for example you can set `SCCACHE_ENDPOINT=<ip>:<port>`.

Set `SCCACHE_REDIS` to a [Redis](https://redis.io/) url in format `redis://[:<passwd>@]<hostname>[:port][/<db>]` to store the cache in a Redis instance.

Set `SCCACHE_MEMCACHED` to a [Memcached](https://memcached.org/) url in format `tcp://<hostname>:<port> ...` to store the cache in a Memcached instance.

To use [Google Cloud Storage](https://cloud.google.com/storage/), you need to set the `SCCACHE_GCS_BUCKET` environment variable to the name of the GCS bucket.
If you're using authentication, set `SCCACHE_GCS_KEY_PATH` to the location of your JSON service account credentials.
By default, SCCACHE on GCS will be read-only. To change this, set `SCCACHE_GCS_RW_MODE` to either `READ_ONLY` or `READ_WRITE`.

*Important:* The environment variables are only taken into account when the server starts, so only on the first run.

---

Debugging
---------

You can run the server manually in foreground mode by running `SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 sccache`, and send logging to stderr by setting the `RUST_LOG` environment variable, the format of which is described in more detail in the [env_logger](https://docs.rs/env_logger/0.5.3/env_logger/#enabling-logging) documentation.

Alternately, you can set the `SCCACHE_ERROR_LOG` environment variable to a path and set `RUST_LOG` to get the server process to redirect its logging there (including the output of unhandled panics, since the server sets `RUST_BACKTRACE=1` internally).

---

Interaction with GNU `make` jobserver
-------------------------------------

Sccache provides support for a [GNU make jobserver](https://www.gnu.org/software/make/manual/html_node/Job-Slots.html). When the server is started from a process that provides a jobserver, sccache will use that jobserver and provide it to any processes it spawns. (If you are running sccache from a GNU make recipe, you will need to prefix the command with `+` to get this behavior.) If the sccache server is started without a jobserver present it will create its own with the number of slots equal to the number of available CPU cores.

This is most useful when using sccache for Rust compilation, as rustc supports using a jobserver for parallel codegen, so this ensures that rustc will not overwhelm the system with codegen tasks. Cargo implements its own jobserver ([see the information on `NUM_JOBS` in the cargo documentation](https://doc.rust-lang.org/stable/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts)) for rustc to use, so using sccache for Rust compilation in cargo via `RUSTC_WRAPPER` should do the right thing automatically.

---

Known caveats
-------------

(and possible future improvements)

* Sccache doesn't try to be smart about the command line arguments it uses when computing a key for a given compilation result (like skipping preprocessor-specific arguments)
* It doesn't support all kinds of compiler flags, and is certainly broken with a few of them. Really only the flags used during Firefox builds have been tested.
* It doesn't support ccache's direct mode.
* [It doesn't support an option like `CCACHE_BASEDIR`](https://github.com/mozilla/sccache/issues/35).
