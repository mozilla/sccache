[![Build Status](https://github.com/paritytech/cachepot/workflows/ci/badge.svg)](https://github.com/paritytech/cachepot/actions?query=workflow%3Aci)
[![rust 1.43.0+ badge](https://img.shields.io/badge/rust-1.43.0+-93450a.svg)](https://blog.rust-lang.org/2020/04/23/Rust-1.43.0.html)

![cachepot maskot image](./cachepot.png)

cachepot - Shared Compilation Cache
==================================

cachepot is a [ccache](https://ccache.dev/)-like compiler caching tool.
It is used as a compiler wrapper and avoids compilation when possible, storing cached results either on [local disk](#local) or in one of [several cloud storage backends](#storage-options).

It's also a fork of [sccache](https://github.com/mozilla/sccache) with improved security properties and improvements all-around the code base.
We upstream as much as we can back upstream, but the goals might not be a 100% match.

cachepot includes support for caching the compilation of C/C++ code, [Rust](docs/Rust.md), as well as NVIDIA's CUDA using [nvcc](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html).

cachepot also provides [icecream](https://github.com/icecc/icecream)-style distributed compilation (automatic packaging of local toolchains) for all supported compilers (including Rust). The distributed compilation system includes several security features that icecream lacks such as authentication, transport layer encryption, and sandboxed compiler execution on build servers. See [the distributed quickstart](docs/DistributedQuickstart.md) guide for more information.

---

Table of Contents (ToC)
======================

* [Installation](#installation)
* [Build Requirements](#build-requirements)
* [Build](#build)
* [Usage](#usage)
* [Storage Options](#storage-options)
  * [Local](#local)
  * [S3](#s3)
  * [Redis](#redis)
  * [Memcached](#memcached)
  * [Google Cloud Storage](#google-cloud-storage)
  * [Azure](#azure)
* [Debugging](#debugging)
* [Interaction with GNU `make` jobserver](#interaction-with-gnu-make-jobserver)
* [Known Caveats](#known-caveats)

---

## Installation

There are prebuilt x86-64 binaries available for Windows, Linux (a portable binary compiled against musl), and macOS [on the releases page](https://github.com/paritytech/cachepot/releases/latest). Several package managers also include cachepot packages, you can install the latest release from source using cargo, or build directly from a source checkout.

### macOS

On macOS cachepot can be installed via [Homebrew](https://brew.sh/):

```bash
brew install cachepot
```

### Windows

On Windows, cachepot can be installed via [scoop](https://scoop.sh/):

```
scoop install cachepot
```

### Via cargo

If you have a Rust toolchain installed you can install cachepot using cargo. **Note that this will compile cachepot from source which is fairly resource-intensive. For CI purposes you should use prebuilt binary packages.**


```bash
cargo install cachepot
```

---

Usage
-----

Running cachepot is like running ccache: prefix your compilation commands with it, like so:

```bash
cachepot gcc -o foo.o -c foo.c
```

If you want to use cachepot for caching Rust builds you can define `build.rustc-wrapper` in the
[cargo configuration file](https://doc.rust-lang.org/cargo/reference/config.html).  For example, you can set it globally
in `$HOME/.cargo/config` by adding:

```toml
[build]
rustc-wrapper = "/path/to/cachepot"
```

Note that you need to use cargo 1.40 or newer for this to work.

Alternatively you can use the environment variable `RUSTC_WRAPPER`:

```sh
RUSTC_WRAPPER=/path/to/cachepot cargo build
```

cachepot supports gcc, clang, MSVC, rustc, NVCC, and [Wind River's diab compiler](https://www.windriver.com/products/development-tools/#diab_compiler).

If you don't [specify otherwise](#storage-options), cachepot will use a local disk cache.

cachepot works using a client-server model, where the server runs locally on the same machine as the client. The client-server model allows the server to be more efficient by keeping some state in memory. The cachepot command will spawn a server process if one is not already running, or you can run `cachepot --start-server` to start the background server process without performing any compilation.

You can run `cachepot --stop-server` to terminate the server. It will also terminate after (by default) 10 minutes of inactivity.

Running `cachepot --show-stats` will print a summary of cache statistics.

Some notes about using `cachepot` with [Jenkins exist](docs/Jenkins.md).

To use cachepot with cmake, provide the following command line arguments to `cmake >= 3.4`:

```cmake
-DCMAKE_C_COMPILER_LAUNCHER=cachepot
-DCMAKE_CXX_COMPILER_LAUNCHER=cachepot
```

---

Build Requirements
------------------

cachepot is a [Rust](https://www.rust-lang.org/) program. Building it requires `cargo` (and thus `rustc`). cachepot currently requires **Rust 1.43.0**. We recommend you install Rust via [Rustup](https://rustup.rs/).

Build
-----

If you are building cachepot for non-development purposes make sure you use `cargo build --release` to get optimized binaries:

```bash
cargo build --release [--no-default-features --features=s3|redis|gcs|memcached|azure]
```

By default, `cachepot` builds with support for all storage backends, but individual backends may be disabled by resetting the list of features and enabling all the other backends. Refer the [Cargo Documentation](http://doc.crates.io/manifest.html#the-features-section) for details on how to select features with Cargo.

#### Linux

No native dependencies.

Build with `cargo` and use `ldd` to check that the resulting binary does not depend on OpenSSL anymore.

#### macOS

No native dependencies.

Build with `cargo` and use `otool -L` to check that the resulting binary does not depend on OpenSSL anymore.

#### Windows

On Windows, the binary might also depend on a few MSVC CRT DLLs that are not available on older Windows versions.

It is possible to statically link against the CRT using a `.cargo/config` file with the following contents.

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-Ctarget-feature=+crt-static"]
```

Build with `cargo` and use `dumpbin /dependents` to check that the resulting binary does not depend on MSVC CRT DLLs anymore.

---

Storage Options
---------------

### Local

cachepot defaults to using local disk storage. You can set the `CACHEPOT_DIR` environment variable to change the disk cache location. By default it will use a sensible location for the current platform: `~/.cache/cachepot` on Linux, `%LOCALAPPDATA%\Parity\cachepot` on Windows, and `~/Library/Caches/Parity.cachepot` on MacOS.

The default cache size is 10 gigabytes. To change this, set `CACHEPOT_CACHE_SIZE`, for example `CACHEPOT_CACHE_SIZE="1G"`.

### S3
If you want to use S3 storage for the cachepot cache, you need to set the `CACHEPOT_BUCKET` environment variable to the name of the S3 bucket to use.

You can use `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to set the S3 credentials.  Alternately, you can set `AWS_IAM_CREDENTIALS_URL` to a URL that returns credentials in the format supported by the [EC2 metadata service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials), and credentials will be fetched from that location as needed. In the absence of either of these options, credentials for the instance's IAM role will be fetched from the EC2 metadata service directly.

If you need to override the default endpoint you can set `CACHEPOT_ENDPOINT`. To connect to a minio storage for example you can set `CACHEPOT_ENDPOINT=<ip>:<port>`. If your endpoint requires TLS, set `CACHEPOT_S3_USE_SSL=true`.

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the S3 bucket, effectively creating a scope. To do that use the `CACHEPOT_S3_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.


### Redis
Set `CACHEPOT_REDIS` to a [Redis](https://redis.io/) url in format `redis://[:<passwd>@]<hostname>[:port][/<db>]` to store the cache in a Redis instance. Redis can be configured as a LRU (least recently used) cache with a fixed maximum cache size. Set `maxmemory` and `maxmemory-policy` according to the [Redis documentation](https://redis.io/topics/lru-cache). The `allkeys-lru` policy which discards the *least recently accessed or modified* key fits well for the cachepot use case.

### Memcached
Set `CACHEPOT_MEMCACHED` to a [Memcached](https://memcached.org/) url in format `tcp://<hostname>:<port> ...` to store the cache in a Memcached instance.

### Google Cloud Storage
To use [Google Cloud Storage](https://cloud.google.com/storage/), you need to set the `CACHEPOT_GCS_BUCKET` environment variable to the name of the GCS bucket.
If you're using authentication, either set `CACHEPOT_GCS_KEY_PATH` to the location of your JSON service account credentials or `CACHEPOT_GCS_CREDENTIALS_URL` with
a URL that returns the oauth token.
By default, CACHEPOT on GCS will be read-only. To change this, set `CACHEPOT_GCS_RW_MODE` to either `READ_ONLY` or `READ_WRITE`.

### Azure
To use Azure Blob Storage, you'll need your Azure connection string and an _existing_ Blob Storage container name.  Set the `CACHEPOT_AZURE_CONNECTION_STRING`
environment variable to your connection string, and `CACHEPOT_AZURE_BLOB_CONTAINER` to the name of the container to use.  Note that cachepot will not create
the container for you - you'll need to do that yourself.

**Important:** The environment variables are only taken into account when the server starts, i.e. only on the first run.

---

Overwriting the cache
---------------------

In situations where the cache contains broken build artifacts, it can be necessary to overwrite the contents in the cache. That can be achieved by setting the `CACHEPOT_RECACHE` environment variable.

---

Debugging
---------

You can set the `CACHEPOT_ERROR_LOG` environment variable to a path and set `CACHEPOT_LOG` to get the server process to redirect its logging there (including the output of unhandled panics, since the server sets `RUST_BACKTRACE=1` internally).

    CACHEPOT_ERROR_LOG=/tmp/cachepot_log.txt CACHEPOT_LOG=debug cachepot

You can also set these environment variables for your build system, for example

    CACHEPOT_ERROR_LOG=/tmp/cachepot_log.txt CACHEPOT_LOG=debug cmake --build /path/to/cmake/build/directory

Alternatively, if you are compiling locally, you can run the server manually in foreground mode by running `CACHEPOT_START_SERVER=1 CACHEPOT_NO_DAEMON=1 cachepot`, and send logging to stderr by setting the [`CACHEPOT_LOG` environment variable](https://docs.rs/env_logger/0.7.1/env_logger/#enabling-logging) for example. This method is not suitable for CI services because you need to compile in another shell at the same time.

    CACHEPOT_LOG=debug CACHEPOT_START_SERVER=1 CACHEPOT_NO_DAEMON=1 cachepot

---

Interaction with GNU `make` jobserver
-------------------------------------

cachepot provides support for a [GNU make jobserver](https://www.gnu.org/software/make/manual/html_node/Job-Slots.html). When the server is started from a process that provides a jobserver, cachepot will use that jobserver and provide it to any processes it spawns. (If you are running cachepot from a GNU make recipe, you will need to prefix the command with `+` to get this behavior.) If the cachepot server is started without a jobserver present it will create its own with the number of slots equal to the number of available CPU cores.

This is most useful when using cachepot for Rust compilation, as rustc supports using a jobserver for parallel codegen, so this ensures that rustc will not overwhelm the system with codegen tasks. Cargo implements its own jobserver ([see the information on `NUM_JOBS` in the cargo documentation](https://doc.rust-lang.org/stable/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts)) for rustc to use, so using cachepot for Rust compilation in cargo via `RUSTC_WRAPPER` should do the right thing automatically.

---

Known Caveats
-------------

### General

* Absolute paths to files must match to get a cache hit. This means that even if you are using a shared cache, everyone will have to build at the same absolute path (i.e. not in `$HOME`) in order to benefit each other. In Rust this includes the source for third party crates which are stored in `$HOME/.cargo/registry/cache` by default.

### Rust

* Crates that invoke the system linker cannot be cached. This includes `bin`, `dylib`, `cdylib`, and `proc-macro` crates. You may be able to improve compilation time of large `bin` crates by converting them to a `lib` crate with a thin `bin` wrapper.
* Incrementally compiled crates cannot be cached. By default, in the debug profile Cargo will use incremental compilation for workspace members and path dependencies. [You can disable incremental compilation.](https://doc.rust-lang.org/cargo/reference/profiles.html#incremental)

[More details on Rust caveats](/docs/Rust.md)
