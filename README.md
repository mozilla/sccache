[![Build Status](https://github.com/mozilla/sccache/workflows/ci/badge.svg)](https://github.com/mozilla/sccache/actions?query=workflow%3Aci)

sccache - Shared Compilation Cache
==================================

sccache is a [ccache](https://ccache.dev/)-like compiler caching tool. It is used as a compiler wrapper and avoids compilation when possible, storing cached results either on [local disk](#local) or in one of [several cloud storage backends](#storage-options).

sccache includes support for caching the compilation of C/C++ code, [Rust](docs/Rust.md), as well as NVIDIA's CUDA using [nvcc](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html).

sccache also provides [icecream](https://github.com/icecc/icecream)-style distributed compilation (automatic packaging of local toolchains) for all supported compilers (including Rust). The distributed compilation system includes several security features that icecream lacks such as authentication, transport layer encryption, and sandboxed compiler execution on build servers. See [the distributed quickstart](docs/DistributedQuickstart.md) guide for more information.

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

There are prebuilt x86-64 binaries available for Windows, Linux (a portable binary compiled against musl), and macOS [on the releases page](https://github.com/mozilla/sccache/releases/latest). Several package managers also include sccache packages, you can install the latest release from source using cargo, or build directly from a source checkout.

### macOS

On macOS sccache can be installed via [Homebrew](https://brew.sh/):

```bash
brew install sccache
```

### Windows

On Windows, sccache can be installed via [scoop](https://scoop.sh/):

```
scoop install sccache
```

### Via cargo

If you have a Rust toolchain installed you can install sccache using cargo. **Note that this will compile sccache from source which is fairly resource-intensive. For CI purposes you should use prebuilt binary packages.**


```bash
cargo install sccache
```

---

Usage
-----

Running sccache is like running ccache: prefix your compilation commands with it, like so:

```bash
sccache gcc -o foo.o -c foo.c
```

If you want to use sccache for caching Rust builds you can define `build.rustc-wrapper` in the
[cargo configuration file](https://doc.rust-lang.org/cargo/reference/config.html).  For example, you can set it globally
in `$HOME/.cargo/config` by adding:

```toml
[build]
rustc-wrapper = "/path/to/sccache"
```

Note that you need to use cargo 1.40 or newer for this to work.

Alternatively you can use the environment variable `RUSTC_WRAPPER`:

```bash
export RUSTC_WRAPPER=/path/to/sccache
cargo build
```

sccache supports gcc, clang, MSVC, rustc, NVCC, and [Wind River's diab compiler](https://www.windriver.com/products/development-tools/#diab_compiler).

If you don't [specify otherwise](#storage-options), sccache will use a local disk cache.

sccache works using a client-server model, where the server runs locally on the same machine as the client. The client-server model allows the server to be more efficient by keeping some state in memory. The sccache command will spawn a server process if one is not already running, or you can run `sccache --start-server` to start the background server process without performing any compilation.

You can run `sccache --stop-server` to terminate the server. It will also terminate after (by default) 10 minutes of inactivity.

Running `sccache --show-stats` will print a summary of cache statistics.

Some notes about using `sccache` with [Jenkins](https://jenkins.io) are [here](docs/Jenkins.md).

To use sccache with cmake, provide the following command line arguments to cmake 3.4 or newer:

```
-DCMAKE_C_COMPILER_LAUNCHER=sccache
-DCMAKE_CXX_COMPILER_LAUNCHER=sccache
```

---

Build Requirements
------------------

sccache is a [Rust](https://www.rust-lang.org/) program. Building it requires `cargo` (and thus `rustc`). sccache currently requires **Rust 1.43.0**. We recommend you install Rust via [Rustup](https://rustup.rs/).

Build
-----

If you are building sccache for non-development purposes make sure you use `cargo build --release` to get optimized binaries:

```bash
cargo build --release [--no-default-features --features=s3|redis|gcs|memcached|azure]
```

By default, `sccache` builds with support for all storage backends, but individual backends may be disabled by resetting the list of features and enabling all the other backends. Refer the [Cargo Documentation](http://doc.crates.io/manifest.html#the-features-section) for details on how to select features with Cargo.

### Building portable binaries

When building with the `gcs` feature, `sccache` will depend on OpenSSL, which can be an annoyance if you want to distribute portable binaries. It is possible to statically link against OpenSSL using the `openssl/vendored` feature.

#### Linux

Build with `cargo` and use `ldd` to check that the resulting binary does not depend on OpenSSL anymore.

#### macOS

Build with `cargo` and use `otool -L` to check that the resulting binary does not depend on OpenSSL anymore.

#### Windows

On Windows, the binary might also depend on a few MSVC CRT DLLs that are not available on older Windows versions.

It is possible to statically link against the CRT using a `.cargo/config` file with the following contents.

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-Ctarget-feature=+crt-static"]
```

Build with `cargo` and use `dumpbin /dependents` to check that the resulting binary does not depend on MSVC CRT DLLs anymore.

When statically linking with OpenSSL, you will need Perl available in your `$PATH`.

---

Storage Options
---------------

### Local
sccache defaults to using local disk storage. You can set the `SCCACHE_DIR` environment variable to change the disk cache location. By default it will use a sensible location for the current platform: `~/.cache/sccache` on Linux, `%LOCALAPPDATA%\Mozilla\sccache` on Windows, and `~/Library/Caches/Mozilla.sccache` on MacOS.

The default cache size is 10 gigabytes. To change this, set `SCCACHE_CACHE_SIZE`, for example `SCCACHE_CACHE_SIZE="1G"`.

### S3
If you want to use S3 storage for the sccache cache, you need to set the `SCCACHE_BUCKET` environment variable to the name of the S3 bucket to use.

You can use `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to set the S3 credentials.  Alternately, you can set `AWS_IAM_CREDENTIALS_URL` to a URL that returns credentials in the format supported by the [EC2 metadata service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials), and credentials will be fetched from that location as needed. In the absence of either of these options, credentials for the instance's IAM role will be fetched from the EC2 metadata service directly.

If you need to override the default endpoint you can set `SCCACHE_ENDPOINT`. To connect to a minio storage for example you can set `SCCACHE_ENDPOINT=<ip>:<port>`. If your endpoint requires TLS, set `SCCACHE_S3_USE_SSL=true`.

You can also define a prefix that will be prepended to the keys of all cache objects created and read within the S3 bucket, effectively creating a scope. To do that use the `SCCACHE_S3_KEY_PREFIX` environment variable. This can be useful when sharing a bucket with another application.


### Redis
Set `SCCACHE_REDIS` to a [Redis](https://redis.io/) url in format `redis://[:<passwd>@]<hostname>[:port][/<db>]` to store the cache in a Redis instance. Redis can be configured as a LRU (least recently used) cache with a fixed maximum cache size. Set `maxmemory` and `maxmemory-policy` according to the [Redis documentation](https://redis.io/topics/lru-cache). The `allkeys-lru` policy which discards the *least recently accessed or modified* key fits well for the sccache use case.

### Memcached
Set `SCCACHE_MEMCACHED` to a [Memcached](https://memcached.org/) url in format `tcp://<hostname>:<port> ...` to store the cache in a Memcached instance.

### Google Cloud Storage
To use [Google Cloud Storage](https://cloud.google.com/storage/), you need to set the `SCCACHE_GCS_BUCKET` environment variable to the name of the GCS bucket.
If you're using authentication, either set `SCCACHE_GCS_KEY_PATH` to the location of your JSON service account credentials or `SCCACHE_GCS_CREDENTIALS_URL` with
a URL that returns the oauth token.
By default, SCCACHE on GCS will be read-only. To change this, set `SCCACHE_GCS_RW_MODE` to either `READ_ONLY` or `READ_WRITE`.

### Azure
To use Azure Blob Storage, you'll need your Azure connection string and an _existing_ Blob Storage container name.  Set the `SCCACHE_AZURE_CONNECTION_STRING`
environment variable to your connection string, and `SCCACHE_AZURE_BLOB_CONTAINER` to the name of the container to use.  Note that sccache will not create
the container for you - you'll need to do that yourself.

**Important:** The environment variables are only taken into account when the server starts, i.e. only on the first run.

---

Overwriting the cache
---------------------

In situations where the cache contains broken build artifacts, it can be necessary to overwrite the contents in the cache. That can be achieved by setting the `SCCACHE_RECACHE` environment variable.

---

Debugging
---------

You can set the `SCCACHE_ERROR_LOG` environment variable to a path and set `SCCACHE_LOG` to get the server process to redirect its logging there (including the output of unhandled panics, since the server sets `RUST_BACKTRACE=1` internally).

    SCCACHE_ERROR_LOG=/tmp/sccache_log.txt SCCACHE_LOG=debug sccache

You can also set these environment variables for your build system, for example

    SCCACHE_ERROR_LOG=/tmp/sccache_log.txt SCCACHE_LOG=debug cmake --build /path/to/cmake/build/directory

Alternatively, if you are compiling locally, you can run the server manually in foreground mode by running `SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 sccache`, and send logging to stderr by setting the [`SCCACHE_LOG` environment variable](https://docs.rs/env_logger/0.7.1/env_logger/#enabling-logging) for example. This method is not suitable for CI services because you need to compile in another shell at the same time.

    SCCACHE_LOG=debug SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 sccache

---

Interaction with GNU `make` jobserver
-------------------------------------

sccache provides support for a [GNU make jobserver](https://www.gnu.org/software/make/manual/html_node/Job-Slots.html). When the server is started from a process that provides a jobserver, sccache will use that jobserver and provide it to any processes it spawns. (If you are running sccache from a GNU make recipe, you will need to prefix the command with `+` to get this behavior.) If the sccache server is started without a jobserver present it will create its own with the number of slots equal to the number of available CPU cores.

This is most useful when using sccache for Rust compilation, as rustc supports using a jobserver for parallel codegen, so this ensures that rustc will not overwhelm the system with codegen tasks. Cargo implements its own jobserver ([see the information on `NUM_JOBS` in the cargo documentation](https://doc.rust-lang.org/stable/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts)) for rustc to use, so using sccache for Rust compilation in cargo via `RUSTC_WRAPPER` should do the right thing automatically.

---

Known Caveats
-------------

### General

* Absolute paths to files must match to get a cache hit. This means that even if you are using a shared cache, everyone will have to build at the same absolute path (i.e. not in `$HOME`) in order to benefit each other. In Rust this includes the source for third party crates which are stored in `$HOME/.cargo/registry/cache` by default.

### Rust

* Crates that invoke the system linker cannot be cached. This includes `bin`, `dylib`, `cdylib`, and `proc-macro` crates. You may be able to improve compilation time of large `bin` crates by converting them to a `lib` crate with a thin `bin` wrapper.
* Incrementally compiled crates cannot be cached. By default, in the debug profile Cargo will use incremental compilation for workspace members and path dependencies. [You can disable incremental compilation.](https://doc.rust-lang.org/cargo/reference/profiles.html#incremental)

[More details on Rust caveats](/docs/Rust.md)
