[![Build Status](https://github.com/mozilla/sccache/workflows/ci/badge.svg)](https://github.com/mozilla/sccache/actions?query=workflow%3Aci)
[![Crates.io](https://img.shields.io/crates/v/sccache.svg)](https://crates.io/crates/sccache)
[![Matrix](https://img.shields.io/matrix/sccache:mozilla.org)](https://chat.mozilla.org/#/room/#sccache:mozilla.org)
![Crates.io](https://img.shields.io/crates/l/sccache)
[![dependency status](https://deps.rs/repo/github/mozilla/sccache/status.svg)](https://deps.rs/repo/github/mozilla/sccache)

[![CodeCov](https://codecov.io/gh/mozilla/sccache/branch/main/graph/badge.svg)](https://codecov.io/gh/mozilla/sccache)


sccache - Shared Compilation Cache
==================================

sccache is a [ccache](https://ccache.dev/)-like compiler caching tool. It is used as a compiler wrapper and avoids compilation when possible, storing cached results either on [local disk](docs/Local.md) or in one of [several cloud storage backends](#storage-options).

sccache includes support for caching the compilation of C/C++ code, [Rust](docs/Rust.md), as well as NVIDIA's CUDA using [nvcc](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html), and [clang](https://llvm.org/docs/CompileCudaWithLLVM.html).

sccache also provides [icecream](https://github.com/icecc/icecream)-style distributed compilation (automatic packaging of local toolchains) for all supported compilers (including Rust). The distributed compilation system includes several security features that icecream lacks such as authentication, transport layer encryption, and sandboxed compiler execution on build servers. See [the distributed quickstart](docs/DistributedQuickstart.md) guide for more information.

sccache is also available as a [GitHub Actions](https://github.com/marketplace/actions/sccache-action) to facilitate the deployment using GitHub Actions cache.

---

Table of Contents (ToC)
=======================

* [Installation](#installation)
* [Usage](#usage)
* [Build Requirements](#build-requirements)
* [Build](#build)
* [Separating caches between invocations](#separating-caches-between-invocations)
* [Overwriting the cache](#overwriting-the-cache)
* [Debugging](#debugging)
* [Interaction with GNU `make` jobserver](#interaction-with-gnu-make-jobserver)
* [Known Caveats](#known-caveats)
* [Storage Options](#storage-options)
  * [Local](docs/Local.md)
  * [S3](docs/S3.md)
  * [R2](docs/S3.md#R2)
  * [Redis](docs/Redis.md)
  * [Memcached](docs/Memcached.md)
  * [Google Cloud Storage](docs/Gcs.md)
  * [Azure](docs/Azure.md)
  * [GitHub Actions](docs/GHA.md)
  * [WebDAV (Ccache/Bazel/Gradle compatible)](docs/Webdav.md)
  * [Alibaba OSS](docs/OSS.md)

---

## Installation

There are prebuilt x86-64 binaries available for Windows, Linux (a portable binary compiled against musl), and macOS [on the releases page](https://github.com/mozilla/sccache/releases/latest). Several package managers also include sccache packages, you can install the latest release from source using cargo, or build directly from a source checkout.

### macOS

On macOS sccache can be installed via [Homebrew](https://brew.sh/):

```bash
brew install sccache
```

or via [MacPorts](https://www.macports.org/):

```bash
sudo port install sccache
```

### Windows

On Windows, sccache can be installed via [scoop](https://scoop.sh/):

```
scoop install sccache
```

### Via cargo

If you have a Rust toolchain installed you can install sccache using cargo. **Note that this will compile sccache from source which is fairly resource-intensive. For CI purposes you should use prebuilt binary packages.**


```bash
cargo install sccache --locked
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
in `$HOME/.cargo/config.toml` by adding:

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

sccache supports gcc, clang, MSVC, rustc, [NVCC](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html), [NVC++](https://docs.nvidia.com/hpc-sdk//compilers/hpc-compilers-user-guide/index.html), and [Wind River's diab compiler](https://www.windriver.com/products/development-tools/#diab_compiler). Both gcc and msvc support Response Files, read more about their implementation [here](docs/ResponseFiles.md).

If you don't [specify otherwise](#storage-options), sccache will use a local disk cache.

sccache works using a client-server model, where the server runs locally on the same machine as the client. The client-server model allows the server to be more efficient by keeping some state in memory. The sccache command will spawn a server process if one is not already running, or you can run `sccache --start-server` to start the background server process without performing any compilation.

By default sccache server will listen on `127.0.0.1:4226`, you can specify environment variable `SCCACHE_SERVER_PORT` to use a different port or `SCCACHE_SERVER_UDS` to listen on unix domain socket. Abstract unix socket is also supported as long as the path is escaped following the [format](https://doc.rust-lang.org/std/ascii/fn.escape_default.html). For example:

```
% env SCCACHE_SERVER_UDS=$HOME/sccache.sock sccache --start-server # unix socket
% env SCCACHE_SERVER_UDS=\\x00sccache.sock sccache --start-server # abstract unix socket
```

You can run `sccache --stop-server` to terminate the server. It will also terminate after (by default) 10 minutes of inactivity.

Running `sccache --show-stats` will print a summary of cache statistics.

Some notes about using `sccache` with [Jenkins](https://jenkins.io) are [here](docs/Jenkins.md).

To use sccache with cmake, provide the following command line arguments to cmake 3.4 or newer:

```
-DCMAKE_C_COMPILER_LAUNCHER=sccache
-DCMAKE_CXX_COMPILER_LAUNCHER=sccache
```

The process for using sccache with MSVC and cmake, depends on which version of cmake you're using. **For versions of cmake 3.24 and earlier**, to generate PDB files for debugging with MSVC, you can use the [`/Z7` option](https://docs.microsoft.com/en-us/cpp/build/reference/z7-zi-zi-debug-information-format?view=msvc-160). Alternatively, the `/Zi` option together with `/Fd` can work if `/Fd` names a different PDB file name for each object file created. Note that CMake sets `/Zi` by default, so if you use CMake, you can use `/Z7` by adding code like this in your CMakeLists.txt:

```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  string(REPLACE "/Zi" "/Z7" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  string(REPLACE "/Zi" "/Z7" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
  string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  string(REPLACE "/Zi" "/Z7" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
  string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
endif()
```

By default, sccache will fail your build if it fails to successfully communicate with its associated server. To have sccache instead gracefully failover to the local compiler without stopping, set the environment variable `SCCACHE_IGNORE_SERVER_IO_ERROR=1`.

**For versions of cmake 3.25 and later**, to compile with MSVC, you have to use the new `CMAKE_MSVC_DEBUG_INFORMATION_FORMAT` option, meant to configure the `-Z7` flag.  Additionally, you must set the cmake policy number 0141 to the NEW setting:
```cmake
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT Embedded)
cmake_policy(SET CMP0141 NEW)
```

Example configuration where we automatically look for `sccache` in the `PATH`:
```cmake
find_program(SCCACHE sccache REQUIRED)

set(CMAKE_C_COMPILER_LAUNCHER ${SCCACHE})
set(CMAKE_CXX_COMPILER_LAUNCHER ${SCCACHE})
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT Embedded)
cmake_policy(SET CMP0141 NEW)
```

Alternatively, if configuring cmake with MSVC on the command line, assuming that sccache is on the default search path:

```
cmake -DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache -DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded -DCMAKE_POLICY_CMP0141=NEW [...]
```

And you can build code as usual without any additional flags in the command line, which is useful for IDEs.


---

Build Requirements
------------------

sccache is a [Rust](https://www.rust-lang.org/) program. Building it requires `cargo` (and thus`rustc`). sccache currently requires **Rust 1.75.0**. We recommend you install Rust via [Rustup](https://rustup.rs/).

Build
-----

If you are building sccache for non-development purposes make sure you use `cargo build --release` to get optimized binaries:

```bash
cargo build --release [--no-default-features --features=s3|redis|gcs|memcached|azure|gha|webdav|oss]
```

The list of features can be found in the `Cargo.toml` file, `[features]` section.

By default, `sccache` builds with support for all storage backends, but individual backends may be disabled by resetting the list of features and enabling all the other backends. Refer the [Cargo Documentation](http://doc.crates.io/manifest.html#the-features-section) for details on how to select features with Cargo.

### Building portable binaries

When building with the `dist-server` feature, `sccache` will depend on OpenSSL, which can be an annoyance if you want to distribute portable binaries. It is possible to statically link against OpenSSL using the `openssl/vendored` feature.

#### Linux

Build with `cargo` and use `ldd` to check that the resulting binary does not depend on OpenSSL anymore.

#### macOS

Build with `cargo` and use `otool -L` to check that the resulting binary does not depend on OpenSSL anymore.

#### Windows

On Windows, the binary might also depend on a few MSVC CRT DLLs that are not available on older Windows versions.

It is possible to statically link against the CRT using a `.cargo/config.toml` file with the following contents.

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-Ctarget-feature=+crt-static"]
```

Build with `cargo` and use `dumpbin /dependents` to check that the resulting binary does not depend on MSVC CRT DLLs anymore.

When statically linking with OpenSSL, you will need Perl available in your `$PATH`.

---

Separating caches between invocations
-------------------------------------

In situations where several different compilation invocations
should not reuse the cached results from each other,
one can set `SCCACHE_C_CUSTOM_CACHE_BUSTER` to a unique value
that'll be mixed into the hash.
`MACOSX_DEPLOYMENT_TARGET` and `IPHONEOS_DEPLOYMENT_TARGET` variables
already exhibit such reuse-suppression behaviour.
There are currently no such variables for compiling Rust.

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

### Symbolic links

* Symbolic links to sccache won't work. Use hardlinks: `ln sccache /usr/local/bin/cc`

### User Agent

* Requests sent to your storage option of choice will have a user agent header indicating the current sccache version, e.g. `sccache/0.8.2`.

Storage Options
---------------

* [Local](docs/Local.md)
* [S3](docs/S3.md)
* [R2](docs/S3.md#R2)
* [Redis](docs/Redis.md)
* [Memcached](docs/Memcached.md)
* [Google Cloud Storage](docs/Gcs.md)
* [Azure](docs/Azure.md)
* [GitHub Actions](docs/GHA.md)
* [WebDAV (Ccache/Bazel/Gradle compatible)](docs/Webdav.md)
* [Alibaba OSS](docs/OSS.md)
