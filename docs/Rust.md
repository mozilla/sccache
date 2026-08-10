sccache includes support for caching Rust compilation. This includes many caveats, and is primarily focused on caching rustc invocations as produced by cargo. A (possibly-incomplete) list follows:
* `--emit` is required.
* `--crate-name` is required.
* Only `link`, `metadata` and `dep-info` are supported as `--emit` values, and `link` must be present.
* `--out-dir` is required.
* `-o file` is not supported.
* Compilation from stdin is not supported, a source file must be provided.
* Values from `env!` require Rust >= 1.46 to be tracked in caching.
* Procedural macros that read files from the filesystem may not be cached properly.
* `rustc`'s incremental compilation needs to be disabled. See [The Cargo Book](https://doc.rust-lang.org/cargo/reference/profiles.html#incremental)
* Crates that invoke the system linker cannot be cached. Examples are `bin`, `dylib`, `cdylib`, and `proc-macro` crates.
* `SCCACHE_BASEDIRS` normalizes paths in Rust cache keys when rustc's `--remap-path-prefix` covers the working directory with the default or `all` remap scope. Cached dep-info output targets are rewritten for the current invocation.
* Path normalization remains location-sensitive when explicit external crates or dynamic libraries on crate search paths may invoke procedural macros, because they can observe physical paths without reporting a dependency to rustc.
* Rust path normalization is limited to ASCII paths on Windows.
* Distributed Rust compilation falls back to local compilation when `--remap-path-prefix` is used with a non-identity path transformer.

If you are using Rust 1.18 or later, you can ask cargo to wrap all compilation with sccache by setting `RUSTC_WRAPPER=sccache` in your build environment.
