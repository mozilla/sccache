sccache includes support for caching Rust compilation. This includes many caveats, and is primarily focused on caching rustc invocations as produced by cargo. A (possibly-incomplete) list follows:
* `--emit` is required.
* `--crate-name` is required.
* Only `link`, `metadata` and `dep-info` are supported as `--emit` values, and `link` must be present.
* `--out-dir` is required.
* `-o file` is not supported.
* Compilation from stdin is not supported, a source file must be provided.
* Values from `env!` require Rust >= 1.46 to be tracked in caching.
* With `SCCACHE_BASEDIRS`, the values of variables read with `env!` or `option_env!` are hashed with the basedirs stripped, so a crate that bakes `env!("CARGO_MANIFEST_DIR")` into its outputs can get a cache hit from another checkout and use that checkout's path. `SCCACHE_BASEDIRS_VERBATIM_ENV_DEPS=CARGO_MANIFEST_DIR,CARGO_MANIFEST_PATH` hashes those values verbatim, so only the crates that read them are cached per checkout. A procedural macro that reads the variable with `std::env::var` is not covered, as rustc does not list it in the dep-info. Listing `OUT_DIR` would stop sharing every crate that `include!`s generated code.
* Procedural macros that read files from the filesystem may not be cached properly.
* A procedural macro is identified by its crate metadata, so a change to native code it links, with no change to its Rust source or dependencies, is not seen.
* `rustc`'s incremental compilation needs to be disabled. See [The Cargo Book](https://doc.rust-lang.org/cargo/reference/profiles.html#incremental). sccache exits with an error when `CARGO_INCREMENTAL=1` is set, unless `SCCACHE_ALLOW_INCREMENTAL=1` is set: then only the incremental crates (workspace members and path dependencies) go uncached.
* Crates that invoke the system linker cannot be cached. Examples are `bin`, `dylib`, `cdylib`, and `proc-macro` crates.

If you are using Rust 1.18 or later, you can ask cargo to wrap all compilation with sccache by setting `RUSTC_WRAPPER=sccache` in your build environment.

To compute the cache key of a crate, sccache runs `rustc --emit=dep-info` to list its source files, and `rustc --print file-names` to list its outputs. The server remembers what both found, and reuses it for a later compile of the crate with the same compiler, arguments, working directory, environment, externs, static libraries and target spec, as long as every listed source file still has the same contents. This lasts for the life of the server; nothing is written to the cache. As with the preprocessor cache, a file that was not listed does not invalidate it: for instance, adding `foo/mod.rs` next to an existing `foo.rs` keeps reusing the cached result instead of failing with an ambiguous module error.
