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

If you are using Rust 1.18 or later, you can ask cargo to wrap all compilation with sccache by setting `RUSTC_WRAPPER=sccache` in your build environment.

To compute the cache key of a crate, sccache runs `rustc --emit=dep-info` to list its source files, and `rustc --print file-names` to list its outputs. The first one parses and expands the whole crate, which used to be most of the work of a cache hit. The server remembers what both found, and reuses it for a later compile of the crate with the same compiler, arguments, working directory, environment, externs, static libraries and target spec, as long as every listed source file still has the same contents. This lasts for the life of the server; nothing is written to the cache. As with the preprocessor cache, a file that was not listed does not invalidate it: for instance, adding `foo/mod.rs` next to an existing `foo.rs` keeps reusing the cached result instead of failing with an ambiguous module error.
