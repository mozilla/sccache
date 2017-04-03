sccache now includes experimental support for caching Rust compilation. This includes many caveats, and is primarily focused on caching rustc invocations as produced by cargo. A (possibly-incomplete) list follows:
* `--emit` is required.
* `--crate-name` is required.
* Only `link` and `dep-info` are supported as `--emit` values, and `link` must be present.
* `--out-dir` is required.
* `-o file` is not supported.
* Compilation from stdin is not supported, a source file must be provided.
* Values from `env!` will not be tracked in caching.
* Procedural macros that read files from the filesystem may not be cached properly
* The system linker is not factored in as a cache input, so changing the linker may produce incorrect cached results.
* Target specs aren't hashed (e.g. custom target specs)
