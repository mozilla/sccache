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
* `SCCACHE_BASEDIRS` permits cross-checkout reuse when rustc's `--remap-path-prefix` maps the inputs and working directory to the same paths with the default or `all` remap scope. Dep-info is generated locally for each invocation.
* Path normalization remains location-sensitive when explicit external crates or dynamic libraries on crate search paths may invoke procedural macros, because they can observe physical paths without reporting a dependency to rustc.
* Rust path normalization is limited to ASCII paths on Windows.

If you are using Rust 1.18 or later, you can ask cargo to wrap all compilation with sccache by setting `RUSTC_WRAPPER=sccache` in your build environment.

## Cross-checkout cache correctness

Stripping a checkout path from a cache key does not remove it from compiler output.
For example, this library must return the current checkout's manifest directory:

```rust
pub fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}
```

If checkout A and checkout B share a key after that environment value is stripped,
B can receive A's library and return A's directory. `--remap-path-prefix` does not
rewrite string values produced by `env!` or arbitrary procedural-macro output.

| Input | Required cache behavior across checkouts |
| --- | --- |
| `env!` or `option_env!` with different values | Miss; preserve the recorded values exactly. |
| `file!` with different absolute source paths and no remapping | Miss; preserve source identity. |
| Remappings with different destination paths | Miss; destinations affect compiler output. |
| A procedural macro reading the physical working directory | Miss; compiler remapping does not change that directory. |
| Sources and working directories remapped to the same virtual paths, without other path-sensitive inputs | A hit is possible. |

To enable the last case, set `SCCACHE_BASEDIRS` to the checkout roots and pass
`--remap-path-prefix=<current-checkout>=/workspace` to rustc in each checkout.
Only known path-valued Cargo variables are eligible for normalization; values
reported as dependencies by rustc are always retained exactly. This includes
`OUT_DIR` even when it is only used to locate generated source through `include!`.

The procedural-macro check is conservative: any explicit `--extern` input or
dynamic library in a crate search directory disables path normalization. Most
Cargo crates with dependencies therefore remain location-sensitive, even when
those dependencies happen not to use procedural macros.

The Rust cache-key version is advanced to invalidate entries produced by the
previous normalization rules. Existing Rust entries will miss once after upgrading.
