# Profile-guided optimization

sccache can be built with [profile-guided optimization](https://doc.rust-lang.org/rustc/profile-guided-optimization.html) (PGO): an instrumented sccache is run on real compilations, and the profile it records tells the compiler which code is hot when it builds the final binary.

The binaries published on the [releases page](https://github.com/mozilla/sccache/releases) for x86-64 Linux, macOS (arm64 and x86-64) and x86-64 Windows are built this way. On x86-64 Linux, PGO cuts the instructions the sccache server runs on each cache hit by 3-5%. That gain applies to every compilation sccache wraps, while it costs nothing at runtime: only the build takes longer.

**If you package sccache, please build it with PGO as well**, so that your users get the same binary performance as the official releases.

## Building

`scripts/build-pgo.sh` does everything:

```bash
rustup component add llvm-tools
./scripts/build-pgo.sh
```

The optimized binary ends up in `target/sccache-pgo/<target>/release/sccache`.

The script:

1. builds an instrumented sccache (`-Cprofile-generate`) with the same LTO and codegen settings as a release build, along with the integration tests;
2. runs those integration tests (`system`, `sccache_cargo`, `sccache_rustc`, `cache_hit_rate` and `sccache_args`), then compiles a generated C/C++ corpus through sccache, cache misses followed by hits, in preprocessor and direct mode;
3. merges the recorded profile with `llvm-profdata`, and stops if it covers suspiciously few functions;
4. builds the optimized sccache with `-Cprofile-use`.

It runs on Linux, macOS and Windows (from Git Bash), and takes roughly twice as long as a regular release build.

### Options

| Option | |
|---|---|
| `--target TRIPLE` | Target to build for. Defaults to the host. The host has to be able to run the binary: the profile comes from running it. |
| `--features LIST` | Cargo features, as passed to `cargo build --features`. Use the same ones as for your regular build. |
| `--target-dir DIR` | Where to build. Defaults to `target/sccache-pgo`. |
| `--train-only` | Stop after recording the profile, and print the flag to build with it. Its absolute path is also written to `<target-dir>/profdata-path.txt`. |
| `--llvm-profdata PATH` | `llvm-profdata` to merge the profile with. Defaults to the one of the active rustup toolchain. Its LLVM major version has to be the one of `rustc`. |
| `--bench` | Also build sccache without the profile, and compare both with `scripts/bench-pgo.sh`. Needs [hyperfine](https://github.com/sharkdp/hyperfine). |

## Packaging

Packaging recipes usually have their own `cargo build` invocation. Use `--train-only`, then add the profile to the `RUSTFLAGS` of your build:

```bash
./scripts/build-pgo.sh --train-only --features "$FEATURES"
export RUSTFLAGS="$RUSTFLAGS -Cprofile-use=$(cat target/sccache-pgo/profdata-path.txt)"
cargo build --release --features "$FEATURES"
```

This is what sccache's own CI does, see `.github/workflows/ci.yml`. Things to keep in mind:

- **Build exactly what you trained.** Use the same Rust toolchain, target, features, `RUSTFLAGS` and release profile settings (LTO, codegen units) for the training and for the final build. The profile is matched to the code by function, and functions compiled differently get no profile data; nothing fails, the binary is just not optimized. Keep any `RUSTFLAGS` you need in the environment when running the script: it adds its own flags to them.
- **The toolchain needs the profiler runtime.** rustup toolchains include it. If yours does not, the instrumented build fails with `can't find crate for profiler_builtins`.
- **`llvm-profdata` has to match the LLVM version of `rustc`** (shown by `rustc -vV`). The script checks this before building anything, and stops if the major versions differ. Without rustup, install the matching LLVM tools from your distribution and pass `--llvm-profdata /path/to/llvm-profdata`.
- **The training needs the dev-dependencies.** It builds and runs the integration tests, so an offline build environment has to provide sccache's dev-dependencies too, not just its dependencies.
- **Generate the profile in the build.** A profile is tied to the exact source and compiler it was recorded with: don't reuse one across sccache or Rust versions.
- **Profiles are not byte-for-byte reproducible.** Two training runs record slightly different counts, so two PGO builds of the same source can differ. If you need reproducible builds, keep that in mind.
- **Cross builds cannot be trained** on a host that cannot run the target binary.

C/C++ compilers on `PATH` (`cc`, `gcc` or `clang`, and their C++ counterparts, or `$CC`/`$CXX`) make the training cover C/C++ compilations too. Without them, the script still trains on the Rust tests, but the profile is less representative of C/C++ workloads.
