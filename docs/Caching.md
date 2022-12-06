# How caching works

To know if the storage contains the artifact we need, we are
computing some hashes to make sure the input is the same.

Because the configuration and environnement matter, the hash
computation takes a few parameters into account.

## How hash keys are computed.

### Rust

We generate a blake3 digest for each file compiled.
In parallel, we also take into account in the hash:
* Path to the rustc executable
* Host triple for this rustc
* Path to the rustc sysroot
* digests of all the shared libraries in rustc's $sysroot/lib
* A shared, caching reader for rlib dependencies (for dist-client)
* Parsed arguments from the rustc invocation
  See https://github.com/mozilla/sccache/blob/8567bbe2ba493153e76177c1f9a6f98cc7ba419f/src/compiler/rust.rs#L122 for the full list

### C/C++ compiler

For C/C++, the hash is generated with a blake3 digest of the preprocessed
file (-E with gcc/clang).

We also take into account in the hash:
* Hash of the compiler binary
* Programming language
* Flag required to compile for the given language
* File in which to generate dependencies.
* Commandline arguments for dependency generation
* Commandline arguments for the preprocessor
* Extra files that need to have their contents hashed
* Whether the compilation is generating profiling or coverage data
* Color mode
* Environment variables
See https://github.com/mozilla/sccache/blob/8567bbe2ba493153e76177c1f9a6f98cc7ba419f/src/compiler/c.rs#L84
