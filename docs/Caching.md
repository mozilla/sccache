# How caching works

To know if the storage contains the artifact we need, we are
computing some hashes to make sure the input is the same.

Because the configuration and environment matter, the hash
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
file (-E with gcc/clang). For compilations that specify multiple `-arch` flags,
these flags are rewritten to their corresponding preprocessor defines to allow
pre-processing the file (e.g `-arch x86_64` is rewritten to `-D__X86_64__=1`),
this can be enabled by setting the environment variable
`SCCACHE_CACHE_MULTIARCH` but is disabled by default as it may not work in all
cases.

We also take into account in the hash:
* Hash of the compiler binary
* Programming language
* Flag required to compile for the given language
* File in which to generate dependencies.
* Commandline arguments for dependency generation
* Commandline arguments for the preprocessor
* Commandline arguments specifying the architecture to compile for
* Extra files that need to have their contents hashed
* Whether the compilation is generating profiling or coverage data
* Color mode
* Environment variables

See https://github.com/mozilla/sccache/blob/8567bbe2ba493153e76177c1f9a6f98cc7ba419f/src/compiler/c.rs#L84

### C/C++ preprocessor

In "preprocessor cache mode", [explained in the local doc](Local.md), an
extra key is computed to cache the preprocessor output itself. It is very close
to the C/C++ compiler one, but with additional elements:

* The path of the input file
* The hash of the input file

Note that some compiler options can disable preprocessor cache mode. As of this
writing, only `-Xpreprocessor` and `-Wp,*` do.
