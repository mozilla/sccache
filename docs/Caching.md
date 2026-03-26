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

In "preprocessor cache mode" explained below, an extra key is computed to cache the preprocessor output itself.
It is very close to the C/C++ compiler one, but with additional elements:

* The path of the input file
* The hash of the input file

Note that some compiler options can disable preprocessor cache mode. As of this
writing, only `-Xpreprocessor` and `-Wp,*` do.

#### Preprocessor cache mode

This is inspired by [ccache's direct mode](https://ccache.dev/manual/3.7.9.html#_the_direct_mode) and works roughly the same.
It adds a cache that allows to skip preprocessing when compiling C/C++. This can make it much faster to return compilation results
from cache since preprocessing is a major expense for these.

Preprocessor cache mode is controlled by a configuration option which is true by default, as well as additional conditions described below.

To ensure that the cached preprocessor results for a source file correspond to the un-preprocessed inputs, sccache needs
to remember, among other things, all files included by the source file. sccache also needs to recognize
when "external factors" may change the results, such as system time if the `__TIME__` macro is used
in a source file. How conservative sccache is about some of these external factors is configurable, see below.

Preprocessor cache mode will be disabled in any of the following cases:

- Not compiling C or C++
- The configuration option is false
- Not using GCC or Clang
- Not using local storage for the cache
- Any of the compiler options `-Xpreprocessor`, `-Wp,` are present
- The modification time of one of the header files is too new (avoids a race condition)
- Certain strings such as `__DATE__`, `__TIME__`, `__TIMESTAMP__` are present in the source code,
  indicating that the preprocessor result may change based on external factors

The preprocessor cache may silently produce stale results in any of the following cases:

- When a source file was compiled and its results were cached, a header file would have been included if it existed, but it did
  not exist at the time. sccache does not know about such files, so it cannot invalidate the result if the header file later exists.
- A macro such as `__TIME__` (etc) is used in the source code and `ignore_time_macros` is enabled
- There are other external factors influencing the preprocessing result that sccache does not know about

Configuration options and their default values:

- `use_preprocessor_cache_mode`: `true`. Whether to use preprocessor cache mode. This can be overridden for an sccache invocation by setting the environment variable `SCCACHE_DIRECT` to `true`/`on`/`1` or `false`/`off`/`0`.
- `file_stat_matches`: `false`. If false, only compare header files by hashing their contents. If true, will use size + ctime + mtime to check whether a file has changed. See other flags below for more control over this behavior.
- `use_ctime_for_stat`: `true`. If true, uses the ctime (file status change on UNIX, creation time on Windows) to check that a file has/hasn't changed. Can be useful to disable when backdating modification times in a controlled manner.

- `ignore_time_macros`: `false`. If true, ignore `__DATE__`, `__TIME__` and `__TIMESTAMP__` being present in the source code. Will speed up preprocessor cache mode, but can produce stale results.

- `skip_system_headers`: `false`. If true, the preprocessor cache will only add the paths of included system headers to the cache key but ignore the headers' contents.

- `hash_working_directory`: `true`. If true, will add the current working directory to the cache key to distinguish two compilations from different directories.
- `max_size`: `10737418240`. The size of the preprocessor cache, defaults to the default disk cache size.
- `rw_mode`: `ReadWrite`. ReadOnly or ReadWrite mode for the cache.
- `dir`: `path_to_cache_directory`. Path to the preprocessor cache, By default it will use DiskCache's directory, under subdirectory `preprocessor`.

See where to write the config in [the configuration doc](Configuration.md).

`sccache --debug-preprocessor-cache` can be used to investigate the content of the preprocessor cache.

The preprocessor cache uses random read and write; thus, certain file systems, including `s3fs`, are not supported.