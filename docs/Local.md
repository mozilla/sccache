# Local

sccache defaults to using local disk storage. You can set the `SCCACHE_DIR` environment variable to change the disk cache location. By default it will use a sensible location for the current platform: `~/.cache/sccache` on Linux, `%LOCALAPPDATA%\Mozilla\sccache` on Windows, and `~/Library/Caches/Mozilla.sccache` on MacOS.

The default cache size is 10 gigabytes. To change this, set `SCCACHE_CACHE_SIZE`, for example `SCCACHE_CACHE_SIZE="1G"`.

The local storage only supports a single sccache server at a time. Multiple concurrent servers will race and cause spurious build failures.

## Preprocessor cache mode

This is inspired by [ccache's direct mode](https://ccache.dev/manual/3.7.9.html#_the_direct_mode) and works roughly the same.

It can be set with by setting the variable:
```
SCCACHE_DIRECT=true
```

In preprocessor cache mode, sccache caches the preprocessor step for C/C++ whenever possible. This can make the compilation a lot faster, since the preprocessor accounts for a non-negligible amount of time in the entire compile chain.

In order to cache the preprocessor step sccache needs to remember, among other things, all files included by the given input file. To quote ccache's documentation:

> There is a catch with the [preprocessor cache] mode: header files that were used by the compiler are recorded, but header files that were not used, but would have been used if they existed, are not. So, when [sccache] checks if a result can be taken from the cache, it currently can’t check if the existence of a new header file should invalidate the result. In practice, the [preprocessor cache] mode is safe to use in the absolute majority of cases.

Preprocessor cache mode will be disabled if any of the following holds:

- the configuration setting `use_preprocessor_cache_mode` is false
- a modification time of one of the include files is too new (needed to avoid a race condition)
- a compiler option not supported by the preprocessor cache mode is used. Currently, this is only `-Xpreprocessor` and `-Wp,*`, but if/when sccache grows to handle options then more could be added to this list.
- the string `__TIME__` is present in the source code

Configuration options and their default values:

- `use_preprocessor_cache_mode`: `true`. Whether to use preprocessor cache mode entirely.
- `file_stat_matches`: `false`. If false, only compare header files by hashing their contents. If true, will use size + ctime + mtime to check whether a file has changed. See other flags below for more control over this behavior.
- `use_ctime_for_stat`: `true`. If true, uses the ctime (file status change on UNIX, creation time on Windows) to check that a file has/hasn't changed. Can be useful to disable when backdating modification times in a controlled manner.

- `ignore_time_macros`: `false`. If true, ignore `__DATE__`, `__TIME__` and `__TIMESTAMP__` being present in the source code. Will speed up preprocessor cache mode, but can result in false positives.

- `skip_system_headers`: `false`. If true, preprocessor cache mode will not cache system headers, only add them to the hash.

- `hash_working_directory`: `true`. If true, will add the current working directory in the hash to distinguish two compilations from different directories.

See where to write the config in [the configuration doc](Configuration.md).

*Note that preprocessor caching is currently only implemented for GCC and Clang and when using local storage.*

## Read-only cache mode

By default, the local cache operates in read/write mode. The `SCCACHE_LOCAL_RW_MODE` environment variable can be set to `READ_ONLY` (or `READ_WRITE`) to modify this behavior.

You can use read-only mode to prevent sccache from writing new cache items to the disk. This can be useful, for example, if you want to use items that have already been cached, but not add new ones to the cache. 

Note that this feature is only effective if you already have items in your cache. Using this option on an empty cache will cause sccache to simply do nothing, just add overhead.
