# Local

sccache defaults to using local disk storage. You can set the `SCCACHE_DIR` environment variable to change the disk cache location. By default it will use a sensible location for the current platform: `~/.cache/sccache` on Linux, `%LOCALAPPDATA%\Mozilla\sccache` on Windows, and `~/Library/Caches/Mozilla.sccache` on MacOS.

The default cache size is 10 gigabytes. To change this, set `SCCACHE_CACHE_SIZE`, for example `SCCACHE_CACHE_SIZE="1G"`.

The local storage only supports a single sccache server at a time. Multiple concurrent servers will race and cause spurious build failures.

## Read-only cache mode

By default, the local cache operates in read/write mode. The `SCCACHE_LOCAL_RW_MODE` environment variable can be set to `READ_ONLY` (or `READ_WRITE`) to modify this behavior.

You can use read-only mode to prevent sccache from writing new cache items to the disk. This can be useful, for example, if you want to use items that have already been cached, but not add new ones to the cache. 

Note that this feature is only effective if you already have items in your cache. Using this option on an empty cache will cause sccache to simply do nothing, just add overhead.
