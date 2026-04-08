use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // All remote cache backends
        any_cache_remote: {
            any(
                feature = "azure",
                feature = "gcs",
                feature = "gha",
                feature = "memcached",
                feature = "redis",
                feature = "s3",
                feature = "webdav",
                feature = "oss",
                feature = "cos"
            )
        },
        // HTTP-based remote cache backends (excludes memcached and redis)
        any_http_remote: {
            any(
                feature = "azure",
                feature = "gcs",
                feature = "gha",
                feature = "s3",
                feature = "webdav",
                feature = "oss",
                feature = "cos"
            )
        },
        // Distributed compilation features
        any_dist: {
            any(
                feature = "dist-client",
                feature = "dist-server"
            )
        },
    }
}
