# GitHub Actions

To use the [GitHub Actions cache](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows), you need to set the `SCCACHE_GHA_CACHE_URL`/`ACTIONS_CACHE_URL` and `SCCACHE_GHA_RUNTIME_TOKEN`/`ACTIONS_RUNTIME_TOKEN` environmental variables. The `SCCACHE_` prefixed environmental variables override the variables without the prefix.

In a GitHub Actions workflow, you can set these environmental variables using the following step.

```yaml
- name: Configure sccache
  uses: actions/github-script@v6
  with:
    script: |
      core.exportVariable('ACTIONS_CACHE_URL', process.env.ACTIONS_CACHE_URL || '');
      core.exportVariable('ACTIONS_RUNTIME_TOKEN', process.env.ACTIONS_RUNTIME_TOKEN || '');
```

To write to the cache, set `SCCACHE_GHA_CACHE_TO` to a cache key, for example
`sccache-latest`. To read from cache key prefixes, set `SCCACHE_GHA_CACHE_FROM`
to a comma-separated list of cache key prefixes, for example `sccache-`.

In contrast to the [`@actions/cache`](https://github.com/actions/cache) action, which saves a single large archive per cache key, `sccache` with GHA cache storage saves each cache entry separately.

GHA cache storage will create many small caches with the same cache key, e.g. `SCCACHE_GHA_CACHE_TO` and `SCCACHE_GHA_CACHE_FROM`. These GHA caches are differentiated by their [_version_](https://github.com/actions/cache#cache-version). The GHA cache implementation in `sccache` calculates the cache version from the [`sccache` entry key](docs/Caching.md), e.g. the source file path.

For example, if a cache entry has the version `main.rs` and has GHA cache entries for the `sccache-1` and `sccache-2` keys, then `SCCACHE_GHA_CACHE_FROM=sccache-` will match both and [return the most recent entry](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#matching-a-cache-key).

This behavior is useful for scoping caches from different versions of Rust or for cross-platform builds (`rust-sdk-{RUST_TOOLKIT}-{TARGET_TRIPLE}-`), and to allow newer commits to override older caches by adding the Git SHA as a suffix (`-{GITHUB_SHA}`), as in the following screenshot.

<img width="718" src="https://user-images.githubusercontent.com/19253212/205356799-deedc465-e534-4ef6-a249-fc15121fdfd9.png">
