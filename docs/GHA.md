# GitHub Actions

To use the [GitHub Actions cache](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows), you need to set `SCCACHE_GHA_ENABLED` to `on` to enable it.

By changing `SCCACHE_GHA_VERSION`, we can purge all the cache.

This cache type will need tokens like `ACTIONS_CACHE_URL` and `ACTIONS_RUNTIME_TOKEN` to work. You can set these environmental variables using the following step in a GitHub Actions workflow.

```yaml
- name: Configure sccache
  uses: actions/github-script@v7
  with:
    script: |
      core.exportVariable('ACTIONS_CACHE_URL', process.env.ACTIONS_CACHE_URL || '');
      core.exportVariable('ACTIONS_RUNTIME_TOKEN', process.env.ACTIONS_RUNTIME_TOKEN || '');
```

## Behavior

In case sccache reaches the rate limit of the service, the build will continue, but the storage might not be performed.
