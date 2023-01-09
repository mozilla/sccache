# GitHub Actions

To use the [GitHub Actions cache](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows), you need to set the `SCCACHE_GHA_VERSION` which is a namespace for the whole cache set.

This cache type will needs token like `ACTIONS_CACHE_URL` and `ACTIONS_RUNTIME_TOKEN` to work. You can set these environmental variables using the following step in a GitHub Actions workflow.

```yaml
- name: Configure sccache
  uses: actions/github-script@v6
  with:
    script: |
      core.exportVariable('ACTIONS_CACHE_URL', process.env.ACTIONS_CACHE_URL || '');
      core.exportVariable('ACTIONS_RUNTIME_TOKEN', process.env.ACTIONS_RUNTIME_TOKEN || '');
```

## Behavior

Sccache has a need to access and create caches separately. So, in contrast to the [`@actions/cache`](https://github.com/actions/cache) action, which saves a single large archive per cache key, `sccache` with GHA cache storage saves each cache entry separately.

So while visiting `Caches` Under Github's Action tab, you will see a lot of cache entries like the following:

![image](https://user-images.githubusercontent.com/5351546/211239569-11ca3e41-8906-4420-b69f-7fc3d1af20e5.png)
