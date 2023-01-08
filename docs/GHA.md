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
