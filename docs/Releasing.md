# Sccache Release Process

Most of the sccache release process is automated, [there are Linux/macOS release builds](https://github.com/mozilla/sccache/blob/5bb5d047e27bd8e69da0e1cab2882468313cd080/.travis.yml#L17-L27) in the Travis CI configuration, [as well as a `deploy` section](https://github.com/mozilla/sccache/blob/5bb5d047e27bd8e69da0e1cab2882468313cd080/.travis.yml#L46-L57) that will create a GitHub release which is triggered by pushing a new tag to the repository. Similarly [there is a release build](https://github.com/mozilla/sccache/blob/5bb5d047e27bd8e69da0e1cab2882468313cd080/appveyor.yml#L40-L43) in the AppVeyor configuration and [a `deploy` section](https://github.com/mozilla/sccache/blob/5bb5d047e27bd8e69da0e1cab2882468313cd080/appveyor.yml#L68-L76) that triggers on new tags being pushed. Both CI configs will upload the resulting binary packages to [the GitHub releases page](https://github.com/mozilla/sccache/releases) on the repository.

The `api_key` / `auth_token` in each CI configuration contains an encrypted GitHub API token for the [`sccachereleasebot`](https://github.com/sccachereleasebot) user, which has write permission to the sccache repository for creating release.

# Producing a release

Historically I have used [`cargo-release`](https://github.com/sunng87/cargo-release) to produce releases, since it encapsulates the steps of bumping the version number, creating and pushing a new tag, and releasing to [crates.io](https://crates.io/crates/sccache). You can install it with `cargo install cargo-release`, then simply run `cargo release` in an sccache checkout to do the work. Note that it supports a `--dry-run` option you can use to preview what it will run.

## Things to be aware of

1. You must have authenticated to crates.io using `cargo login` to publish the sccache crate there.
2. cargo will not allow publishing a crate if there are crates in the `[patch]` section in `Cargo.toml`. As of this writing there are two crates patched and the upstream pull requests have not been merged. For the previous release [I created a branch](https://github.com/mozilla/sccache/commits/0.2.8-workaround) and [removed the patch on that branch](https://github.com/mozilla/sccache/commit/978813cef19161ced6be33da517f8c4feac060dc) in order to release, since that patch was only necessary for `sccache-dist` usage.
