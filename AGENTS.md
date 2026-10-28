# AGENTS.md

Writing this file is not a statement for or against using AI coding agents.
People are using them on this repository either way, so this file exists to make
sure that when they do, the rules of the project are actually followed.

If you are driving an agent here, you are responsible for its output. Read the
diff before you send it.

Answers to the reviewers should be done by a human, not an agent.

## 1. A PR needs tests

New behavior or a bug fix comes with a test:

- compiler argument parsing, hashing, cache key computation: a unit test in the
  `mod test` block of the file you changed (`src/compiler/gcc.rs`,
  `src/compiler/nvcc.rs`, `src/cache/cache.rs`, ...)
- end-to-end behavior (real compiler invocation, cache hit/miss, server
  lifecycle): `tests/system.rs`, `tests/sccache_args.rs`,
  `tests/sccache_cargo.rs`, `tests/dist.rs`, ...

A new compiler flag is not "just a one-liner": if it changes what ends up in the
cache key, it needs a test that would catch getting it wrong. A wrong cache key
silently hands users someone else's object file.

No tests, no merge.

## 2. Keep the PR description short

Describe the problem being solved and what changed. That is all.

- No generated walls of text, no bullet-point summaries of every hunk, no
  emoji-headed sections.
- Title: `<area>: <what changed>`, e.g. `nvcc: fix dryrun parsing for CUDA 13.3`.
- Write issue reports, PR descriptions and replies to reviewers in your own
  words. The point of review is to check that a human understands the change.

## 3. Keep the code quiet too

Comments explain why, not what. Do not narrate the diff in the source, do not
leave "// Step 1: ..." scaffolding behind, and do not add doc comments that only
restate the function signature. Match the density of the surrounding file.

## 4. Run what CI runs

Before sending anything:

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings -A unknown-lints \
    -A clippy::type_complexity -A clippy::new-without-default
cargo test --locked --lib --bins --tests
```

Also keep in mind:

- MSRV is the `rust-version` in `Cargo.toml` (kept in sync with `README.md` and
  the CI toolchain). Do not use newer language or std features.
- Storage backends are cargo features (`s3`, `gcs`, `azure`, `redis`,
  `memcached`, `gha`, `webdav`, `oss`, `cos`, `dist-client`). Code must still
  build with `--no-default-features --features <one>`; CI checks each one.
- New dependencies need a reason in the PR description. `Cargo.lock` is
  committed and CI builds `--locked`.
- Some tests need real compilers (gcc, clang, msvc, nvcc) or a running server;
  if you skipped a test locally, say so instead of claiming it passed.

## 5. Read the docs already in this repo

Before changing anything, look at the Markdown files here - they are the actual
rules, this file is only a pointer:

- `README.md` - usage, supported compilers, build and install, MSRV
- `docs/Architecture.md` - client/server split, how a compilation is cached
- `docs/Caching.md`, `docs/Configuration.md`, `docs/Local.md` - cache layout and
  configuration; update these when you add or change a config knob
- `docs/Distributed.md`, `docs/DistributedQuickstart.md` - the scheduler/server
  side, read before touching `src/dist`
- the per-backend docs (`docs/S3.md`, `docs/Gcs.md`, `docs/Azure.md`,
  `docs/Redis.md`, `docs/Memcached.md`, `docs/Webdav.md`, `docs/GHA.md`,
  `docs/OSS.md`, `docs/COS.md`, `docs/MultiLevel.md`) when touching
  `src/cache/*`
- `docs/Rust.md`, `docs/Xcode.md`, `docs/ResponseFiles.md` - compiler-specific
  behavior
- `docs/Releasing.md`
