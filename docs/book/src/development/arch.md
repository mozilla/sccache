# Architecture

Describes the current state of the architecture.

While cachepot can also run in a serverless mode, the primary focus here is on running
in so called `dist`-mode, which is the default for `cachepot`, where it is _not_ the default for `sccache`.

## Components

* `cachepot` - is the client with whom the end user interacts.
* `cachepot-dist scheduler` - has knowledge of all available workers and distributes compile tasks
* `cachepot-dist server` - this receives compilation requests, as performs job of rustc
* `toolchain cache` - the toolchains are cached on the server side in `icecream` format
* `cache`


## cachepot

The cachepot client is launched as compiler wrapper binary.
This is achieved in the case of `cargo` /w setting `RUSTC_WRAPPER=$(which cachepot)` or
setting it explicitly in your `.config/cargo.toml`.

## cachepot scheduler

A known service, that takes care of distributing individual compiles to `cachepot server`s
based on a workload queue. The decision is based on the queue length which is propagated
from the `server` back to the `scheduler`.

## cachepot server

The component that does the actual, sandboxed, compilation.
It's run via `cachepot-dist server`.
