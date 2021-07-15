# Threat model


By definition, PRs can contain arbitrary code.
With the rust ecosystem it's common to have custom code
in the form of `proc_macro`s being run as part of
the compilation process. As a consequence,
there must be measures taken to avoid fallout.

## Assumptions

A single rust invocation does _not_ require any kind of internet access.
This precludes any `proc_macro`s that implement and web or socket based queries
from working with `cachepot`.

## Goals

make the build server to securely and fast provide build artifacts, if possible increase the possibility of caching computations with security precautions.
The goal of cachepot is to provide a secure compilation and artifact caching system, where a set of inputs is derived from a compiler invocation (i.e. rustc) and computed on the remote worker. The crucial part here is to provide a robust mapping from those input sets to cached compile artifacts in an efficient manner.


### Guarantees

For a given set of inputs, user should get the appropriate cached artifact that was created by an equivalent commandlind invocation of the compiler minus some path prefix changes.

### Sandbox

The `rustc` invocation on the `cachepot server` must never have access to the host environment or storage.

#### Current

Built-in support for `bubblewrap` (with the binary `bwrap`) and `docker`.
`bubblewrap` is the prefered choice.
#### Hardening
Future considerations include adding a `KVM` based sandboxing for further hardening i.e. [Quark][quark], [katacontainers][kata], or [firecracker][firecracker]

### Cache poisoning

Independence between compiler invocation, such that no invocation of a (potentially malicious) invocation
can lead to delivering incorrect artifacts.
It must be impossible to modify existing artifacts.

#### Current

> TODO

#### Hardening

Assure the hash is verified on the server side, such that the client has no power over the hash calculation.

> TODO

### Container poisoning

Proper measures should be introduced to prevent containers to be poisoned between runs.

#### Current Measure

Use overlay fs with bubblewarp or and ephemeral containers with docker.
Containers as such or their storage are never re-used.


[quark]: https://github.com/QuarkContainer/Quark
[firecracker]: https://github.com/firecracker-microvm/firecracker
[kata]: https://katacontainers.io/
