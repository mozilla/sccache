# roadmap

While we attempt to upstream as much as possible back to `sccache`, there is no guarantee
that the changes we make are also appropriate for the upstream which is used for the
`firefox` builds and might have different requirements.

## Priorities

1. Linux x86-64 first
2. Make `paritytech/substrate` and `paritytech/polkadot` work
3. Investigate performance bottlenecks
4. Implement additional security layers

### Linux x86-64 first

Most machines running as servers are x86_64 Linux machines today. Clients might be Mac or Windows.
We are focusing on Linux at the beginning and try to not break the existing support for Mac and Windows
on the client side. The server side will stay x86_64 Linux only, cross compilation is supported by (cross
-)toolchains.

### Performance Bottlenecks

The lookup keys are based on hashes includes timestamps and paths, as such re-usability of cache vars is very limited.
This is a performance limitation, since the cache is ultimately not shared.
There are of course various other performance topics that will be addressed but are not necessarily
part of this priority item.

### Additional Security layers

The biggest topic that has yet to be specified in detail, is the introduction
of multi layer caches, with different trust levels. I.e. a CI cluster could
warm caches every night with trusted storage. These could then be used
to fetch artifacts combined with a per-user cache for local repeated compiles.
