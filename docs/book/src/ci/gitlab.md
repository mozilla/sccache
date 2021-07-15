# integration with gitlab

Compilation outputs (stdout, stderr)

Compilation outputs allow attackers to leak data from inside of the execution environment. This also applies the `cachepot server` provided sandbox
and as such nothing of the CI environment should be deemed `s3cr1t`.

As the way `cachepot client` works, is that it's provided to `cargo` via `RUSTC_WRAPPER=cachepot`, therefore compilations will be executed on cachepot-dist server, but `build.rs` and invocations with uncachable elements are still being run on the client on the gitlab runner's executor.
As such, the security concerns for the `gitlab` worker are still to be kept high!

`cachepot-dist server` and `cachepot-dist scheduler` is a distinct service, therefore can run on another machine/instance.

## Interaction Graph

```raw
             +----------------------+
             |                      |
             |  +-----------------+ |
             |  |                 | |
             |  | parsing ci.yml  | |
             |  |                 | |
             |  +-----------------+ |
             |                      |
             | <instance>.gitlab.io |
             +----------+-----------+
                        |
                        |
                        |
                        |
                        |
                        v
+-----------------------+---------------------------+
|                                                   |   (In future we may
| +-(always-fresh container) execution-of-CI/CD--+  |   consider option
| |                                              |  |   ofcachepot client
| |                                              |  |   connecting from
| |          1st. fetch dependencies             |  |   employees machines)
| |                                              |  |
| | +---------------(optional)-----------------+ |  |
| | |       (restricting to be considered)     | |  |   here only "get"/"read" ACL
| | | 2. cargo build without internet access   | |  |    to cache
| | |                                          | |  |             as this container
| | | except for                            <------------<-----+  may be modified
| | | cachepot client <-> scheduler, server    | |  |          |  by
| | |      ^                     ^  cache "get"| |  |          |  gitlab-ci.yml
| | +------------------------------------------+ |  |          |  build.rs
| |        |                     |               |  |          |  proc-macros
| +----------------------------------------------+  |          |
|          |                     |                  |          |
|          |    gitlab runner    |                  |          ^
|          |                     |                  |          |
+---------------------------------------------------+          |
           |                     |                             |
           |                     |                             |
           |                     |                             |
           |                     |                             |
           |                     v                             ^
           |                +----+---------------+          get|
           |                |                    |             |
           |                | cachepot scheduler |             |
           |                |                    |     +-------+---------+
           |                +---+----------------+     |                 |
           |                    ^                      |                 |
           |                    |                      | s3-like cache   |
           |                    |                      |                 |
           |                    |                      |                 |
           v                    v                      |                 |
+----------+--------------------+--------+             +-----------------+
|                                        |
|                                        |                   put,get
|         container/sandbox              |                     ^
|   +---------(bubblewrap)--------+      |                     |
|   |(no internet,very restricted)|      |                     |
|   |                             |      |                     |
|   |                             |      |                     |
|   |    rustc etc.               |      |                     |
|   |                             |      |                     |
|   |                             |      |                     |
|   |                             |      |                     |
|   +-----------------------------+      |                     |
|                                        |                     |
|                                        +<--------------------+
|  cachepot server                       |
|                                        |
|                                        |
+----------------------------------------+
```
