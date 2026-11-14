# sccache process architecture

This document describes *which code runs in which process* when sccache intercepts a compiler
invocation. For the caching data-flow (hash → storage lookup → compile → store) see
[Architecture.md](Architecture.md). For distributed compilation see
[Distributed.md](Distributed.md) and `src/dist/`.

---

## The two processes

sccache is a single binary that plays two roles, chosen at startup:

| Process | How it is detected | Entry point |
|---|---|---|
| **CLI** (short-lived) | Normal invocation — `SCCACHE_START_SERVER` not set | `commands::run_command` |
| **Daemon** (long-lived) | `SCCACHE_START_SERVER=1` in the environment | `server::start_server` |

The `Command` enum is parsed in the CLI process and dispatched in
`run_command`. The daemon never parses `Command`; it enters `start_server` directly.

### Compiler symlink trick

If the binary is invoked under a name other than `sccache` (e.g. as a symlink named `gcc`),
`cmdline::try_parse` prepends the real `sccache` name to `argv` so that
the rest of the CLI acts as `sccache gcc …`. This lets users drop sccache into a build's `CC`
without changing Makefiles.

---

## Server autostart

When the CLI needs to send a compile request but no daemon is listening, it starts one
automatically:

```
CLI
 └─ connect_or_start_server()          
     ├─ connect_to_server() → ECONNREFUSED
     └─ run_server_process()
         ├─ bind a Unix socket for startup notification
         ├─ spawn child: same binary + SCCACHE_START_SERVER=1 + SCCACHE_STARTUP_NOTIFY=<path>
         └─ await ServerStartup::Ok { addr } (length-prefixed bincode on the notify socket)
```

The daemon signals readiness by writing `ServerStartup::Ok { addr }` on the notification socket
before entering its accept loop. The CLI reads it with
`read_server_startup_status`.

---

## IPC transport

Both processes speak over a single persistent TCP connection (or Unix domain socket):

- **Address**: `127.0.0.1:4226` by default, overridable with `SCCACHE_SERVER_PORT`; UDS path via
  `SCCACHE_SERVER_UDS`.
- **Framing**: 4-byte big-endian length prefix followed by a bincode-serialized payload.
- **CLI side**: synchronous `ServerConnection`; calls `request()` which writes a
  `Request`, then reads a `Response`.
- **Daemon side**: async `LengthDelimitedCodec` + `tokio_serde::Framed<BincodeCodec>`
 , driven by a Tower service.

---

## Wire protocol

Types live in `protocol.rs`.

A compile exchange uses a **two-response pattern**:

```
CLI                          Daemon
 ── Request::Compile ──────►
 ◄── Response::Compile ──────
       (CompileStarted |
        UnhandledCompile |
        UnsupportedCompiler)
 ◄── Response::CompileFinished ─   (only when CompileStarted was sent)
```

Other requests (`GetStats`, `Shutdown`, `ZeroStats`, `DistStatus`) get a single response.

---

## What runs where

This is server mode. In client-side mode the CLI runs all of these steps itself
and uses the daemon only as a proxy to the cache storage; see
[Architecture.md](Architecture.md#client-side-mode-sccache_client_side).

| Step | Server mode |
|---|---|
| Parse compiler arguments | **Daemon** |
| `which` / resolve compiler path | CLI |
| Detect compiler type & version | **Daemon** |
| Preprocess source file | **Daemon** |
| Hash inputs (args + preprocessed output + env) | **Daemon** |
| Consult preprocessor cache (direct mode) | **Daemon** |
| Cache get | **Daemon** |
| Compile (on cache miss) | **Daemon** |
| Cache put | **Daemon** |
| Capture and return stdout / stderr | **Daemon** → written by CLI |
| Accumulate statistics | **Daemon** |
| Jobserver token management | CLI |
| IPC framing | CLI + Daemon |
| `UnhandledCompile` fallback (unsupported invocation) | CLI |

---

## Daemon compile pipeline

```
start_server
 └─ accept loop → Tower Service::call
     └─ handle_compile
         ├─ compiler_info
         │    memoised in self.compilers; runs the compiler once to detect type & version
         ├─ check_compiler
         │    validates the detected compiler is cacheable
         └─ start_compile_task
             └─ CompilerHasher::get_cached_or_compile
                 ├─ generate_hash_key  — preprocess + hash
                 ├─ storage.get(key)   — cache lookup
                 ├─ [on miss] Compilation::compile
                 └─ storage.put(key, entry)
```

`SccacheService<C>` is generic over `C: CommandCreatorSync`, which
allows unit tests to inject a mock command runner. In production the daemon uses
`ProcessCommandCreator`.

---

## C/C++ preprocessor mode

`CCompilerHasher::generate_hash_key` drives the C/C++ cache key:

1. Run the preprocessor (`CCompilerImpl::preprocess`, e.g. `gcc.rs`) to expand all
   `#include`s and `#define`s.
2. Hash the preprocessed output together with compiler path, version, and relevant flags.
3. **Optional direct mode** (`preprocessor_cache_mode_config`): before preprocessing, digest the
   raw input file and all its includes, and consult the *preprocessor cache* — a second LRU
   store (disk only) keyed by those digests (`c.rs`,
   `Storage::get_preprocessor_cache_entry`). A hit avoids the preprocessor fork entirely.

---

## Storage backends

`trait Storage` (`src/cache/storage.rs`) abstracts over all backends. Key methods:

- `get(key) -> Cache` — returns `Hit(CacheRead)`, `Miss`, `Recache`, or `None`.
- `put(key, CacheWrite) -> Duration` — stores a compiled result.
- `get_preprocessor_cache_entry` / `put_preprocessor_cache_entry` — direct-mode side table.

Backends (under `src/cache/`): local disk (`disk.rs`), S3, GCS, Redis, Memcached, Azure,
GitHub Actions cache, WebDAV, Alibaba OSS, Tencent COS, and a read-only wrapper.
`MultiLevelStorage` chains a fast local cache in front of a remote backend.
`storage_from_config` selects the backend at daemon startup.

Cache entries are zip archives (declared `Stored`, actually zstd-compressed blobs inside) built
by `CacheWrite` / read back by `CacheRead` (`cache/cache_io.rs`).

---

## Distributed compilation

When the `dist-client` feature is enabled, `start_compile_task` can dispatch to remote build
servers instead of compiling locally. The distributed layer lives in `src/dist/` and is
described in [Distributed.md](Distributed.md). This document does not cover it further.
