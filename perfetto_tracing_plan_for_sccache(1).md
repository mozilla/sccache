# Implementation Plan: Perfetto-Compatible Tracing for `sccache`

This document outlines a detailed, commit-by-commit plan to add zero-dependency, Perfetto-compatible tracing to `sccache`, modeled after how Ninja (`ninjatracing`) and Clang (`-ftime-trace`) emit Chrome Trace Event Format JSON.

## 1. Overview & Design Philosophy

Perfetto natively ingests the **Chrome Trace Event Format (JSON Array Format)** without requiring the Perfetto C++ SDK or Protobuf definitions. Just like Ninja and `rustc -Zself-profile`, `sccache` can directly serialize JSON trace events using `serde_json`.

### Key Design Goals:

1. **Zero External Tracing SDKs**: Use `serde` and `serde_json` to write standard Chrome Trace JSON objects (`ph: "X"`, `"M"`, `"C"`).

2. **Async & Multi-Thread Track Allocation**: Because async tasks in Tokio can yield across OS threads at `.await` boundaries, mapping spans to raw OS thread IDs would cause overlapping/corrupted slices in Perfetto. Instead, we allocate **virtual `tid`s (Worker Slot IDs)** from a free-list pool per active compilation task.

3. **Support Both Daemon Mode & Client-Side Mode**: Events from both background daemons and client-side compilation runs (`SCCACHE_CLIENT_SIDE=1`) are unified into a single trace output.

4. **Rich Metadata & Counter Tracks**: Every compilation slice carries `filename` / `output_pretty` arguments, cache status (`Hit`, `Miss`, `Tier`), and time-series counter tracks (`ph: "C"`) for storage tiers and overall hit rates.

## 2. Commit-by-Commit Implementation Plan

### Commit 1: Core Trace Infrastructure & Chrome Trace Format Serialization

**Goal:** Implement the foundational serialization module, trace writer, and configuration interface without touching existing compilation pipelines.

- [x] **Create `src/trace.rs`**
  - [x] Define `TraceEvent` with Chrome Trace Event fields using `serde::Serialize`.
  - [x] Implement `Tracer` with `Arc<Mutex<BufWriter<File>>>` initialized with opening `[\n`.
  - [x] Expose global singleton access via `std::sync::OnceLock<Tracer>`.
  - [x] Define thread-safe track allocation (`TrackAllocator`) using a free-list of `tid`s.
  - [x] Define `tokio::task_local!` context `TRACE_CONTEXT`.
  - [x] Define RAII `SpanGuard` that captures timestamps and emits duration events (`ph: "X"`) on `Drop`.
- [x] **Update Configuration (`src/config.rs`)**
  - [x] Add `trace_file: Option<PathBuf>` to `FileConfig` and `Config`.
  - [x] Support reading environment variable `SCCACHE_TRACE`.
- [x] **Wire Initialization & Teardown (`src/server.rs`, `src/commands.rs`)**
  - [x] Initialize `Tracer` during `start_server`.
  - [x] Call `Tracer::flush()` during graceful daemon shutdown.

### Commit 2: Top-Level Compilation Spans & Worker Track Allocation

**Goal:** Hook into the request lifecycle to emit root compilation slices with filename and outcome metadata.

- [x] **Attach Worker Slot to Compilation Requests (`src/server.rs`)**
  - [x] In `SccacheService::handle_compile`, lease a `TrackGuard`.
  - [x] Scope `check_compiler` within `TRACE_CONTEXT`.
- [x] **Root Compilation Event (`src/server.rs`)**
  - [x] In `SccacheService::start_compile_task`, wrap the execution in a root `SpanGuard` (`compile: <output_pretty>`).
  - [x] Update `args` upon completion with cache hit/miss status and compiler details.

### Commit 3: Parsing Instrumentation (CLI Args, Includes & Dependencies)

**Goal:** Instrument internal parsing logic as nested child spans within the compilation worker track.

- [x] **Command-Line & Compiler Option Parsing (`src/server.rs`)**
  - [x] Wrap `c.parse_arguments` with span `"parse_arguments"`.
- [x] **Direct Preprocessor Cache Parsing (`src/compiler/preprocessor_cache.rs`)**
  - [x] Add `"parse_preprocessor_includes"` and `"scan_file"` spans. (`parse_preprocessor_includes` wraps `process_preprocessed_file` in `src/compiler/c.rs`; `scan_file` is per include in `result_matches`.)
- [x] **Compiler Dependency Parsing (`src/compiler/gcc.rs`, `src/compiler/msvc.rs`, `src/compiler/rust.rs`)**
  - [x] Wrap dependency file parsing with `"parse_dependencies"`. (Only `rust.rs` parses a dependency file; gcc.rs reads `@` response files and msvc.rs has no dependency file parsing, so nothing to wrap there.)

### Commit 4: Tool Execution & Process Spans

**Goal:** Track external sub-process executions (preprocessor calls, compiler invocations).

- [x] **Compiler Probing Spans (`src/server.rs`)**
  - [x] Wrap compiler probing with span `"tool: detect_compiler"`. (Wraps the `get_compiler_info` call in `compiler_info`; the probe runs before the `compile:` slice starts, on the same worker track.)
- [x] **Preprocessor & Compiler Invocations (`src/util.rs`, `src/compiler/*.rs`)**
  - [x] Wrap external preprocessor child processes with span `"tool: preprocess"`. (Wraps the `preprocess` call in `CCompiler::compile`, which covers all C-family compilers, so no per-compiler changes.)
  - [x] Emit `"tool: compile"` duration span via `run_input_output`. (Emitted in `SingleCompileCommand::execute` around the `run_input_output` calls, so it covers local compiles only.)

### Commit 5: Storage Tier Instrumentation & Async Backfills

**Goal:** Provide granular visibility into individual cache backends and background L1/L2 multi-level backfill tasks.

- [ ] **Base Storage Interface Instrumentation (`src/compiler/compiler.rs`)**
  - [ ] Wrap `storage.get` / `storage.put` calls with `"storage: {cache_type} get/put"`.
- [ ] **Multi-Level Storage & Async Backfills (`src/cache/multilevel.rs`)**
  - [ ] Define dedicated track `pid: 2` (`"sccache Async Background & Backfill"`).
  - [ ] Instrument spawned tasks with `"backfill: L{from} -> L{to}"`.

### Commit 6: Metric Counters & Time-Series Graphs

**Goal:** Emit Perfetto counter events (`ph: "C"`) to visualize cache hit rates and per-tier storage activity.

- [ ] **Overall Cache Hit Rate & Storage Counters**
  - [ ] Emit counter events for `"Cache Totals"` (hits, misses, errors).
  - [ ] Emit counter events for `"Tier L{idx} ({cache_type})"` in `MultiLevelStorage`.

### Commit 7: Client-Side Mode Unification

**Goal:** Propagate trace data from `SCCACHE_CLIENT_SIDE=1` CLI processes to the daemon trace file.

- [ ] **Client-Side Mode Forwarding (`src/protocol.rs`, `src/server.rs`)**
  - [ ] Extend `Request::RecordStats` to capture events produced during client-side execution.
  - [ ] In `SccacheService::merge_stats`, drain received events and write them to the central trace file under dedicated client tracks.

---

## 3. Test Design & Strategy

To ensure tracing is reliable, low-overhead, and produces valid JSON that Perfetto can ingest, testing will be split into three tiers: Unit Tests, Integration Tests, and JSON Trace Validation.

### 3.1 Unit Testing (Tracing Primitives)
Located primarily in `src/trace.rs`, these tests validate the core data structures without requiring a full `sccache` daemon.

-   **`TrackAllocator` Logic:**
    -   *Test:* Concurrently request multiple `TrackGuard`s using threads or tokio tasks.
    -   *Assertion:* Ensure no two active guards share the same `tid`.
    -   *Assertion:* Ensure that when a guard is dropped, its `tid` is pushed back to the free-list and successfully reused by the next request.
-   **Trace Serialization Formatting:**
    -   *Test:* Instantiate a `Tracer` with an in-memory buffer, record a few `TraceEvent`s (including nested `SpanGuard` drops), and flush.
    -   *Assertion:* The output begins with `[\n`, entries are comma-separated, and the raw text parses perfectly via `serde_json::from_slice::<Vec<TraceEvent>>` (after artificially appending the closing `]`).
-   **`tokio::task_local!` Context Propagation:**
    -   *Test:* Spawn a tokio task, set the `TRACE_CONTEXT`, and spawn a sub-task.
    -   *Assertion:* The sub-task correctly reads the parent's `tid` and `pid`.

### 3.2 Integration Testing (End-to-End Tracing)
Located in `tests/system.rs` and `tests/sccache_cargo.rs`, these tests evaluate the end-to-end behavior of the daemon when tracing is enabled.

-   **Daemon Mode Tracing:**
    -   *Test:* Set `SCCACHE_TRACE=<temp_file.json>`. Run a sequence of compilations (one miss, one hit). Stop the server via `sccache --stop-server`.
    -   *Assertion:* The `<temp_file.json>` exists on disk, has a non-zero size, and successfully parses as JSON.
-   **Client-Side Mode Tracing (`SCCACHE_CLIENT_SIDE=1`):**
    -   *Test:* Start the daemon. Set `SCCACHE_CLIENT_SIDE=1` and `SCCACHE_TRACE=<temp_file.json>`. Run a compilation.
    -   *Assertion:* Trace events generated by the client process (e.g., `tool: compile`) are forwarded to the daemon via IPC and appear in the daemon's trace file under a distinct client `pid`.
-   **Multi-Level Cache Backfills:**
    -   *Test:* Configure a two-level cache (L0 = Disk, L1 = Mock/Memory). Force an L1 hit.
    -   *Assertion:* Ensure the trace file captures the asynchronous backfill event (`"backfill: L1 -> L0"`) occurring on the dedicated async background track (`pid: 2`).

### 3.3 Trace Structure Validation (The "Perfetto Linter")
To guarantee that the emitted JSON will render correctly in the Perfetto UI, we will write a custom test helper function (`validate_trace_structure`) used in the integration tests.

This helper will parse the JSON array and perform the following semantic checks:
1.  **Metadata Presence:** Ensure there are `ph: "M"` events defining `process_name` and `thread_name` for `pid: 1` (Workers), `pid: 2` (Background Tasks), and `pid: 0` (Metrics).
2.  **Span Nesting & Ordering:**
    -   Filter events by `(pid, tid)`.
    -   Sort by timestamp (`ts`).
    -   Iterate through the events and ensure that for any nested duration slices (`ph: "X"`), `child.ts >= parent.ts` and `(child.ts + child.dur) <= (parent.ts + parent.dur)`.
3.  **Mandatory Arguments:**
    -   Ensure all `"compile: *"` events contain the `"result"` key (Hit/Miss) in their `args` object.
4.  **Counters Existence:** Ensure at least one `ph: "C"` event exists for `"Cache Totals"`.

### 3.4 Concurrency & Stress Testing
-   *Test:* Run a highly parallel build (e.g., `cargo build -j 32` on a dummy crate) with `SCCACHE_TRACE` enabled.
-   *Assertion:* Ensure the daemon does not panic, the trace file flushes correctly on shutdown, and the `Tracer` mutex does not cause a hard deadlock under high contention. Verify that the max allocated `tid` roughly matches the peak concurrency, confirming free-list reuse is functioning under load.

---

## 4. Status Summary

### 4.1 Commits on `main`

| Commit | Scope |
|---|---|
| `dd1f74d` | Perfetto-compatible trace writer and `SCCACHE_TRACE` option (commit 1) |
| `2644c23` | Root span per compilation (commit 2) |
| `00a9ef1` | Trace file tested on Windows and with compilations |
| `57ca141` | Compile work kept on the worker track |
| `e9f70ba` | Spans for argument, include and dep-info parsing (commit 3) |
| `e20826a` | `scan_file` records `miss_reason` on failure |

Uncommitted at the time of writing: commit 4 (`tool: detect_compiler`, `tool: preprocess`, `tool: compile`) in `src/server.rs`, `src/compiler/c.rs`, `src/compiler/compiler.rs`, with tests in `tests/server.rs`.

### 4.2 Span reference

| Span | Where | Args | Notes |
|---|---|---|---|
| `compile: <output>` | `start_compile_task` | `result` (Hit/Miss), `compiler` | Root slice per compilation |
| `parse_arguments` | `check_compiler` | none | Measured 4–24 µs; not nested inside `compile:` |
| `parse_preprocessor_includes` | `c.rs` | none | Miss only; 2.4 ms on a 16-include file |
| `scan_file` | `preprocessor_cache.rs` | `path`, `miss_reason` on failure | One per recorded include. Checks the file's size and stat, then hashes it if stat differs. `miss_reason`: `stat`, `size`, `open`, `read`, `digest`, `time_macro` |
| `parse_dependencies` | `rust.rs` | none | Rust only; about 0.03 ms |
| `tool: detect_compiler` | `server.rs` | `executable` | Runs before `compile:` on the same track. Rustc takes about 100 ms and repeats on every rustc request |
| `tool: preprocess` | `c.rs` | `executable` | Miss only |
| `tool: compile` | `compiler.rs` | `executable` | Local compile only; not distributed |

### 4.3 Measurements and findings

- On a C hit, `scan_file` takes about 1.3 ms of a 1.5 ms request. Each C hit checks 136 includes for a 16-include source file, so the spans grow with the include graph.
- A C miss takes about 42 ms. About 40 ms of it was unspanned before commit 4.
- A rustc hit takes about 10 ms, and only `parse_dependencies` was spanned before commit 4.
- Rustc detection repeats on every rustc request (about 100 ms each). The C path caches detection and doesn't repeat it. The cause is not investigated.
- Open question: one aggregate `scan_file` span per compile with a `count` arg would cut trace volume. The change would need an update to `test_server_traces_preprocessor_cache`.

### 4.4 Open items

- Commit 4 is not committed yet.
- Commit 5 (storage tiers and backfills) and commit 6 (counters) are not started.
- Commit 7 (client-side forwarding) is not started.
- The `scan_file` volume question above is unresolved.
- Rustc detection repeats on every request.
- `src/lsp_probe.rs` is untracked and not part of this work.
- Clippy fails with 27 errors on the installed toolchain (`must_use` and `vec!` lints). These errors predate the tracing work.

---

## 5. How to Create a Trace

Tracing is off unless `SCCACHE_TRACE` is set when the server starts. The server writes the file while it runs and finishes it on shutdown, so the file is only valid JSON after `--stop-server`.

```sh
D=$(mktemp -d)
export SCCACHE_DIR=$D/cache
export SCCACHE_TRACE=$D/trace.json

sccache --start-server
sccache cc -c main.c -o main.o      # miss
sccache cc -c main.c -o main.o      # hit
sccache --stop-server

echo "$SCCACHE_TRACE"
```

Notes:

- `SCCACHE_TRACE` must be set in the environment of the server, not only the client. If the server is already running, stop it and start it again with the variable set.
- `trace_file` in the configuration file sets the same path. `SCCACHE_TRACE` takes precedence (see `docs/Configuration.md`).
- Open the file at <https://ui.perfetto.dev> with "Open trace file". The file is a Chrome Trace Event JSON array.
- Worker tracks (`pid` 1) hold one row per concurrent compilation. Track `tid` values are reused.
- To check the file is complete, parse it with `python3 -m json.tool trace.json > /dev/null`. An unfinished file fails to parse.
- To count a span name per compile in a trace, see the Python snippets used in this session. They group child spans by `tid` and by time range.
- Trace files should live outside the repository (for example in `/tmp`). The repository has no tracked trace files.

Traces used for measurements in this session:

- `/tmp/s3_measure.v1LB/trace.json`: stage 3 measurements (before the `path` arg)
- `/tmp/scan_path_trace.0Ojb/trace.json`: `scan_file` with `path`
- `/tmp/scan_miss_trace.EoD1/trace.json`: header change, cache miss, before `miss_reason`
- `/tmp/scan_reason_trace.MWB5/trace.json`: `miss_reason: digest`
- `/tmp/phase4.xqJG/trace.json`: commit 4 spans (debug build)

These paths are in `/tmp` and may be removed by the system.
