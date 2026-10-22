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

- [ ] **Command-Line & Compiler Option Parsing (`src/server.rs`)**
  - [ ] Wrap `c.parse_arguments` with span `"parse_arguments"`.
- [ ] **Direct Preprocessor Cache Parsing (`src/compiler/preprocessor_cache.rs`)**
  - [ ] Add `"parse_preprocessor_includes"` and `"scan_file"` spans.
- [ ] **Compiler Dependency Parsing (`src/compiler/gcc.rs`, `src/compiler/msvc.rs`, `src/compiler/rust.rs`)**
  - [ ] Wrap dependency file parsing with `"parse_dependencies"`.

### Commit 4: Tool Execution & Process Spans

**Goal:** Track external sub-process executions (preprocessor calls, compiler invocations).

- [ ] **Compiler Probing Spans (`src/server.rs`)**
  - [ ] Wrap compiler probing with span `"tool: detect_compiler"`.
- [ ] **Preprocessor & Compiler Invocations (`src/util.rs`, `src/compiler/*.rs`)**
  - [ ] Wrap external preprocessor child processes with span `"tool: preprocess"`.
  - [ ] Emit `"tool: compile"` duration span via `run_input_output`.

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
