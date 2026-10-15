# mozilla/sccache Issue: Distributed Compilation Fails on Proc Macros with Build Artifacts

**Related Issue:** #1838

## Summary
Distributed sccache compilation fails hard when proc macros require access to build-time artifacts (files, scripts) that are location-dependent. The failure should gracefully fall back to local compilation instead of aborting the entire build.

## Reproduction

Build `grok-build` with distributed sccache enabled:

```bash
cd /home/kk/git-repos/grok-build
export SCCACHE_DIRECT=true
export RUSTC_WRAPPER=sccache
cargo build --release
```

**Failure point:** `wayland-client` crate during proc macro expansion

## Error Output

```
sccache: Job failed on server 192.168.1.2:10501:
error: proc macro panicked
   --> /home/kk/toolchains/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/wayland-client-0.31.12/src/lib.rs:219:9
    |
219 |         wayland_scanner::generate_interfaces!("wayland.xml");
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: message: Failed to open protocol file /home/kk/toolchains/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/wayland-client-0.31.12/wayland.xml: No such file or directory (os error 2)

error: could not compile `wayland-client` (lib) due to 8 previous errors
```

## Root Cause

1. **Proc macro execution on remote worker:** Proc macros like `wayland-scanner` are executed on the remote build server
2. **File path mismatch:** The proc macro tries to load `wayland.xml` using a relative path
3. **Missing build context:** The remote worker doesn't have the full source tree with the required `.xml` file
4. **No graceful fallback:** The build fails hard instead of falling back to local compilation

## Impact

- **Affected crates:** Any proc macro that reads files or scripts during expansion:
  - `wayland-client` (wayland-scanner)
  - `bindgen` (with custom header binding files)
  - Custom build-script-driven proc macros
  - Code-generation proc macros that depend on external data
  
- **Build failure:** Entire `cargo build --release` aborts
- **CI/CD Impact:** Builds cannot complete with distributed compilation enabled

## Current Behavior

1. Distributed compilation is attempted
2. Proc macro fails due to missing file
3. Error is reported as a hard compilation failure
4. **No automatic retry with local-only compilation**
5. Build aborts

## Expected Behavior

1. Distributed compilation is attempted
2. Proc macro fails due to missing file
3. **Detect proc macro failure pattern**
4. **Automatically retry with local-only compilation**
5. Log the fallback with `WARN` level for debugging
6. Build succeeds using local cache

## Proposed Solution

### Option A: Detect and Retry (Recommended)

In `src/compiler/compiler.rs`, detect proc macro failures and automatically retry with local compilation:

```rust
/// Detect if a compilation error is due to proc macro failures that can't be distributed
fn is_proc_macro_dist_failure(stderr: &str) -> bool {
    stderr.contains("error: proc macro panicked") ||
    stderr.contains("Failed to open") && stderr.contains("No such file or directory") ||
    stderr.contains("proc macro") && stderr.contains("cannot open")
}

// When distributed compilation fails:
if is_proc_macro_dist_failure(&output.stderr) {
    warn!("[{}]: Retrying with local-only compilation due to proc macro failure", crate_name);
    // Retry with may_dist=false
}
```

### Option B: Mark Crates as Non-Distributable

Add a `[package.metadata.sccache]` config:

```toml
[package.metadata.sccache]
non-distributable-proc-macros = true
```

### Option C: Environment Variable

```bash
export SCCACHE_NONDIST_CRATES="wayland-client,bindgen"
```

## Test Cases

1. **Baseline:** Build grok-build with distributed sccache enabled
   - Expected: Build succeeds by falling back to local for wayland-client
   - Verify: Log shows `WARN` message about fallback

2. **Local-only (control):** Disable distributed compilation
   - Expected: Build succeeds immediately
   - Verify: No fallback messages

3. **Metrics:** Monitor distributed compilation stats
   - Total requests: 640+
   - Distributed: 637 (majority)
   - Retried locally: 1-3 (wayland-client + others)

## Workarounds

Until this is fixed:

```bash
# Disable distributed compilation entirely
export SCCACHE_DIRECT=true  # (already set)
export SCCACHE_ONLY_LOCAL_CACHE=1  # Add this

# Or use local cache only
unset SCCACHE_DIST_CLIENT
```

## Configuration Details

**Current sccache version:** 0.18.0
**Distributed mode:** sccache-dist with 4 worker nodes
  - MSI (192.168.1.2) - scheduler
  - ASUS (192.168.1.5) - worker
  - Lenovo (192.168.1.4) - worker  
  - Gigabyte (192.168.1.6) - worker

**Build stats:**
- 640 total compile requests
- 637 successful distributed compiles (99.5%)
- 1 proc macro failure (wayland-client)
- 2-3 other distribution failures (retriable)

## References

- Related: #1838 "Distributed Rust compile fails when derive macros are used"
- Similar: icecc limitations with build-context-dependent compilation
- Rust proc macro docs: https://doc.rust-lang.org/reference/procedural-macros.html

---

**Submitter:** grok-build CI/CD system
**Date:** 2026-09-30
**Environment:** Linux 6.18, Rust nightly 2026-09-20, sccache 0.18.0
