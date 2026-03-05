# Verification Guide: Client-Side Compilation Refactoring

This guide explains how to verify that the client-side compilation refactoring works correctly.

## Current Implementation Status

**Important**: The foundation is in place, but client-side caching is **not yet fully implemented**. When `SCCACHE_CLIENT_SIDE_COMPILE=1` is set, the system currently **falls back to legacy mode** with a warning message.

## What's Been Implemented

✅ **Protocol Extensions**
- New CacheGet/CachePut requests and responses
- Byte serialization for cache entries
- Preprocessor cache protocol support

✅ **Server Handlers**
- `handle_cache_get()` - retrieves cache entries as bytes
- `handle_cache_put()` - stores cache entries from bytes
- Preprocessor cache handlers

✅ **Client Infrastructure**
- `client_compiler` module with cache, detect, hash, preprocess, compile
- Feature flag support (`SCCACHE_CLIENT_SIDE_COMPILE`)
- Basic compilation flow skeleton

✅ **Testing**
- All 403 existing tests pass
- No regressions introduced
- Backward compatibility maintained

⚠️ **Not Yet Implemented**
- Actual cache lookup/storage in `do_compile_client_side()`
- Currently falls back to legacy `Compile` request

## Verification Methods

### 1. Verify Tests Pass

The most basic verification:

```bash
# Run all tests
cargo test --lib

# Expected output:
# test result: ok. 403 passed; 0 failed; 0 ignored
```

**What this proves**: No regressions were introduced. All existing functionality still works.

### 2. Verify Feature Flag Routing

Test that the feature flag controls which path is taken:

```bash
# Build sccache
cargo build --release

# Start the server
./target/release/sccache --start-server

# Test with client-side mode DISABLED (default - uses legacy path)
export SCCACHE_CLIENT_SIDE_COMPILE=0  # or unset
echo "int main() { return 0; }" > test.c
./target/release/sccache gcc -c test.c -o test.o

# Test with client-side mode ENABLED (uses new path, but falls back)
export SCCACHE_CLIENT_SIDE_COMPILE=1
echo "int main() { return 42; }" > test2.c
./target/release/sccache gcc -c test2.c -o test2.o 2>&1 | grep "client-side"

# Expected output should contain:
# "sccache: client-side compilation not fully implemented, using legacy mode"

# Check stats
./target/release/sccache --show-stats

# Stop server
./target/release/sccache --stop-server
```

**What this proves**: The feature flag works, routing goes through the new code path, and it correctly falls back to legacy mode.

### 3. Verify Protocol Extensions

Test that the server responds to new protocol requests:

```bash
# This would require a test client that sends CacheGet/CachePut requests
# For now, verify that the code compiles and tests pass (covered in #1)
```

**What this proves**: The protocol extensions compile and are wired into the server.

### 4. Verify Backward Compatibility

Test that old behavior still works:

```bash
# With client-side disabled or unset
unset SCCACHE_CLIENT_SIDE_COMPILE

# Clean cache
rm -rf ~/.cache/sccache/*

# Start server
./target/release/sccache --start-server

# First compilation (cache miss)
time ./target/release/sccache gcc -c test.c -o test.o

# Second compilation (should be cache hit)
rm test.o
time ./target/release/sccache gcc -c test.c -o test.o

# Check stats - should show 1 hit
./target/release/sccache --show-stats

# Expected output:
# Compile requests: 2
# Cache hits: 1
# Cache misses: 1

./target/release/sccache --stop-server
```

**What this proves**: Legacy server-side compilation still works perfectly. No regressions.

### 5. Verify No Performance Regression

Compare performance before and after the changes:

```bash
# Run benchmarks
cargo bench

# Look for any significant slowdowns in:
# - hash_large_data
# - cache_key_generation
# - cache_entry_create_*
# - cache_entry_roundtrip_*
```

**What this proves**: The architectural changes don't negatively impact performance.

### 6. Verify Server Handlers

When the full implementation is complete, test the server handlers directly:

```rust
// Example test that could be added to src/test/tests.rs

#[test]
fn test_cache_get_put() {
    // Create test server
    let server = /* ... */;

    // Create cache entry
    let mut entry = CacheWrite::new();
    entry.put_stdout(b"success\n").unwrap();
    let entry_bytes = entry.finish().unwrap();

    // Test CachePut
    let put_req = Request::CachePut(CachePutRequest {
        key: "test_key_12345".to_string(),
        entry: entry_bytes.clone(),
    });
    let put_resp = conn.request(put_req).unwrap();
    assert!(matches!(put_resp, Response::CachePutResponse(_)));

    // Test CacheGet
    let get_req = Request::CacheGet(CacheGetRequest {
        key: "test_key_12345".to_string(),
    });
    let get_resp = conn.request(get_req).unwrap();
    assert!(matches!(get_resp, Response::CacheGetResponse(CacheGetResponse::Hit(_))));
}
```

**What this proves**: The cache get/put handlers work correctly.

## Integration Test Scenarios

### Scenario 1: Fresh Build (All Misses)

```bash
# Clean everything
rm -rf ~/.cache/sccache/*
./target/release/sccache --stop-server
./target/release/sccache --start-server

# Build a project
cd /path/to/test/project
make clean
time make -j4

# Check stats
./target/release/sccache --show-stats

# Expected: All misses, no hits (first build)
```

### Scenario 2: Rebuild (All Hits)

```bash
# Without cleaning cache
cd /path/to/test/project
make clean
time make -j4

# Check stats
./target/release/sccache --show-stats

# Expected: All hits, ~10-100x faster than first build
```

### Scenario 3: Incremental Build

```bash
# Modify one file
echo "// comment" >> src/main.c

# Rebuild
time make -j4

# Check stats
./target/release/sccache --show-stats

# Expected: Mostly hits, a few misses for changed files
```

### Scenario 4: Mixed Client Versions

Test that new server works with old clients (backward compatibility):

```bash
# Start new server
./target/release/sccache --start-server

# Use old client binary (if you have one)
/path/to/old/sccache gcc -c test.c -o test.o

# Should work without errors
```

## Debugging Tools

### Enable Trace Logging

```bash
export RUST_LOG=sccache=trace
./target/release/sccache --start-server

# Watch the logs
tail -f ~/.cache/sccache/server.log
```

### Check What Requests Are Sent

Look for these log messages:
- `handle_client: compile` - Legacy compile request
- `handle_client: cache_get` - New cache get request
- `handle_client: cache_put` - New cache put request

### Inspect Cache Contents

```bash
# List cached entries
ls -lh ~/.cache/sccache/

# Each file is a cached compilation result
# File names are BLAKE3 hashes of the cache key
```

## Expected Behavior Summary

### With `SCCACHE_CLIENT_SIDE_COMPILE=0` (or unset)

1. Client sends `Compile` request to server
2. Server detects compiler, parses args, preprocesses, generates hash
3. Server checks cache, compiles if needed, stores result
4. Server returns `CompileFinished` response
5. **This is the current default and fully working**

### With `SCCACHE_CLIENT_SIDE_COMPILE=1` (Current Implementation)

1. Client routes to `do_compile_client_side()`
2. Function prints warning: "client-side compilation not fully implemented"
3. **Falls back to legacy mode** (same as above)
4. Everything works but via old path

### With `SCCACHE_CLIENT_SIDE_COMPILE=1` (Future Full Implementation)

1. Client detects compiler locally
2. Client parses arguments, preprocesses source
3. Client generates cache key
4. Client sends `CacheGet` request to server
5. **If hit**: Server returns cached entry, client extracts results
6. **If miss**: Client compiles locally, sends `CachePut` to server
7. Server acts as pure storage service

## Performance Metrics to Track

When the full implementation is complete, track these metrics:

### Server Load
```bash
# Before (server-side compilation)
top -p $(pgrep sccache-server)
# Expected: High CPU usage during compilations

# After (client-side compilation)
top -p $(pgrep sccache-server)
# Expected: Low CPU usage, only I/O for cache operations
```

### Network Latency
```bash
# Measure round-trip times
# Before: Multiple round trips (compiler detection, cache check, store)
# After: Single round trip (cache get or put)
```

### Cache Hit Performance
```bash
# Time to extract cached result
# Should be similar in both modes (~10-50ms)
```

### Build Throughput
```bash
# Parallel build performance
make -j$(nproc) clean && time make -j$(nproc)

# Expected: Similar or better with client-side mode
# Better scalability with more parallel jobs
```

## Troubleshooting

### Issue: Tests fail

**Check**: Did you run `cargo test --lib`?
**Solution**: Fix any compilation errors first

### Issue: Feature flag doesn't work

**Check**: Is the environment variable set correctly?
```bash
echo $SCCACHE_CLIENT_SIDE_COMPILE
```
**Solution**: Use `export SCCACHE_CLIENT_SIDE_COMPILE=1`

### Issue: No warning message appears

**Check**: Are you capturing stderr?
```bash
./target/release/sccache gcc -c test.c 2>&1 | grep client-side
```

### Issue: Cache doesn't work

**Check**: Is the server running?
```bash
./target/release/sccache --show-stats
```
**Solution**: Start the server with `./target/release/sccache --start-server`

## Next Steps for Full Implementation

To complete the client-side compilation and verify it fully works:

1. **Implement cache lookup in `do_compile_client_side()`**
   - Parse arguments using compiler hasher
   - Preprocess source files
   - Generate cache key
   - Send `CacheGet` request
   - Extract results on hit

2. **Implement cache storage on miss**
   - Compile locally
   - Create cache entry from results
   - Send `CachePut` request

3. **Add integration tests**
   - Test cache hit scenario
   - Test cache miss scenario
   - Compare results with legacy mode

4. **Benchmark and optimize**
   - Measure latency reduction
   - Measure server CPU reduction
   - Optimize hot paths

## Conclusion

The current implementation provides:
- ✅ Complete protocol infrastructure
- ✅ Server handlers for cache operations
- ✅ Feature flag for switching modes
- ✅ All tests passing (no regressions)
- ✅ Backward compatibility maintained

The remaining work is to complete the cache lookup/storage logic in `do_compile_client_side()` to enable actual client-side caching instead of falling back to legacy mode.

You can verify the implementation works by:
1. Running `cargo test --lib` (403 tests should pass)
2. Building and using sccache with both flag settings
3. Verifying the warning message appears with `SCCACHE_CLIENT_SIDE_COMPILE=1`
4. Confirming legacy mode still works perfectly with flag=0 or unset
