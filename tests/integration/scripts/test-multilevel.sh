#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
export SCCACHE_ERROR_LOG=/build/sccache-error.log

echo "========================================================================"
echo "Testing: Multi-Level Cache with all backends (disk + remote)"
echo "========================================================================"

# Function to show error log on failure
show_error_log() {
    echo ""
    echo "=== Server Error Log (last 300 lines) ==="
    tail -300 "$SCCACHE_ERROR_LOG" 2>/dev/null || echo "No error log file found"
}

# Helper function to get Rust cache misses with error handling
# If Rust key doesn't exist, returns 0 (means no misses occurred yet in this session)
get_rust_misses() {
    local stats_json="$1"
    echo "$stats_json" | python3 -c "
import sys, json
try:
    stats = json.load(sys.stdin).get('stats', {})
    misses = stats.get('cache_misses', {}).get('counts', {}).get('Rust', 0)
    print(misses)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Function to test a multi-level backend configuration
test_multilevel_backend() {
    local backend_name="$1"
    local level_name="$backend_name"
    if [ "$backend_name" = "azblob" ]; then
        # The config value is azure, but opendal uses 'azblob' as the backend name
        level_name="azure"
    fi
    shift

    echo ""
    echo "=========================================="
    echo "Testing multi-level: disk + $backend_name"
    echo "=========================================="

    # Stop any running sccache server
    "$SCCACHE" --stop-server &>/dev/null || true
    sleep 1

    # Set backend-specific environment variables (passed as arguments)
    for env_var in "$@"; do
        export "${env_var?}"
    done

    # Configure multi-level cache: disk first (L1), then remote (L2)
    export SCCACHE_MULTILEVEL_CHAIN="disk,$level_name"
    export SCCACHE_DIR="/build/sccache-disk"

    # Clean disk cache
    rm -rf /build/sccache-disk
    mkdir -p /build/sccache-disk

    # Copy test crate
    rm -rf /build/test-crate
    cp -r /sccache/tests/test-crate /build/
    cd /build/test-crate

    # Start sccache server with logging
    rm -f "$SCCACHE_ERROR_LOG"
    SCCACHE_LOG=trace \
      "$SCCACHE" --start-server &>/dev/null

    echo "Build 1: Initial cache miss (populating both levels)"
    TEST_ENV_VAR="test_value_$(date +%s)" && export TEST_ENV_VAR
    cargo clean
    cargo build

    echo "Checking stats after first build..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    CACHE_LOCATION=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cache_location', ''))" || echo "unknown")
    echo "Cache location: $CACHE_LOCATION"

    # Verify multi-level is detected
    if ! echo "$CACHE_LOCATION" | grep -qi "Multi-level"; then
        echo "FAIL: Multi-level cache not detected in cache_location"
        echo "$STATS_JSON" | python3 -m json.tool
        exit 1
    fi
    echo "Multi-level cache detected"

    # Verify both disk and remote backend are in the configuration
    if ! echo "$CACHE_LOCATION" | grep -qi "disk"; then
        echo "FAIL: Disk not found in multi-level configuration"
        echo "$STATS_JSON" | python3 -m json.tool
        exit 1
    fi
    echo "Disk level detected"

    if ! echo "$CACHE_LOCATION" | grep -qi "$backend_name"; then
        echo "FAIL: $backend_name not found in multi-level configuration"
        echo "$STATS_JSON" | python3 -m json.tool
        exit 1
    fi
    echo "$backend_name level detected"

    FIRST_MISSES=$(get_rust_misses "$STATS_JSON") || {
        echo "FAIL: Could not get initial cache miss count"
        echo "$STATS_JSON" | python3 -m json.tool
        exit 1
    }
    echo "Cache misses after first build: $FIRST_MISSES"

    echo ""
    echo "Build 2: Cache hit expected (from disk L1)"
    cargo clean
    cargo build

    echo "Verifying cache behavior..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    SECOND_MISSES=$(get_rust_misses "$STATS_JSON") || {
        echo "FAIL: Could not get second build cache miss count"
        echo "$STATS_JSON" | python3 -m json.tool
        show_error_log
        exit 1
    }

    echo "Cache misses after second build: $SECOND_MISSES (first build: $FIRST_MISSES)"

    if [ "$SECOND_MISSES" -gt "$FIRST_MISSES" ]; then
        echo "FAIL: Cache misses increased from $FIRST_MISSES to $SECOND_MISSES for $backend_name"
        echo "$STATS_JSON" | python3 -m json.tool
        show_error_log
        exit 1
    fi
    echo "Cache working: misses stayed at $SECOND_MISSES"

    echo ""
    echo "Test 3: Backfill test - clear L1 (disk), verify L2 (remote) still has data"
    "$SCCACHE" --stop-server &>/dev/null || true
    rm -rf /build/sccache-disk
    mkdir -p /build/sccache-disk
    SCCACHE_LOG=trace \
      "$SCCACHE" --start-server &>/dev/null
    sleep 1

    echo "Build 3: Should hit L2 ($backend_name) and backfill to L1 (disk)"
    cargo clean
    cargo build

    echo "Verifying backfill behavior..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    THIRD_MISSES=$(get_rust_misses "$STATS_JSON") || {
        echo "FAIL: Could not get third build cache miss count"
        echo "$STATS_JSON" | python3 -m json.tool
        show_error_log
        exit 1
    }

    echo "Cache misses after L0 clear: $THIRD_MISSES (should be 0 - stats reset after server restart)"

    if [ "$THIRD_MISSES" -gt 0 ]; then
        echo "FAIL: Cache misses = $THIRD_MISSES (expected 0) - L1 ($backend_name) didn't serve data"
        echo "$STATS_JSON" | python3 -m json.tool
        show_error_log
        exit 1
    fi
    echo "PASS: Backfill working - L1 served data and backfilled to L0"

    echo ""
    echo "Build 4: Verify backfill completed - should hit L1 (disk) now"
    cargo clean
    cargo build

    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    FINAL_MISSES=$(get_rust_misses "$STATS_JSON") || {
        echo "FAIL: Could not get final cache miss count"
        echo "$STATS_JSON" | python3 -m json.tool
        show_error_log
        exit 1
    }

    echo "Cache misses after backfill: $FINAL_MISSES (should be 0)"

    if [ "$FINAL_MISSES" -gt 0 ]; then
        echo "FAIL: Cache misses = $FINAL_MISSES (expected 0) - backfilled L0 not working"
        echo "$STATS_JSON" | python3 -m json.tool
        show_error_log
        exit 1
    fi

    echo "PASS: Multi-level cache with $backend_name working correctly"
    echo "  - L1 (disk) and L2 ($backend_name) both operational"
    echo "  - Backfill from L2 to L1 working"
    echo "  - All builds after first used cache (no additional misses)"

    # Clean up for next backend test
    "$SCCACHE" --stop-server &>/dev/null || true
    rm -rf /build/test-crate /build/sccache-disk

    # Unset environment variables
    for env_var in "$@"; do
        VAR_NAME="${env_var%%=*}"
        unset "$VAR_NAME"
    done
    unset SCCACHE_MULTILEVEL_CHAIN
    unset SCCACHE_DIR
}

# Test each remote backend with disk as L1
test_multilevel_backend "redis" "SCCACHE_REDIS_ENDPOINT=tcp://redis:6379"

test_multilevel_backend "memcached" "SCCACHE_MEMCACHED_ENDPOINT=tcp://memcached:11211"

test_multilevel_backend "s3" \
    "SCCACHE_BUCKET=test" \
    "SCCACHE_ENDPOINT=http://minio:9000/" \
    "SCCACHE_REGION=us-east-1" \
    "AWS_ACCESS_KEY_ID=minioadmin" \
    "AWS_SECRET_ACCESS_KEY=minioadmin" \
    "AWS_EC2_METADATA_DISABLED=true"

test_multilevel_backend "azblob" \
    "SCCACHE_AZURE_BLOB_CONTAINER=test" \
    "SCCACHE_AZURE_CONNECTION_STRING=DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://azurite:10000/devstoreaccount1;"

test_multilevel_backend "webdav" \
    "SCCACHE_WEBDAV_ENDPOINT=http://webdav:8080" \
    "SCCACHE_WEBDAV_USERNAME=bar" \
    "SCCACHE_WEBDAV_PASSWORD=baz"

echo ""
echo "=========================================================================="
echo "All multi-level cache tests completed successfully!"
echo "=========================================================================="
