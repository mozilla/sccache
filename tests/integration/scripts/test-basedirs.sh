#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"
TEST_FILE="/sccache/tests/test_clang_multicall.c"

echo "=========================================="
echo "Testing: Basedirs with all backends"
echo "=========================================="

# Create two different build directories
mkdir -p /build/dir1/project /build/dir2/project

# Copy test file to both directories
cp "$TEST_FILE" /build/dir1/project/test.cpp
cp "$TEST_FILE" /build/dir2/project/test.cpp

# Function to test a backend
test_backend() {
    local backend_name="$1"
    shift

    echo ""
    echo "=========================================="
    echo "Testing backend: $backend_name"
    echo "=========================================="

    # Stop any running sccache server
    "$SCCACHE" --stop-server 2>/dev/null || true

    # Set backend-specific environment variables (passed as arguments)
    for env_var in "$@"; do
        export "${env_var?}"
    done

    # Configure basedirs
    export SCCACHE_BASEDIRS="/build/dir1:/build/dir2"

    # Start sccache server
    "$SCCACHE" --start-server

    echo "Test 1: Compile from first directory (cache miss)"
    "$SCCACHE" g++ -c /build/dir1/project/test.cpp -o /build/dir1/project/test.o
    test -f /build/dir1/project/test.o || { echo "ERROR: No compiler output found"; exit 1; }

    echo "Checking stats after first build..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    CACHE_LOCATION=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cache_location', ''))" || echo "unknown")
    echo "Backend detected: $CACHE_LOCATION"

    # Verify backend is being used
    if ! echo "$CACHE_LOCATION" | grep -qi "$backend_name"; then
        echo "WARNING: Expected backend '$backend_name' not found in cache_location: $CACHE_LOCATION"
    fi

    echo "Test 2: Compile from second directory with same relative path (cache hit expected)"
    "$SCCACHE" g++ -c /build/dir2/project/test.cpp -o /build/dir2/project/test.o
    test -f /build/dir2/project/test.o || { echo "ERROR: No compiler output found"; exit 1; }

    echo "Verifying cache hits..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

    echo "Cache hits for $backend_name: $CACHE_HITS"

    if [ "$CACHE_HITS" -gt 0 ]; then
        echo "✓ PASS: $backend_name - Basedir test successful"
    else
        echo "✗ FAIL: $backend_name - No cache hits detected with basedirs"
        echo "$STATS_JSON" | python3 -m json.tool
        exit 1
    fi

    # Verify basedirs are shown in stats
    BASEDIRS_IN_STATS=$(echo "$STATS_JSON" | python3 -c "import sys, json; bd = json.load(sys.stdin).get('basedirs', []); print(':'.join(bd) if bd else 'none')")
    echo "Basedirs in stats: $BASEDIRS_IN_STATS"

    if [ "$BASEDIRS_IN_STATS" = "none" ]; then
        echo "WARNING: Basedirs not shown in stats output: $STATS_JSON"
    fi

    # Clean up for next backend test
    rm -f /build/dir1/project/test.o /build/dir2/project/test.o
    "$SCCACHE" --stop-server &>/dev/null || true

    # Unset environment variables
    for env_var in "$@"; do
        VAR_NAME="${env_var%%=*}"
        unset "$VAR_NAME"
    done
    unset SCCACHE_BASEDIRS
}

# Test each backend
test_backend "local disk" "SCCACHE_DIR=/build/sccache"
test_backend "redis" "SCCACHE_REDIS_ENDPOINT=tcp://redis:6379"
test_backend "memcached" "SCCACHE_MEMCACHED_ENDPOINT=tcp://memcached:11211"
test_backend "s3" \
    "SCCACHE_BUCKET=test" \
    "SCCACHE_ENDPOINT=http://minio:9000/" \
    "SCCACHE_REGION=us-east-1" \
    "AWS_ACCESS_KEY_ID=minioadmin" \
    "AWS_SECRET_ACCESS_KEY=minioadmin" \
    "AWS_EC2_METADATA_DISABLED=true"
test_backend "azblob" \
    "SCCACHE_AZURE_BLOB_CONTAINER=test" \
    "SCCACHE_AZURE_CONNECTION_STRING=DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://azurite:10000/devstoreaccount1;"
test_backend "webdav" \
    "SCCACHE_WEBDAV_ENDPOINT=http://webdav:8080" \
    "SCCACHE_WEBDAV_USERNAME=bar" \
    "SCCACHE_WEBDAV_PASSWORD=baz"

echo ""
echo "=========================================="
echo "All basedir tests completed successfully!"
echo "=========================================="
