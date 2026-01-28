#!/bin/bash
set -euo pipefail

SCCACHE="${SCCACHE_PATH:-/sccache/target/debug/sccache}"

echo "==================================================================="
echo "Testing: Basedirs with all backends, autotools + headers + __FILE__"
echo "==================================================================="

autotools() (
    cd "$1"
    autoreconf -i >/dev/null 2>&1 || true
    automake --add-missing >/dev/null 2>&1 || true
    ./configure CXX="$SCCACHE g++" >/dev/null 2>&1
    make >/dev/null 2>&1
)

# Function to test a backend
test_backend() {
    local backend_name="$1"
    shift
    cp -r /sccache/tests/integration/basedirs-autotools /build/dir1
    cp -r /sccache/tests/integration/basedirs-autotools /build/dir2

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

    # Configure basedirs - should strip /build/dir1 and /build/dir2 prefixes
    export SCCACHE_BASEDIRS="/build/dir1:/build/dir2"

    # Start sccache server
    "$SCCACHE" --start-server

    echo "Test 1: Compile from first directory (cache miss)"
    autotools /build/dir1

    echo "Checking stats after first build..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    CACHE_LOCATION=$(echo "$STATS_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cache_location', ''))" || echo "unknown")
    echo "Backend detected: $CACHE_LOCATION"

    # Verify backend is being used
    if ! echo "$CACHE_LOCATION" | grep -qi "$backend_name"; then
        echo "WARNING: Expected backend '$backend_name' not found in cache_location: $CACHE_LOCATION"
    fi

    FIRST_MISSES=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_misses', {}).get('counts', {}).get('C/C++', 0))")
    echo "Cache misses after first build: $FIRST_MISSES"

    echo ""
    echo "Test 2: Compile from second directory with same relative path (cache hit expected)"
    autotools /build/dir2

    echo "Verifying cache hits..."
    STATS_JSON=$("$SCCACHE" --show-stats --stats-format=json)
    CACHE_HITS=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_hits', {}).get('counts', {}).get('C/C++', 0))")

    echo "Cache hits for $backend_name: $CACHE_HITS"

    SECOND_MISSES=$(echo "$STATS_JSON" | python3 -c "import sys, json; stats = json.load(sys.stdin).get('stats', {}); print(stats.get('cache_misses', {}).get('counts', {}).get('C/C++', 0))")

    if [ "$FIRST_MISSES" == "$SECOND_MISSES" ]; then
        echo "✓ PASS: $backend_name - Basedir test successful"
    else
        echo "✗ FAIL: $backend_name - Basedir test failed, cache misses did not remain the same: $FIRST_MISSES != $SECOND_MISSES"
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
    rm -rf /build/dir1 /build/dir2
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
