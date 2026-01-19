# sccache Integration Tests

Docker Compose-based integration tests for sccache backends and compilers.

## Prerequisites

- Docker and Docker Compose
- Make (optional, for convenience)

## Quick Start

```bash
cd tests/integration

# Run a specific test
make test-redis

# Run all backend tests
make test-backends

# Run all tools tests
make test-tools

# Clean up
make clean
```

## Binary Management

Tests will automatically use existing `target/debug/sccache` binary if present.
If not found, it will build in Docker automatically.

To pre-build manually:
```bash
cargo build --all-features
```

## Test Pattern

Each backend test follows this pattern:

1. Start required service (redis, memcached, etc.)
2. Run cargo build (cache miss expected)
3. Verify backend is used via JSON stats
4. Run cargo build again (cache hit expected)
5. Verify cache hits > 0 via JSON stats
6. Clean up service state
7. Stop services

### Cleanup
- `make clean` - Stop all services and remove volumes

## Debugging

Run test manually:
```bash
docker compose --profile redis up -d redis
docker compose --profile redis run --rm test-redis
```

Check service logs:
```bash
docker compose logs redis
```

Manual cleanup:
```bash
docker compose --profile cleanup run --rm cleanup-redis
```
