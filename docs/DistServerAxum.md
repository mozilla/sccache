# dist-server-axum: Modern Async Implementation

## Overview

`dist-server-axum` is a modern, fully asynchronous implementation of sccache's distributed compilation server using the axum 0.7 framework. It replaces the legacy rouille-based synchronous HTTP implementation while maintaining 100% protocol compatibility.

## Building

### Build with axum implementation

```bash
cargo build --release --features dist-server-axum --bin sccache-dist-axum
```

### Build with legacy rouille implementation

```bash
cargo build --release --features dist-server --bin sccache-dist
```

## Usage

The axum implementation is used exactly the same way as the legacy version:

### Starting the Scheduler

```bash
./target/release/sccache-dist-axum scheduler --config scheduler.conf
```

### Starting the Server

```bash
./target/release/sccache-dist-axum server --config server.conf
```

Configuration files are identical to the legacy implementation - no changes needed.

## Compatibility Testing

### Running Built-in Tests

Test protocol serialization compatibility:

```bash
cargo test --lib --features dist-server-axum,dist-client protocol_tests
```

Test JWT token compatibility:

```bash
cargo test --lib --features dist-server-axum,dist-client,jwt jwt_tests
```

Run all http_axum tests:

```bash
cargo test --lib --features dist-server-axum,dist-client,jwt http_axum
```

## Architecture

### Endpoints

**Scheduler (HTTP on configurable port):**
- `POST /api/v1/scheduler/alloc_job` - Allocate compilation job
- `GET /api/v1/scheduler/server_certificate/:id` - Get server certificate
- `POST /api/v1/scheduler/heartbeat_server` - Server heartbeat
- `POST /api/v1/scheduler/job_state/:job_id` - Update job state
- `GET /api/v1/scheduler/status` - Query scheduler status

**Server (HTTPS with self-signed cert):**
- `POST /api/v1/distserver/assign_job/:job_id` - Assign job to server
- `POST /api/v1/distserver/submit_toolchain/:job_id` - Upload toolchain (streaming)
- `POST /api/v1/distserver/run_job/:job_id` - Execute compilation (special format)

## Platform Support

- ✅ **Linux x86_64**: Full support
- ✅ **FreeBSD**: Full support
- ⚠️ **macOS**: Library only (binaries require Linux-specific dependencies)
- ❌ **Windows**: Not supported (same as legacy)

## Troubleshooting

### Build fails with "cannot find axum"

**Solution:** Ensure you're using the correct feature flag:
```bash
cargo build --features dist-server-axum
```

### Test failures with "protocol incompatible"

**Solution:** Run protocol tests to identify the issue:
```bash
cargo test --lib --features dist-server-axum,dist-client protocol_tests -- --nocapture
```

## Performance

The axum implementation offers several performance improvements:

- **Higher concurrency**: Async I/O prevents thread blocking
- **Lower memory usage**: Coroutines are lighter than threads
- **Better resource utilization**: Tokio runtime auto-schedules work

Actual performance gains will vary based on workload and hardware.

## Configuration

Configuration files remain unchanged. See [DistributedQuickstart.md](DistributedQuickstart.md) for configuration details.

## Security

The axum implementation maintains the same security model:

- **JWT tokens**: HS256 symmetric signing (exp validation disabled for compatibility)
- **Certificate pinning**: Self-signed certificates distributed via scheduler
- **IP verification**: Server requests verified against declared IP
