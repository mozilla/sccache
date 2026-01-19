.PHONY: help clean $(addprefix test-,$(BACKENDS)) $(addprefix clean-,$(BACKENDS)) test-backends

export UID := $(shell id -u)
export GID := $(shell id -g)

PROJECT_ROOT := $(shell git rev-parse --show-toplevel)
SCCACHE_BIN := $(PROJECT_ROOT)/target/debug/sccache

BACKENDS := redis redis-deprecated memcached memcached-deprecated s3 azblob webdav
TOOLS := gcc clang cmake autotools coverage zstd

# Map backends to their compose profiles
PROFILE_redis := redis
PROFILE_redis-deprecated := redis
PROFILE_memcached := memcached
PROFILE_memcached-deprecated := memcached
PROFILE_s3 := s3
PROFILE_azblob := azblob
PROFILE_webdav := webdav
PROFILE_gcc := gcc
PROFILE_clang := clang
PROFILE_cmake := cmake
PROFILE_autotools := autotools
PROFILE_coverage := coverage
PROFILE_zstd := zstd

# Map backends to their services
SERVICES_redis := redis
SERVICES_redis-deprecated := redis
SERVICES_memcached := memcached
SERVICES_memcached-deprecated := memcached
SERVICES_s3 := minio minio-setup
SERVICES_azblob := azurite azurite-setup
SERVICES_webdav := webdav
SERVICES_gcc :=
SERVICES_clang :=
SERVICES_cmake :=
SERVICES_autotools :=
SERVICES_coverage :=
SERVICES_zstd :=

help:
	@echo "sccache Integration Tests"
	@echo ""
	@echo "Available targets:"
	@echo "  make build                   Build sccache binary"
	@echo ""
	@echo "Backend Storage Tests:"
	@echo "  make test-redis              Run Redis (new endpoint) test"
	@echo "  make test-redis-deprecated   Run Redis (deprecated) test"
	@echo "  make test-memcached          Run Memcached (new endpoint) test"
	@echo "  make test-memcached-deprecated Run Memcached (deprecated) test"
	@echo "  make test-s3                 Run S3/MinIO test"
	@echo "  make test-azblob             Run Azure Blob Storage test"
	@echo "  make test-webdav             Run WebDAV test"
	@echo ""
	@echo "Compiler Integration Tests:"
	@echo "  make test-gcc                Run GCC compiler test"
	@echo "  make test-clang              Run Clang compiler test"
	@echo ""
	@echo "Build System Tests:"
	@echo "  make test-cmake              Run CMake integration test"
	@echo "  make test-autotools          Run Autotools integration test"
	@echo ""
	@echo "Advanced Tests:"
	@echo "  make test-coverage           Run Rust coverage instrumentation test"
	@echo "  make test-zstd               Run ZSTD compression levels test"
	@echo ""
	@echo "  make test-backends           Run all backend tests"
	@echo "  make clean                   Stop all services and clean up"
	@echo "  make help                    Show this help"

build: $(SCCACHE_BIN) $(PROJECT_ROOT)/target/integration-cargo-cache

# Create a persistent cargo cache for integration tests, used to avoid re-downloading dependencies
$(PROJECT_ROOT)/target/integration-cargo-cache:
	@mkdir -p $@

$(SCCACHE_BIN): $(PROJECT_ROOT)/Cargo.toml $(PROJECT_ROOT)/Cargo.lock
	@echo "Building sccache in Docker..."
	@docker run --rm \
		-v $(PROJECT_ROOT):/workspace \
		-v integration-cargo-cache:/usr/local/cargo/registry \
		-w /workspace \
		-e OPENSSL_NO_VENDOR=1 \
		rust:latest \
		bash -c "apt-get update -qq && apt-get install -y -qq libssl-dev pkg-config && \
		         cargo build --all-features && \
		         chown -R $$(id -u):$$(id -g) target"
	@echo "Binary built: $(SCCACHE_BIN)"
	@ls -lh $(SCCACHE_BIN)

# Pattern rule for cleaning backends
clean-%:
	@docker compose --profile $(PROFILE_$*) down -v

# Pattern rule for testing backends
test-%: build clean-%
	@echo "Testing $* backend..."
	@docker compose --profile $(PROFILE_$*) up --quiet-pull -d $(SERVICES_$*)
	@docker compose --profile $(PROFILE_$*) run --quiet-pull --rm test-$*
	@docker compose --profile $(PROFILE_$*) down
	@echo "$* test completed"

test-backends: $(addprefix test-,$(BACKENDS))
	@echo "All backend tests completed"

test-tools: $(addprefix test-,$(TOOLS))
	@echo "All backend tests completed"

test: test-backends test-tools
	@echo "All tests completed"

clean:
	@docker compose --profile '*' down -v
	@echo "Cleanup complete"
