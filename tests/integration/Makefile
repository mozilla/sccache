.PHONY: help clean $(addprefix test-,$(BACKENDS)) $(addprefix clean-,$(BACKENDS)) test-backends

export UID := $(shell id -u)
export GID := $(shell id -g)

PROJECT_ROOT := $(shell git rev-parse --show-toplevel)
SCCACHE_BIN := $(PROJECT_ROOT)/target/debug/sccache

# Coverage support via WITH_COVERAGE=1
COVERAGE_DIR := $(PROJECT_ROOT)/target/integration-coverage

ifdef WITH_COVERAGE
export WITH_COVERAGE
SCCACHE_BIN := $(PROJECT_ROOT)/target/coverage/debug/sccache
BUILD_TARGET_DIR := --target-dir target/coverage
# Container paths (docker-compose will receive these)
export SCCACHE_PATH := /sccache/target/coverage/debug/sccache
export LLVM_PROFILE_FILE := /coverage/profraw/%p-%m.profraw
else
# Default container path
export SCCACHE_PATH := /sccache/target/debug/sccache
endif

BACKENDS := redis redis-deprecated memcached memcached-deprecated s3 azblob webdav basedirs multilevel
TOOLS := gcc clang cmake autotools coverage zstd

# Map backends to their compose profiles
PROFILES_autotools := autotools
PROFILES_azblob := azblob
PROFILES_basedirs := basedirs redis memcached s3 azblob webdav
PROFILES_clang := clang
PROFILES_cmake := cmake
PROFILES_coverage := coverage
PROFILES_gcc := gcc
PROFILES_memcached := memcached
PROFILES_memcached-deprecated := memcached
PROFILES_multilevel := multilevel redis memcached s3 azblob webdav
PROFILES_redis := redis
PROFILES_redis-deprecated := redis
PROFILES_s3 := s3
PROFILES_webdav := webdav
PROFILES_zstd := zstd

# Map backends to their services
SERVICES_autotools :=
SERVICES_azblob := azurite azurite-setup
SERVICES_basedirs := redis memcached minio minio-setup azurite azurite-setup webdav
SERVICES_clang :=
SERVICES_cmake :=
SERVICES_coverage :=
SERVICES_gcc :=
SERVICES_memcached := memcached
SERVICES_memcached-deprecated := memcached
SERVICES_multilevel := redis memcached minio minio-setup azurite azurite-setup webdav
SERVICES_redis := redis
SERVICES_redis-deprecated := redis
SERVICES_s3 := minio minio-setup
SERVICES_webdav := webdav
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
	@echo "  make test-basedirs           Run basedirs test across all backends"
	@echo "  make test-multilevel         Run multi-level cache test across all backends"
	@echo ""
	@echo "  make test-backends           Run all backend tests"
	@echo "  make clean                   Stop all services and clean up"
	@echo "  make help                    Show this help"
	@echo ""
	@echo "Coverage Collection:"
	@echo "  Run any test with WITH_COVERAGE=1 to collect coverage data"
	@echo "  Example: WITH_COVERAGE=1 make test-redis"
	@echo "  Example: WITH_COVERAGE=1 make test-backends"
	@echo "  make coverage-report         Generate lcov report from collected data"
	@echo "  make coverage-clean          Clean coverage artifacts"

build: $(SCCACHE_BIN) $(PROJECT_ROOT)/target/integration-cargo-cache $(COVERAGE_DIR)/profraw

# Create a persistent cargo cache for integration tests, used to avoid re-downloading dependencies
$(PROJECT_ROOT)/target/integration-cargo-cache:
	@mkdir -p $@

$(COVERAGE_DIR)/profraw:
	@mkdir -p $@

$(SCCACHE_BIN): $(PROJECT_ROOT)/Cargo.toml $(PROJECT_ROOT)/Cargo.lock
ifdef WITH_COVERAGE
	@echo "Building sccache with coverage instrumentation in Docker..."
else
	@echo "Building sccache in Docker..."
endif
	@docker run --rm \
		-v $(PROJECT_ROOT):/sccache \
		-v $(PROJECT_ROOT)/target/integration-cargo-cache:/usr/local/cargo/registry \
		-w /sccache \
		-e OPENSSL_NO_VENDOR=1 \
		$(if $(WITH_COVERAGE),-e RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0 -Coverflow-checks=off" -e CARGO_INCREMENTAL=0 -e "LLVM_PROFILE_FILE=/tmp/build-%p-%m.profraw") \
		rust:latest \
		bash -c "apt-get update -qq && apt-get install -y -qq libssl-dev pkg-config && \
		         cargo build --all-features $(BUILD_TARGET_DIR) && \
		         chown -R $(UID):$(GID) target"
	@echo "Binary built: $(SCCACHE_BIN)"
	@ls -lh $(SCCACHE_BIN)

define profiles
$(foreach profile,$(PROFILES_$(1)),--profile $(profile))
endef

# Pattern rule for cleaning backends
clean-%:
	docker compose $(call profiles,$*) down -v

# Pattern rule for testing backends
test-%: build clean-%
	@echo "Testing $* backend..."
	@docker compose $(call profiles,$*) up --quiet-pull -d $(SERVICES_$*)
	@docker compose $(call profiles,$*) run --quiet-pull --rm test-$*
	@docker compose $(call profiles,$*) down
	@echo "$* test completed"

test-backends: $(addprefix test-,$(BACKENDS))
	@echo "All backend tests completed"

test-tools: $(addprefix test-,$(TOOLS))
	@echo "All backend tests completed"

test: test-backends test-tools
	@echo "All tests completed"

coverage-report:
	@echo "Generating coverage report from integration tests..."
	@if [ ! -d "$(PROJECT_ROOT)/target/integration-coverage/profraw" ]; then \
		echo "Error: No coverage data found."; \
		echo "Run tests with: WITH_COVERAGE=1 make test-<name>"; \
		exit 1; \
	fi
	@if [ -z "$$(find $(PROJECT_ROOT)/target/integration-coverage/profraw -name '*.profraw' 2>/dev/null)" ]; then \
		echo "Error: No .profraw files found in coverage directory."; \
		echo "Run tests with: WITH_COVERAGE=1 make test-<name>"; \
		exit 1; \
	fi
	@echo "Generating coverage report..."
	@docker run --rm \
		-v $(PROJECT_ROOT):/sccache \
		-v $(PROJECT_ROOT)/target/integration-cargo-cache:/usr/local/cargo/registry \
		-v sccache-coverage-tools:/usr/local/cargo/bin \
		-v sccache-rustup:/usr/local/rustup \
		-w /sccache \
		rust:latest \
		bash -c "rustup component add llvm-tools 2>/dev/null || true && \
		         (which grcov >/dev/null 2>&1 || cargo install grcov --locked) && \
		         mkdir -p target/integration-coverage/reports && \
		         grcov target/integration-coverage/profraw \
		           --binary-path target/coverage/debug \
		           --source-dir . \
		           --output-type lcov \
		           --output-path target/integration-coverage/reports/lcov.info \
		           --branch \
		           --ignore-not-existing \
		           --ignore '/*' \
		           --ignore 'build.rs' \
		           --excl-br-line '^\s*((debug_)?assert(_eq|_ne)?!|#\[derive\()' && \
		         chown -R $(UID):$(GID) target/integration-coverage"
	@echo ""
	@echo "Coverage report generated:"
	@echo "  $(PROJECT_ROOT)/target/integration-coverage/reports/lcov.info"
	@echo ""
	@echo "View summary with: lcov --summary target/integration-coverage/reports/lcov.info"

clean:
	@echo "Cleaning coverage artifacts..."
	@rm -rf $(PROJECT_ROOT)/target/integration-coverage
	@echo "Coverage artifacts cleaned"
	@echo "Stopping and removing all test services..."
	@docker compose --profile '*' down -v
	@echo "Cleanup complete"
