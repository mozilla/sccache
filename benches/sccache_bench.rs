// Copyright 2025 Mozilla
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Benchmarks for sccache's performance-critical operations.
//!
//! These benchmarks focus on the key operations that affect cache performance:
//! - Hash computation (BLAKE3) for cache keys
//! - Time macro detection for preprocessor cache mode
//! - LRU cache operations

use divan::{Bencher, black_box};
use sccache::cache::{CacheRead, CacheWrite};
use sccache::lru_disk_cache::LruCache;
use sccache::util::{Digest, TimeMacroFinder, normalize_win_path, strip_basedirs};
use std::io::Cursor;

// =============================================================================
// Helper Functions
// =============================================================================

/// Generate test data of specified size
fn generate_test_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let pattern = b"int main() { return 0; }\n";
    while data.len() < size {
        let remaining = size - data.len();
        let to_copy = remaining.min(pattern.len());
        data.extend_from_slice(&pattern[..to_copy]);
    }
    data
}

/// Generate preprocessor output with C code patterns
fn generate_preprocessor_output(num_lines: usize) -> Vec<u8> {
    let mut data = Vec::new();
    let code_lines = [
        "#include <stdio.h>\n",
        "int variable_name_123 = 42;\n",
        "void function_call(int x, int y) {\n",
        "    return x + y;\n",
        "}\n",
        "// This is a comment line\n",
        "#define MACRO_NAME value\n",
        "struct MyStruct { int field; };\n",
        "extern \"C\" void c_function();\n",
        "template<typename T> class Container {};\n",
    ];

    for i in 0..num_lines {
        let line = code_lines[i % code_lines.len()];
        data.extend_from_slice(line.as_bytes());
    }
    data
}

/// Generate data with time macros embedded
fn generate_data_with_time_macros(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let pattern = b"const char* build_time = __TIME__;\nconst char* build_date = __DATE__;\n";

    while data.len() < size {
        let remaining = size - data.len();
        let to_copy = remaining.min(pattern.len());
        data.extend_from_slice(&pattern[..to_copy]);
    }
    data
}

// =============================================================================
// Hash Computation Benchmarks
// =============================================================================

/// Benchmark hashing large data (typical preprocessor output ~4MB)
#[divan::bench]
fn hash_large_data(bencher: Bencher) {
    let data = generate_test_data(4 * 1024 * 1024); // 4MB

    bencher.bench(|| {
        let cursor = Cursor::new(black_box(&data));
        black_box(Digest::reader_sync(cursor).unwrap())
    });
}

// =============================================================================
// Time Macro Finder Benchmarks
// =============================================================================

/// Benchmark time macro detection on data without macros (~1MB)
#[divan::bench]
fn time_macro_finder_no_macros(bencher: Bencher) {
    let data = generate_test_data(1024 * 1024); // 1MB

    bencher.bench(|| {
        let cursor = Cursor::new(black_box(&data));
        black_box(Digest::reader_sync_time_macros(cursor).unwrap())
    });
}

/// Benchmark time macro detection on data with __TIME__ and __DATE__
#[divan::bench]
fn time_macro_finder_with_macros(bencher: Bencher) {
    let data = generate_data_with_time_macros(1024 * 1024); // 1MB

    bencher.bench(|| {
        let cursor = Cursor::new(black_box(&data));
        black_box(Digest::reader_sync_time_macros(cursor).unwrap())
    });
}

/// Benchmark TimeMacroFinder with chunked input (simulates real file reading)
#[divan::bench]
fn time_macro_finder_chunked(bencher: Bencher) {
    let chunk_size = 128 * 1024;
    let total_size = chunk_size * 8; // 1MB total
    let data = generate_test_data(total_size);

    bencher.bench(|| {
        let mut finder = TimeMacroFinder::new();
        for chunk in data.chunks(chunk_size) {
            finder.find_time_macros(black_box(chunk));
        }
        black_box(finder.found_time_macros())
    });
}

// =============================================================================
// LRU Cache Benchmarks
// =============================================================================

/// Benchmark LRU cache insertions
#[divan::bench]
fn lru_cache_insert(bencher: Bencher) {
    let num_entries = 5000;

    bencher
        .with_inputs(|| {
            let cache: LruCache<String, u64> = LruCache::new(num_entries as u64 * 2);
            let keys: Vec<String> = (0..num_entries).map(|i| format!("key_{:08x}", i)).collect();
            (cache, keys)
        })
        .bench_values(|(mut cache, keys)| {
            for (i, key) in keys.into_iter().enumerate() {
                cache.insert(key, i as u64);
            }
            black_box(cache)
        });
}

/// Benchmark LRU cache lookups (cache hits)
#[divan::bench]
fn lru_cache_get_hit(bencher: Bencher) {
    let num_entries = 5000;
    let keys: Vec<String> = (0..num_entries).map(|i| format!("key_{:08x}", i)).collect();

    bencher
        .with_inputs(|| {
            let mut cache: LruCache<String, u64> = LruCache::new(num_entries as u64 * 2);
            for (i, key) in keys.iter().enumerate() {
                cache.insert(key.clone(), i as u64);
            }
            cache
        })
        .bench_values(|mut cache| {
            for key in &keys {
                black_box(cache.get(key));
            }
            black_box(cache)
        });
}

/// Benchmark LRU cache eviction under pressure
#[divan::bench]
fn lru_cache_eviction(bencher: Bencher) {
    let cache_size = 2000;

    bencher
        .with_inputs(|| {
            let cache: LruCache<String, u64> = LruCache::new(cache_size as u64);
            // Generate more keys than cache can hold
            let keys: Vec<String> = (0..cache_size * 3)
                .map(|i| format!("key_{:08x}", i))
                .collect();
            (cache, keys)
        })
        .bench_values(|(mut cache, keys)| {
            for (i, key) in keys.into_iter().enumerate() {
                cache.insert(key, i as u64);
            }
            black_box(cache)
        });
}

/// Benchmark LRU cache mixed workload (insert, get, remove)
#[divan::bench]
fn lru_cache_mixed_workload(bencher: Bencher) {
    let num_ops = 3000;

    bencher
        .with_inputs(|| {
            let cache: LruCache<String, u64> = LruCache::new(num_ops as u64);
            let keys: Vec<String> = (0..num_ops).map(|i| format!("key_{:08x}", i)).collect();
            (cache, keys)
        })
        .bench_values(|(mut cache, keys)| {
            // Insert half
            for (i, key) in keys.iter().take(num_ops / 2).enumerate() {
                cache.insert(key.clone(), i as u64);
            }
            // Get some
            for key in keys.iter().take(num_ops / 4) {
                black_box(cache.get(key));
            }
            // Remove some
            for key in keys.iter().take(num_ops / 8) {
                cache.remove(key);
            }
            // Insert more
            for (i, key) in keys.iter().skip(num_ops / 2).enumerate() {
                cache.insert(key.clone(), i as u64);
            }
            black_box(cache)
        });
}

// =============================================================================
// Cache Key Generation Benchmark
// =============================================================================

/// Simulate the hash_key function behavior
fn simulate_hash_key(
    compiler_digest: &str,
    language: &str,
    arguments: &[&str],
    extra_hashes: &[&str],
    env_vars: &[(&str, &str)],
    preprocessor_output: &[u8],
    plusplus: bool,
) -> String {
    let mut m = Digest::new();
    m.update(compiler_digest.as_bytes());
    m.update(&[plusplus as u8]);
    m.update(b"1"); // CACHE_VERSION simulation
    m.update(language.as_bytes());

    for arg in arguments {
        m.update(arg.as_bytes());
    }

    for hash in extra_hashes {
        m.update(hash.as_bytes());
    }

    for (var, val) in env_vars {
        m.update(var.as_bytes());
        m.update(b"=");
        m.update(val.as_bytes());
    }

    m.update(preprocessor_output);
    m.finish()
}

/// Benchmark cache key generation with typical C++ compilation
#[divan::bench]
fn cache_key_generation(bencher: Bencher) {
    let compiler_digest = "abc123def456789012345678901234567890123456789012345678901234";
    let language = "c++";
    let arguments = vec![
        "-O2",
        "-Wall",
        "-Wextra",
        "-I/usr/include",
        "-I/usr/local/include",
        "-I/usr/include/c++/11",
        "-DNDEBUG",
        "-std=c++17",
        "-fPIC",
        "-march=native",
        "-mtune=native",
        "-fno-exceptions",
        "-fno-rtti",
    ];
    let extra_hashes = vec!["pch_hash_abc123", "module_hash_def456"];
    let env_vars = vec![
        ("LANG", "en_US.UTF-8"),
        ("LC_ALL", "C"),
        ("CPLUS_INCLUDE_PATH", "/opt/custom/include"),
    ];
    let preprocessor_output = generate_preprocessor_output(2000); // ~100KB

    bencher.bench(|| {
        black_box(simulate_hash_key(
            compiler_digest,
            language,
            &arguments,
            &extra_hashes,
            &env_vars,
            &preprocessor_output,
            true,
        ))
    });
}

// =============================================================================
// Cache Artifact Serialization Benchmarks
// =============================================================================

/// Generate realistic object file data
fn generate_object_file(size: usize) -> Vec<u8> {
    // Simulate binary object file with varied byte patterns
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        data.push(((i * 7) % 256) as u8);
    }
    data
}

/// Benchmark creating a cache entry with typical compilation artifacts
#[divan::bench]
fn cache_entry_create_small(bencher: Bencher) {
    let obj_data = generate_object_file(50 * 1024); // 50KB object file
    let stdout_data = b"compilation successful\n";
    let stderr_data = b"";

    bencher.bench(|| {
        let mut entry = CacheWrite::new();
        let mut cursor = Cursor::new(black_box(&obj_data));
        entry
            .put_object("output.o", &mut cursor, Some(0o644))
            .unwrap();
        entry.put_stdout(black_box(stdout_data)).unwrap();
        entry.put_stderr(black_box(stderr_data)).unwrap();
        black_box(entry)
    });
}

/// Benchmark creating a cache entry with larger artifacts
#[divan::bench]
fn cache_entry_create_large(bencher: Bencher) {
    let obj_data = generate_object_file(2 * 1024 * 1024); // 2MB object file
    let stdout_data = b"compilation successful\n";
    let stderr_data = b"warning: unused variable\n";

    bencher.bench(|| {
        let mut entry = CacheWrite::new();
        let mut cursor = Cursor::new(black_box(&obj_data));
        entry
            .put_object("output.o", &mut cursor, Some(0o644))
            .unwrap();
        entry.put_stdout(black_box(stdout_data)).unwrap();
        entry.put_stderr(black_box(stderr_data)).unwrap();
        black_box(entry)
    });
}

/// Benchmark cache entry round-trip (write → finish → read)
#[divan::bench]
fn cache_entry_roundtrip_small(bencher: Bencher) {
    let obj_data = generate_object_file(100 * 1024); // 100KB

    bencher.bench(|| {
        // Create and finish entry
        let mut entry = CacheWrite::new();
        let mut cursor = Cursor::new(black_box(&obj_data));
        entry
            .put_object("output.o", &mut cursor, Some(0o644))
            .unwrap();
        entry.put_stdout(b"success\n").unwrap();
        let bytes = entry.finish().unwrap();

        // Read it back
        let cursor = Cursor::new(bytes);
        let mut reader = CacheRead::from(cursor).unwrap();
        let mut output = Vec::new();
        reader.get_object("output.o", &mut output).unwrap();
        let stdout = reader.get_stdout();
        black_box((output, stdout))
    });
}

/// Benchmark cache entry round-trip with larger data
#[divan::bench]
fn cache_entry_roundtrip_large(bencher: Bencher) {
    let obj_data = generate_object_file(1024 * 1024); // 1MB

    bencher.bench(|| {
        // Create and finish entry
        let mut entry = CacheWrite::new();
        let mut cursor = Cursor::new(black_box(&obj_data));
        entry
            .put_object("output.o", &mut cursor, Some(0o644))
            .unwrap();
        entry.put_stdout(b"compilation successful\n").unwrap();
        entry.put_stderr(b"warning: something\n").unwrap();
        let bytes = entry.finish().unwrap();

        // Read it back
        let cursor = Cursor::new(bytes);
        let mut reader = CacheRead::from(cursor).unwrap();
        let mut output = Vec::new();
        reader.get_object("output.o", &mut output).unwrap();
        let stdout = reader.get_stdout();
        let stderr = reader.get_stderr();
        black_box((output, stdout, stderr))
    });
}

/// Benchmark creating multiple cache entries (simulates multi-file compilation)
#[divan::bench]
fn cache_entry_batch_create(bencher: Bencher) {
    // Simulate compiling 50 small files
    let num_files = 50;
    let obj_data = generate_object_file(30 * 1024); // 30KB each

    bencher.bench(|| {
        for i in 0..num_files {
            let mut entry = CacheWrite::new();
            let mut cursor = Cursor::new(black_box(&obj_data));
            entry
                .put_object(&format!("output{}.o", i), &mut cursor, Some(0o644))
                .unwrap();
            entry.put_stdout(b"success\n").unwrap();
            let _bytes = entry.finish().unwrap();
            black_box(_bytes);
        }
    });
}

/// Benchmark full round-trip for multiple cache entries
#[divan::bench]
fn cache_entry_batch_roundtrip(bencher: Bencher) {
    // Simulate cache miss then cache hit for 20 files
    let num_files = 20;
    let obj_data = generate_object_file(50 * 1024); // 50KB each

    bencher.bench(|| {
        let mut entries_data: Vec<Vec<u8>> = Vec::new();

        // Cache miss: create all entries
        for i in 0..num_files {
            let mut entry = CacheWrite::new();
            let mut cursor = Cursor::new(black_box(&obj_data));
            entry
                .put_object(&format!("output{}.o", i), &mut cursor, Some(0o644))
                .unwrap();
            entry.put_stdout(b"success\n").unwrap();
            entries_data.push(entry.finish().unwrap());
        }

        // Cache hit: read all entries back
        for (i, bytes) in entries_data.into_iter().enumerate() {
            let cursor = Cursor::new(bytes);
            let mut reader = CacheRead::from(cursor).unwrap();
            let mut output = Vec::new();
            reader
                .get_object(&format!("output{}.o", i), &mut output)
                .unwrap();
            black_box(output);
        }
    });
}

// =============================================================================
// Hash Computation Scenarios Benchmarks
// =============================================================================

/// Benchmark hashing typical header file content
#[divan::bench]
fn hash_header_file(bencher: Bencher) {
    // Simulate a typical header file (~50KB)
    let header_content = generate_preprocessor_output(1000); // ~50KB

    bencher.bench(|| {
        let cursor = Cursor::new(black_box(&header_content));
        black_box(Digest::reader_sync(cursor).unwrap())
    });
}

/// Benchmark hashing multiple input files (parallel compilation simulation)
#[divan::bench]
fn hash_multiple_files(bencher: Bencher) {
    // Simulate hashing 10 different source files
    let files: Vec<Vec<u8>> = (0..10)
        .map(|i| {
            let mut data = generate_preprocessor_output(200); // ~10KB each
            data.extend_from_slice(format!("// File {}\n", i).as_bytes());
            data
        })
        .collect();

    bencher.bench(|| {
        for file_data in &files {
            let cursor = Cursor::new(black_box(file_data));
            black_box(Digest::reader_sync(cursor).unwrap());
        }
    });
}

// =============================================================================
// Build Workflow Simulation Benchmarks
// =============================================================================

/// Benchmark initial build (all cache misses)
#[divan::bench]
fn build_workflow_initial(bencher: Bencher) {
    // Simulate initial build of 30 files
    let num_files = 30;
    let obj_data = generate_object_file(40 * 1024); // 40KB each

    bencher.bench(|| {
        for i in 0..num_files {
            // Hash compiler + flags + source
            let mut digest = Digest::new();
            digest.update(b"gcc-11.2.0");
            digest.update(b"-O2");
            digest.update(format!("source_{}.c", i).as_bytes());
            let _key = digest.finish();

            // Create cache entry
            let mut entry = CacheWrite::new();
            let mut cursor = Cursor::new(black_box(&obj_data));
            entry
                .put_object(&format!("output{}.o", i), &mut cursor, Some(0o644))
                .unwrap();
            entry.put_stdout(b"success\n").unwrap();
            let _bytes = entry.finish().unwrap();
            black_box(_bytes);
        }
    });
}

/// Benchmark full rebuild (all cache hits)
#[divan::bench]
fn build_workflow_rebuild(bencher: Bencher) {
    // Simulate rebuild where all files are cached
    let num_files = 30;
    let obj_data = generate_object_file(40 * 1024);

    // Pre-create cache entries
    let cache_entries: Vec<Vec<u8>> = (0..num_files)
        .map(|i| {
            let mut entry = CacheWrite::new();
            let mut cursor = Cursor::new(&obj_data);
            entry
                .put_object(&format!("output{}.o", i), &mut cursor, Some(0o644))
                .unwrap();
            entry.put_stdout(b"success\n").unwrap();
            entry.finish().unwrap()
        })
        .collect();

    bencher.bench(|| {
        for (i, cached_bytes) in cache_entries.iter().enumerate() {
            // Hash compiler + flags + source (same as before)
            let mut digest = Digest::new();
            digest.update(b"gcc-11.2.0");
            digest.update(b"-O2");
            digest.update(format!("source_{}.c", i).as_bytes());
            let _key = digest.finish();

            // Retrieve from cache
            let cursor = Cursor::new(cached_bytes.clone());
            let mut reader = CacheRead::from(cursor).unwrap();
            let mut output = Vec::new();
            reader
                .get_object(&format!("output{}.o", i), &mut output)
                .unwrap();
            black_box(output);
        }
    });
}

/// Benchmark incremental build (90% hits, 10% misses)
#[divan::bench]
fn build_workflow_incremental(bencher: Bencher) {
    let num_files = 30;
    let changed_files = 3; // 10% of files changed
    let obj_data = generate_object_file(40 * 1024);

    // Pre-create cache entries for unchanged files
    let cache_entries: Vec<Vec<u8>> = (0..num_files)
        .map(|i| {
            let mut entry = CacheWrite::new();
            let mut cursor = Cursor::new(&obj_data);
            entry
                .put_object(&format!("output{}.o", i), &mut cursor, Some(0o644))
                .unwrap();
            entry.put_stdout(b"success\n").unwrap();
            entry.finish().unwrap()
        })
        .collect();

    bencher.bench(|| {
        for (i, cache_entry) in cache_entries.iter().enumerate() {
            // Hash compiler + flags + source
            let mut digest = Digest::new();
            digest.update(b"gcc-11.2.0");
            digest.update(b"-O2");
            digest.update(format!("source_{}.c", i).as_bytes());
            let _key = digest.finish();

            if i < changed_files {
                // Cache miss: recompile
                let mut entry = CacheWrite::new();
                let mut cursor = Cursor::new(black_box(&obj_data));
                entry
                    .put_object(&format!("output{}.o", i), &mut cursor, Some(0o644))
                    .unwrap();
                entry.put_stdout(b"success\n").unwrap();
                let _bytes = entry.finish().unwrap();
                black_box(_bytes);
            } else {
                // Cache hit: retrieve
                let cursor = Cursor::new(cache_entry.clone());
                let mut reader = CacheRead::from(cursor).unwrap();
                let mut output = Vec::new();
                reader
                    .get_object(&format!("output{}.o", i), &mut output)
                    .unwrap();
                black_box(output);
            }
        }
    });
}

// =============================================================================
// Compression Characteristics Benchmarks
// =============================================================================

/// Generate highly compressible data (simulates debug builds with padding)
fn generate_compressible_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let pattern = b"\x00\x00\x00\x00\x90\x90\x90\x90"; // Common in binaries
    while data.len() < size {
        data.extend_from_slice(pattern);
    }
    data.truncate(size);
    data
}

/// Generate incompressible data (simulates optimized builds)
fn generate_incompressible_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        // Use a more varied pattern that compresses poorly
        data.push(((i * 31 + i / 7) % 256) as u8);
    }
    data
}

/// Benchmark cache entry with highly compressible data
#[divan::bench]
fn compression_high_compressibility(bencher: Bencher) {
    let obj_data = generate_compressible_data(500 * 1024); // 500KB

    bencher.bench(|| {
        let mut entry = CacheWrite::new();
        let mut cursor = Cursor::new(black_box(&obj_data));
        entry
            .put_object("output.o", &mut cursor, Some(0o644))
            .unwrap();
        entry.put_stdout(b"success\n").unwrap();
        black_box(entry.finish().unwrap())
    });
}

/// Benchmark cache entry with incompressible data
#[divan::bench]
fn compression_low_compressibility(bencher: Bencher) {
    let obj_data = generate_incompressible_data(500 * 1024); // 500KB

    bencher.bench(|| {
        let mut entry = CacheWrite::new();
        let mut cursor = Cursor::new(black_box(&obj_data));
        entry
            .put_object("output.o", &mut cursor, Some(0o644))
            .unwrap();
        entry.put_stdout(b"success\n").unwrap();
        black_box(entry.finish().unwrap())
    });
}

/// Benchmark decompression of highly compressed data
#[divan::bench]
fn decompression_high_ratio(bencher: Bencher) {
    let obj_data = generate_compressible_data(500 * 1024);

    // Pre-create compressed entry
    let mut entry = CacheWrite::new();
    let mut cursor = Cursor::new(&obj_data);
    entry
        .put_object("output.o", &mut cursor, Some(0o644))
        .unwrap();
    let compressed = entry.finish().unwrap();

    bencher.bench(|| {
        let cursor = Cursor::new(black_box(compressed.clone()));
        let mut reader = CacheRead::from(cursor).unwrap();
        let mut output = Vec::new();
        reader.get_object("output.o", &mut output).unwrap();
        black_box(output)
    });
}

/// Benchmark decompression of low-ratio compressed data
#[divan::bench]
fn decompression_low_ratio(bencher: Bencher) {
    let obj_data = generate_incompressible_data(500 * 1024);

    // Pre-create compressed entry
    let mut entry = CacheWrite::new();
    let mut cursor = Cursor::new(&obj_data);
    entry
        .put_object("output.o", &mut cursor, Some(0o644))
        .unwrap();
    let compressed = entry.finish().unwrap();

    bencher.bench(|| {
        let cursor = Cursor::new(black_box(compressed.clone()));
        let mut reader = CacheRead::from(cursor).unwrap();
        let mut output = Vec::new();
        reader.get_object("output.o", &mut output).unwrap();
        black_box(output)
    });
}

// =============================================================================
// Realistic LRU Cache Access Pattern Benchmarks
// =============================================================================

/// Benchmark LRU cache with hot/cold access pattern (80/20 rule)
#[divan::bench]
fn lru_hotcold_access_pattern(bencher: Bencher) {
    let total_keys = 1000;
    let hot_keys = 200; // 20% of keys get 80% of accesses

    bencher
        .with_inputs(|| {
            let mut cache: LruCache<String, u64> = LruCache::new((total_keys * 2) as u64);
            // Populate cache
            for i in 0..total_keys {
                cache.insert(format!("key_{:08x}", i), i as u64);
            }
            let keys: Vec<String> = (0..total_keys).map(|i| format!("key_{:08x}", i)).collect();
            (cache, keys)
        })
        .bench_values(|(mut cache, keys)| {
            // Access pattern: 80% accesses to 20% of keys
            for i in 0..400 {
                let key_idx = if i % 5 < 4 {
                    // 80% of the time, access hot keys
                    i % hot_keys
                } else {
                    // 20% of the time, access cold keys
                    hot_keys + (i % (total_keys - hot_keys))
                };
                black_box(cache.get(&keys[key_idx]));
            }
            black_box(cache)
        });
}

/// Benchmark LRU cache with sequential scan pattern
#[divan::bench]
fn lru_sequential_scan_pattern(bencher: Bencher) {
    let num_keys = 1500;

    bencher
        .with_inputs(|| {
            let mut cache: LruCache<String, u64> = LruCache::new((num_keys * 2) as u64);
            for i in 0..num_keys {
                cache.insert(format!("key_{:08x}", i), i as u64);
            }
            let keys: Vec<String> = (0..num_keys).map(|i| format!("key_{:08x}", i)).collect();
            (cache, keys)
        })
        .bench_values(|(mut cache, keys)| {
            // Sequential access pattern (like iterating through all compilation units)
            for key in &keys {
                black_box(cache.get(key));
            }
            black_box(cache)
        });
}

/// Benchmark LRU cache under pressure with realistic eviction
#[divan::bench]
fn lru_realistic_eviction_pressure(bencher: Bencher) {
    let cache_capacity = 500;
    let num_operations = 700; // More than capacity

    bencher
        .with_inputs(|| {
            let cache: LruCache<String, Vec<u8>> = LruCache::new(cache_capacity as u64);
            // Simulate realistic cache entry sizes (10KB each)
            let entry_data = vec![0u8; 10 * 1024];
            (cache, entry_data)
        })
        .bench_values(|(mut cache, entry_data)| {
            // Insert more than capacity, causing evictions
            for i in 0..num_operations {
                cache.insert(format!("key_{:08x}", i), entry_data.clone());
            }
            black_box(cache)
        });
}

// =============================================================================
// Path Normalization Benchmarks
// =============================================================================

/// Generate a realistic Windows path for benchmarking
fn generate_win_path(depth: usize) -> Vec<u8> {
    let mut path = b"C:\\Users\\Developer\\Projects\\".to_vec();
    for i in 0..depth {
        path.extend_from_slice(format!("SubDir{}\\", i).as_bytes());
    }
    path.extend_from_slice(b"source_file.cpp");
    path
}

/// Generate preprocessor output with embedded paths
fn generate_preprocessor_output_with_paths(num_includes: usize, basedir: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    for i in 0..num_includes {
        data.extend_from_slice(b"# 1 \"");
        data.extend_from_slice(basedir);
        data.extend_from_slice(format!("src/module{}/file{}.c\"\n", i % 10, i).as_bytes());
        data.extend_from_slice(b"int function_");
        data.extend_from_slice(format!("{}", i).as_bytes());
        data.extend_from_slice(b"() { return 0; }\n");
    }
    data
}

/// Benchmark normalize_win_path with typical path
#[divan::bench]
fn normalize_win_path_typical(bencher: Bencher) {
    let path = generate_win_path(5);

    bencher.bench(|| black_box(normalize_win_path(black_box(&path))));
}

/// Benchmark normalize_win_path with UTF-8 characters
#[divan::bench]
fn normalize_win_path_utf8(bencher: Bencher) {
    let path = "C:\\Users\\Müller\\Projekte\\Überarbeitung\\Größe\\Datei.cpp".as_bytes();

    bencher.bench(|| black_box(normalize_win_path(black_box(path))));
}

/// Benchmark strip_basedirs with typical preprocessor output
#[divan::bench]
fn strip_basedirs_typical(bencher: Bencher) {
    let basedir = b"/home/user/project/".to_vec();
    let output = generate_preprocessor_output_with_paths(500, &basedir);

    bencher.bench(|| {
        black_box(strip_basedirs(
            black_box(&output),
            black_box(&[basedir.clone()]),
        ))
    });
}

/// Benchmark strip_basedirs with multiple basedirs
#[divan::bench]
fn strip_basedirs_multiple(bencher: Bencher) {
    let basedirs = vec![
        b"/home/user/project/".to_vec(),
        b"/usr/include/".to_vec(),
        b"/opt/toolchain/include/".to_vec(),
    ];
    let mut output = Vec::new();
    for i in 0..500 {
        let basedir = &basedirs[i % basedirs.len()];
        output.extend_from_slice(b"# 1 \"");
        output.extend_from_slice(basedir);
        output.extend_from_slice(format!("file{}.h\"\n", i).as_bytes());
    }

    bencher.bench(|| black_box(strip_basedirs(black_box(&output), black_box(&basedirs))));
}

fn main() {
    divan::main();
}
