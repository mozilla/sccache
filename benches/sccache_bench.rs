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
use sccache::util::{Digest, TimeMacroFinder};
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

/// Benchmark incremental digest updates (simulating hash_key with many args)
#[divan::bench]
fn digest_incremental_updates(bencher: Bencher) {
    let chunks: Vec<Vec<u8>> = (0..100)
        .map(|i| format!("-I/path/to/include/dir{}", i).into_bytes())
        .collect();

    bencher.bench(|| {
        let mut digest = Digest::new();
        for chunk in &chunks {
            digest.update(black_box(chunk));
        }
        black_box(digest.finish())
    });
}

/// Benchmark digest with delimiter (used for structured hashing)
#[divan::bench]
fn digest_with_delimiters(bencher: Bencher) {
    let section_data = b"section_content_data_here_with_more_content";
    let delimiter_names: Vec<&[u8]> = vec![
        b"compiler",
        b"language",
        b"args",
        b"env",
        b"output",
        b"extra1",
        b"extra2",
        b"extra3",
        b"extra4",
        b"extra5",
    ];

    bencher.bench(|| {
        let mut digest = Digest::new();
        for name in &delimiter_names {
            digest.delimiter(name);
            digest.update(black_box(section_data));
        }
        black_box(digest.finish())
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
        entry.put_object("output.o", &mut cursor, Some(0o644)).unwrap();
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
        entry.put_object("output.o", &mut cursor, Some(0o644)).unwrap();
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
        entry.put_object("output.o", &mut cursor, Some(0o644)).unwrap();
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
        entry.put_object("output.o", &mut cursor, Some(0o644)).unwrap();
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
            entry.put_object(&format!("output{}.o", i), &mut cursor, Some(0o644)).unwrap();
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
            entry.put_object(&format!("output{}.o", i), &mut cursor, Some(0o644)).unwrap();
            entry.put_stdout(b"success\n").unwrap();
            entries_data.push(entry.finish().unwrap());
        }

        // Cache hit: read all entries back
        for (i, bytes) in entries_data.into_iter().enumerate() {
            let cursor = Cursor::new(bytes);
            let mut reader = CacheRead::from(cursor).unwrap();
            let mut output = Vec::new();
            reader.get_object(&format!("output{}.o", i), &mut output).unwrap();
            black_box(output);
        }
    });
}

fn main() {
    divan::main();
}
