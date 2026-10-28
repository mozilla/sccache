// Copyright 2026 Mozilla
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

//! Benchmarks for the preprocessor cache, which direct mode consults on every
//! C/C++ cache hit.
//!
//! They are kept out of `sccache_bench.rs` so that adding them does not change
//! the code layout, and with it the simulated results, of the benchmarks there.

use divan::{Bencher, black_box};
use sccache::PreprocessorCacheEntry;
use sccache::config::PreprocessorCacheModeConfig;
use sccache::util::Digest;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Number of headers in the preprocessor cache entry, about what a C++ file
/// including a few standard headers pulls in.
const INCLUDES: usize = 300;

/// About 4KB of header-like content, different for each `index`.
fn header_contents(index: usize) -> Vec<u8> {
    let lines = [
        "#define MACRO_NAME value\n",
        "struct MyStruct { int field; };\n",
        "template<typename T> class Container {};\n",
        "extern \"C\" void c_function(int x, int y);\n",
        "// This is a comment line\n",
    ];
    let mut contents: Vec<u8> = (0..150)
        .flat_map(|i| lines[i % lines.len()].bytes())
        .collect();
    contents.extend_from_slice(format!("// header {index}\n").as_bytes());
    contents
}

/// A preprocessor cache entry whose result lists `INCLUDES` headers, written
/// in a temporary directory that has to be kept alive while the entry is used.
fn preprocessor_cache_entry() -> (tempfile::TempDir, PreprocessorCacheEntry) {
    let dir = tempfile::tempdir().unwrap();
    let headers = dir.path().join("include/c++/14/bits");
    std::fs::create_dir_all(&headers).unwrap();
    let includes: Vec<(String, PathBuf)> = (0..INCLUDES)
        .map(|i| {
            let path = headers.join(format!("stl_header_{i}.h"));
            let contents = header_contents(i);
            std::fs::write(&path, &contents).unwrap();
            (Digest::reader_sync(contents.as_slice()).unwrap(), path)
        })
        .collect();
    // Real headers are rarely written right before a build, and sccache may
    // not trust the timestamps of files changed in the last couple of
    // seconds, so let the ones just written settle like real ones.
    std::thread::sleep(Duration::from_millis(2500));
    let mut entry = PreprocessorCacheEntry::new();
    entry.add_result(SystemTime::UNIX_EPOCH, "result", includes);
    (dir, entry)
}

/// Benchmark a direct-mode lookup: checking that none of the headers a
/// cached compilation included has changed, which happens on every
/// direct-mode cache hit.
#[divan::bench]
fn preprocessor_cache_lookup(bencher: Bencher) {
    let (_dir, mut entry) = preprocessor_cache_entry();
    let config = PreprocessorCacheModeConfig::activated();
    // Measure the steady state of rebuilds: the headers were already looked
    // at by an earlier build. CodSpeed may run the benchmark only once, which
    // would otherwise measure a first lookup instead.
    let mut updated = false;
    assert!(entry.lookup_result_digest(config, &mut updated).is_some());

    bencher.bench_local(|| {
        let mut updated = false;
        let digest = entry.lookup_result_digest(config, &mut updated);
        assert!(digest.is_some());
        black_box(digest)
    });
}

/// Benchmark reading a preprocessor cache entry back from its stored form,
/// which happens on every direct-mode lookup.
#[divan::bench]
fn preprocessor_cache_entry_decode(bencher: Bencher) {
    let (_dir, entry) = preprocessor_cache_entry();
    let mut buf = Vec::new();
    entry.serialize_to(&mut buf).unwrap();

    bencher.bench(|| black_box(PreprocessorCacheEntry::read(black_box(&buf)).unwrap()));
}

fn main() {
    divan::main();
}
