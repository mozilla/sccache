// Copyright 2016 Mozilla Foundation
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

use cache::disk::DiskCache;
use compiler::Compiler;
use sha1;
use std::env;
use std::io::{
    self,
    Error,
    ErrorKind,
    Read,
    Seek,
    Write,
};
use std::path::PathBuf;
use zip::{
    CompressionMethod,
    ZipArchive,
    ZipWriter,
};

/// Result of a cache lookup.
#[derive(Debug, PartialEq)]
pub enum Cache {
    /// Error fetching from cache.
    Error,
    /// Result was found in cache.
    Hit,
    /// Result was not found in cache.
    Miss,
}

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek : Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

/// Data stored in the compiler cache.
pub struct CacheRead {
    zip: ZipArchive<Box<ReadSeek>>,
}

impl CacheRead {
    /// Create a cache entry from `reader`.
    pub fn from<R: ReadSeek + 'static>(reader: R) -> io::Result<CacheRead> {
        let z = try!(ZipArchive::new(Box::new(reader) as Box<ReadSeek>).or(Err(Error::new(ErrorKind::Other, "Failed to parse cache entry"))));
        Ok(CacheRead {
            zip: z,
        })
    }

    /// Get an object from this cache entry at `name` and write it to `to`.
    pub fn get_object<T: Write>(&mut self, name: &str, to: &mut T) -> io::Result<()> {
        let mut file = try!(self.zip.by_name(name).or(Err(Error::new(ErrorKind::Other, "Failed to read object from cache entry"))));
        try!(io::copy(&mut file, to));
        Ok(())
    }
}

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait WriteSeek : Write + Seek {}

impl<T: Write + Seek> WriteSeek for T {}

/// Data to be stored in the compiler cache.
pub struct CacheWrite {
    zip: ZipWriter<Box<WriteSeek>>,
}

impl CacheWrite {
    /// Create a new, empty cache entry that writes to `writer`.
    pub fn new<W: WriteSeek + 'static>(writer: W) -> CacheWrite {
        CacheWrite {
            zip: ZipWriter::new(Box::new(writer) as Box<WriteSeek>),
        }
    }

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    pub fn put_object<T: Read>(&mut self, name: &str, from: &mut T) -> io::Result<()> {
        try!(self.zip.start_file(name, CompressionMethod::Deflated).or(Err(Error::new(ErrorKind::Other, "Failed to start cache entry object"))));
        try!(io::copy(from, &mut self.zip));
        Ok(())
    }
}

/// An interface to cache storage.
pub trait Storage : Send + Sync {
    /// Get a cache entry by `key`.
    fn get(&self, key: &str) -> Option<CacheRead>;

    /// Get a cache entry for `key` that can be filled with data.
    fn start_put(&self, key: &str) -> io::Result<CacheWrite>;
    /// Put `entry` in the cache under `key`.
    fn finish_put(&self, key: &str, entry: CacheWrite) -> io::Result<()>;
}

/// Get a suitable `Storage` implementation from the environment.
pub fn storage_from_environment() -> Box<Storage + Send> {
    let d = env::var_os(&"SCCACHE_DIR")
        .and_then(|p| Some(PathBuf::from(p)))
        //TODO: better default storage location.
        .unwrap_or(env::temp_dir().join("sccache_cache"));
    Box::new(DiskCache::new(&d))
}

/// The cache is versioned by the inputs to `hash_key`.
pub const CACHE_VERSION : &'static [u8] = b"2";

/// Environment variables that are factored into the cache key.
pub const CACHED_ENV_VARS : &'static [&'static str] = &[
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
];

/// Compute the hash key of `compiler` compiling `preprocessor_output` with `args`.
#[allow(dead_code)]
pub fn hash_key(compiler: &Compiler, args: &[String], preprocessor_output: &[u8]) -> String {
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
    let mut m = sha1::Sha1::new();
    m.update(compiler.digest.as_bytes());
    //TODO: drop the compiler filename from the hash
    m.update(compiler.executable.as_bytes());
    m.update(CACHE_VERSION);
    let last = args.len() - 1;
    for (i, arg) in args.iter().enumerate() {
        m.update(arg.as_bytes());
        if i < last {
            m.update(&b" "[..]);
        }
    }
    //TODO: should propogate these over from the client.
    // https://github.com/glandium/sccache/issues/5
    for var in CACHED_ENV_VARS.iter() {
        match env::var(var) {
            Ok(val) => {
                m.update(var.as_bytes());
                m.update(&b"="[..]);
                m.update(val.as_bytes());
            }
            Err(_) => {}
        }
    }
    m.update(preprocessor_output);
    m.hexdigest()
}

#[cfg(test)]
mod test {
    use super::*;
    use compiler::{Compiler,CompilerKind};
    use std::env;
    use std::io::Write;
    use test::utils::*;

    #[test]
    fn test_hash_key_executable_path_differs() {
        let f = TestFixture::new();
        // Try to avoid testing exact hashes.
        let c1 = Compiler::new(f.bins[0].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        let c2 = Compiler::new(f.bins[1].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        let args = stringvec!["a", "b", "c"];
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key(&c1, &args, &PREPROCESSED),
                    hash_key(&c2, &args, &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_executable_contents_differs() {
        let f = TestFixture::new();
        // Try to avoid testing exact hashes.
        let c1 = Compiler::new(f.bins[0].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        // Overwrite the contents of the binary.
        mk_bin_contents(f.tempdir.path(), "a/bin", |mut f| f.write_all(b"hello")).unwrap();
        let c2 = Compiler::new(f.bins[0].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        let args = stringvec!["a", "b", "c"];
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key(&c1, &args, &PREPROCESSED),
                    hash_key(&c2, &args, &PREPROCESSED));
    }

    #[test]
    fn test_hash_key_args_differs() {
        let f = TestFixture::new();
        let c = Compiler::new(f.bins[0].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        const PREPROCESSED : &'static [u8] = b"hello world";
        assert_neq!(hash_key(&c, &stringvec!["a", "b", "c"], &PREPROCESSED),
                    hash_key(&c, &stringvec!["x", "y", "z"], &PREPROCESSED));

        assert_neq!(hash_key(&c, &stringvec!["a", "b", "c"], &PREPROCESSED),
                    hash_key(&c, &stringvec!["a", "b"], &PREPROCESSED));

        assert_neq!(hash_key(&c, &stringvec!["a", "b", "c"], &PREPROCESSED),
                    hash_key(&c, &stringvec!["a"], &PREPROCESSED));

    }

    #[test]
    fn test_hash_key_preprocessed_content_differs() {
        let f = TestFixture::new();
        let c = Compiler::new(f.bins[0].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        let args = stringvec!["a", "b", "c"];
        assert_neq!(hash_key(&c, &args, &b"hello world"[..]),
                    hash_key(&c, &args, &b"goodbye"[..]));
    }

    #[test]
    fn test_hash_key_env_var_differs() {
        let f = TestFixture::new();
        let c = Compiler::new(f.bins[0].to_str().unwrap(), CompilerKind::Gcc).unwrap();
        let args = stringvec!["a", "b", "c"];
        const PREPROCESSED : &'static [u8] = b"hello world";
        for var in CACHED_ENV_VARS.iter() {
            let old = env::var_os(var);
            env::remove_var(var);
            let h1 = hash_key(&c, &args, &PREPROCESSED);
            env::set_var(var, "something");
            let h2 = hash_key(&c, &args, &PREPROCESSED);
            env::set_var(var, "something else");
            let h3 = hash_key(&c, &args, &PREPROCESSED);
            match old {
                Some(val) => env::set_var(var, val),
                None => env::remove_var(var),
            }
            assert_neq!(h1, h2);
            assert_neq!(h2, h3);
        }
    }
}
