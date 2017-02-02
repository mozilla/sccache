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

use app_dirs::{
    AppDataType,
    AppInfo,
    app_dir,
};
use cache::disk::DiskCache;
use cache::s3::S3Cache;
use compiler::Compiler;
use futures::Future;
use futures_cpupool::CpuPool;
use regex::Regex;
use sha1;
use std::env;
use std::fmt;
use std::io::{
    self,
    Error,
    ErrorKind,
    Read,
    Seek,
    Write,
};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_core::reactor::Handle;
use zip::{
    CompressionMethod,
    ZipArchive,
    ZipWriter,
};

//TODO: might need to put this somewhere more central
const APP_INFO: AppInfo = AppInfo {
    name: "sccache",
    author: "Mozilla",
};

const TEN_GIGS: usize = 10 * 1024 * 1024 * 1024;

/// Result of a cache lookup.
pub enum Cache {
    /// Result was found in cache.
    Hit(CacheRead),
    /// Result was not found in cache.
    Miss,
    /// Cache entry should be ignored, force compilation.
    Recache,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Cache::Hit(_) => write!(f, "Cache::Hit(...)"),
            Cache::Miss => write!(f, "Cache::Miss"),
            Cache::Recache => write!(f, "Cache::Recache"),
        }
    }
}

/// Trait objects can't be bounded by more than one non-builtin trait.
pub trait ReadSeek : Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

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

/// A `Future` that may provide a `CacheWriteResult`.
pub type CacheWriteFuture = Box<Future<Item=Duration, Error=String>>;

/// Data to be stored in the compiler cache.
pub struct CacheWrite {
    zip: ZipWriter<io::Cursor<Vec<u8>>>,
}

impl CacheWrite {
    /// Create a new, empty cache entry.
    pub fn new() -> CacheWrite {
        CacheWrite {
            zip: ZipWriter::new(io::Cursor::new(vec!())),
        }
    }

    /// Add an object containing the contents of `from` to this cache entry at `name`.
    pub fn put_object<T: Read>(&mut self, name: &str, from: &mut T) -> io::Result<()> {
        try!(self.zip.start_file(name, CompressionMethod::Deflated).or(Err(Error::new(ErrorKind::Other, "Failed to start cache entry object"))));
        try!(io::copy(from, &mut self.zip));
        Ok(())
    }

    /// Finish writing data to the cache entry writer, and return the data.
    pub fn finish(self) -> io::Result<Vec<u8>> {
        let CacheWrite { mut zip } = self;
        zip.finish()
            .or(Err(Error::new(ErrorKind::Other, "Failed to finish cache entry zip")))
            .map(|cur| cur.into_inner())
    }
}

/// An interface to cache storage.
pub trait Storage {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    fn get(&self, key: &str) -> Box<Future<Item=Cache, Error=io::Error>>;

    /// Get a cache entry for `key` that can be filled with data.
    fn start_put(&self, key: &str) -> io::Result<CacheWrite>;

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    fn finish_put(&self, key: &str, entry: CacheWrite) -> CacheWriteFuture;

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the current storage usage, if applicable.
    fn current_size(&self) -> Option<usize>;

    /// Get the maximum storage size, if applicable.
    fn max_size(&self) -> Option<usize>;
}

fn parse_size(val: &str) -> Option<usize> {
    let re = Regex::new(r"^(\d+)([KMGT])$").unwrap();
    re.captures(val)
        .and_then(|caps| caps.at(1).and_then(|size| usize::from_str(size).ok()).and_then(|size| Some((size, caps.at(2)))))
        .and_then(|(size, suffix)| {
            match suffix {
                Some("K") => Some(1024 * size),
                Some("M") => Some(1024 * 1024 * size),
                Some("G") => Some(1024 * 1024 * 1024 * size),
                Some("T") => Some(1024 * 1024 * 1024 * 1024 * size),
                _ => None,
            }
        })
}

/// Get a suitable `Storage` implementation from the environment.
pub fn storage_from_environment(pool: &CpuPool, handle: &Handle) -> Arc<Storage> {
    if let Ok(bucket) = env::var("SCCACHE_BUCKET") {
        let endpoint = match env::var("SCCACHE_ENDPOINT") {
            Ok(endpoint) => format!("{}/{}", endpoint, bucket),
            _ => match env::var("SCCACHE_REGION") {
                Ok(ref region) if region != "us-east-1" =>
                    format!("{}.s3-{}.amazonaws.com", bucket, region),
                _ => format!("{}.s3.amazonaws.com", bucket),
            },
        };
        debug!("Trying S3Cache({})", endpoint);
        match S3Cache::new(&bucket, &endpoint, handle) {
            Ok(s) => {
                trace!("Using S3Cache");
                return Arc::new(s);
            }
            Err(e) => warn!("Failed to create S3Cache: {:?}", e),
        }
    }
    let d = env::var_os("SCCACHE_DIR")
        .map(|p| PathBuf::from(p))
        .or_else(|| app_dir(AppDataType::UserCache, &APP_INFO, "").ok())
        // Fall back to something, even if it's not very good.
        .unwrap_or(env::temp_dir().join("sccache_cache"));
    trace!("Using DiskCache({:?})", d);
    let cache_size = env::var("SCCACHE_CACHE_SIZE")
        .ok()
        .and_then(|v| parse_size(&v))
        .unwrap_or(TEN_GIGS);
    trace!("DiskCache size: {}", cache_size);
    Arc::new(DiskCache::new(&d, cache_size, pool))
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
    for (i, arg) in args.iter().enumerate() {
        if i != 0 {
            m.update(&b" "[..]);
        }
        m.update(arg.as_bytes());
    }
    //TODO: should propogate these over from the client.
    // https://github.com/glandium/sccache/issues/5
    for var in CACHED_ENV_VARS.iter() {
        if let Ok(val) = env::var(var) {
            m.update(var.as_bytes());
            m.update(&b"="[..]);
            m.update(val.as_bytes());
        }
    }
    m.update(preprocessor_output);
    m.digest().to_string()
}


#[test]
fn test_parse_size() {
    assert_eq!(None, parse_size(""));
    assert_eq!(None, parse_size("100"));
    assert_eq!(Some(2048), parse_size("2K"));
    assert_eq!(Some(10 * 1024 * 1024), parse_size("10M"));
    assert_eq!(Some(TEN_GIGS), parse_size("10G"));
    assert_eq!(Some(1024 * TEN_GIGS), parse_size("10T"));
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
