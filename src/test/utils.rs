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

use crate::mock_command::*;
use fs::File;
use fs_err as fs;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};

use std::sync::{Arc, Mutex};
use tempfile::TempDir;

use crate::errors::*;
use crate::jobserver::Client;

/// Return a `Vec` with each listed entry converted to an owned `String`.
macro_rules! stringvec {
    ( $( $x:expr ),* ) => {
        vec!($( $x.to_owned(), )*)
    };
}

/// Return a `Vec` with each listed entry converted to an owned `OsString`.
macro_rules! ovec {
    ( $( $x:expr ),* ) => {
        vec!($( ::std::ffi::OsString::from($x), )*)
    };
}

/// Return a `Vec` with each listed entry converted to an owned `PathBuf`.
macro_rules! pathvec {
    ( $( $x:expr ),* ) => {
        vec!($( ::std::path::PathBuf::from($x), )*)
    };
}

/// Assert that `left != right`.
macro_rules! assert_neq {
    ($left:expr , $right:expr) => {{
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val != *right_val) {
                    panic!(
                        "assertion failed: `(left != right)` \
                         (left: `{:?}`, right: `{:?}`)",
                        left_val, right_val
                    )
                }
            }
        }
    }};
}

/// Assert that `map` contains all of the (`key`, `val`) pairs specified and only those keys.
macro_rules! assert_map_contains {
    ( $map:expr , $( ($key:expr, $val:expr) ),* ) => {
        let mut nelems = 0;
        $(
            nelems += 1;
            match $map.get(&$key) {
                Some(&ref v) =>
                    assert_eq!($val, *v, "{} key `{:?}` doesn't match expected! (expected `{:?}` != actual `{:?}`)", stringify!($map), $key, $val, v),
                None => panic!("{} missing key `{:?}`", stringify!($map), $key),
            }
         )*
        assert_eq!(nelems, $map.len(), "{} contains {} elements, expected {}", stringify!($map), $map.len(), nelems);
    }
}

pub fn new_creator() -> Arc<Mutex<MockCommandCreator>> {
    let client = unsafe { Client::new() };
    Arc::new(Mutex::new(MockCommandCreator::new(&client)))
}

pub fn next_command(creator: &Arc<Mutex<MockCommandCreator>>, child: Result<MockChild>) {
    creator.lock().unwrap().next_command_spawns(child);
}

pub fn next_command_calls<C: Fn(&[OsString]) -> Result<MockChild> + Send + 'static>(
    creator: &Arc<Mutex<MockCommandCreator>>,
    call: C,
) {
    creator.lock().unwrap().next_command_calls(call);
}

#[cfg(not(target_os = "macos"))]
pub fn find_sccache_binary() -> PathBuf {
    // Older versions of cargo put the test binary next to the sccache binary.
    // Newer versions put it in the deps/ subdirectory.
    let exe = env::current_exe().unwrap();
    let this_dir = exe.parent().unwrap();
    let dirs = &[&this_dir, &this_dir.parent().unwrap()];
    dirs.iter()
        .map(|d| d.join("sccache").with_extension(env::consts::EXE_EXTENSION))
        .filter_map(|d| fs::metadata(&d).ok().map(|_| d))
        .next()
        .unwrap_or_else(|| {
            panic!(
            "Error: sccache binary not found, looked in `{:?}`. Do you need to run `cargo build`?",
            dirs
        )
        })
}

pub struct TestFixture {
    /// Temp directory.
    pub tempdir: TempDir,
    /// $PATH
    pub paths: OsString,
    /// Binaries created in $PATH
    pub bins: Vec<PathBuf>,
}

pub const SUBDIRS: &[&str] = &["a", "b", "c"];
pub const BIN_NAME: &str = "bin";

pub fn create_file<F>(dir: &Path, path: &str, fill_contents: F) -> io::Result<PathBuf>
where
    F: FnOnce(File) -> io::Result<()>,
{
    let b = dir.join(path);
    let parent = b.parent().unwrap();
    fs::create_dir_all(parent)?;
    let f = fs::File::create(&b)?;
    fill_contents(f)?;
    b.canonicalize()
}

pub fn touch(dir: &Path, path: &str) -> io::Result<PathBuf> {
    create_file(dir, path, |_f| Ok(()))
}

#[cfg(unix)]
pub fn mk_bin_contents<F: FnOnce(File) -> io::Result<()>>(
    dir: &Path,
    path: &str,
    fill_contents: F,
) -> io::Result<PathBuf> {
    use fs_err::os::unix::fs::OpenOptionsExt;
    let bin = dir.join(path);
    let parent = bin.parent().unwrap();
    fs::create_dir_all(parent)?;
    #[allow(clippy::unnecessary_cast)]
    let f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o666 | (libc::S_IXUSR as u32))
        .open(&bin)?;
    fill_contents(f)?;
    bin.canonicalize()
}

#[cfg(unix)]
pub fn mk_bin(dir: &Path, path: &str) -> io::Result<PathBuf> {
    mk_bin_contents(dir, path, |_f| Ok(()))
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub fn mk_bin_contents<F: FnOnce(File) -> io::Result<()>>(
    dir: &Path,
    path: &str,
    contents: F,
) -> io::Result<PathBuf> {
    create_file(
        dir,
        Path::new(path)
            .with_extension(env::consts::EXE_EXTENSION)
            .to_str()
            .unwrap(),
        contents,
    )
}

#[cfg(not(unix))]
pub fn mk_bin(dir: &Path, path: &str) -> io::Result<PathBuf> {
    touch(
        dir,
        Path::new(path)
            .with_extension(env::consts::EXE_EXTENSION)
            .to_str()
            .unwrap(),
    )
}

impl TestFixture {
    pub fn new() -> TestFixture {
        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test")
            .tempdir()
            .unwrap();
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        let mut paths = vec![];
        let mut bins = vec![];
        for d in SUBDIRS.iter() {
            let p = tempdir.path().join(d);
            builder.create(&p).unwrap();
            bins.push(mk_bin(&p, BIN_NAME).unwrap());
            paths.push(p);
        }
        TestFixture {
            tempdir,
            paths: env::join_paths(paths).unwrap(),
            bins,
        }
    }

    #[allow(dead_code)]
    pub fn touch(&self, path: &str) -> io::Result<PathBuf> {
        touch(self.tempdir.path(), path)
    }

    #[allow(dead_code)]
    pub fn mk_bin(&self, path: &str) -> io::Result<PathBuf> {
        mk_bin(self.tempdir.path(), path)
    }
}

pub fn single_threaded_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .unwrap()
}

/// An add on trait, to allow calling `.wait()` for `futures::Future`
/// as it was possible for `futures` at `0.1`.
///
/// Intended for test only!
pub(crate) trait Waiter<R> {
    fn wait(self) -> R;
}

impl<T, O> Waiter<O> for T
where
    T: Future<Output = O>,
{
    fn wait(self) -> O {
        let rt = single_threaded_runtime();
        rt.block_on(self)
    }
}

#[test]
fn test_map_contains_ok() {
    let mut m = HashMap::new();
    m.insert("a", 1);
    m.insert("b", 2);
    assert_map_contains!(m, ("a", 1), ("b", 2));
}

#[test]
#[should_panic]
fn test_map_contains_extra_key() {
    let mut m = HashMap::new();
    m.insert("a", 1);
    m.insert("b", 2);
    assert_map_contains!(m, ("a", 1));
}

#[test]
#[should_panic]
fn test_map_contains_missing_key() {
    let mut m = HashMap::new();
    m.insert("a", 1);
    assert_map_contains!(m, ("a", 1), ("b", 2));
}

#[test]
#[should_panic]
fn test_map_contains_wrong_value() {
    let mut m = HashMap::new();
    m.insert("a", 1);
    m.insert("b", 3);
    assert_map_contains!(m, ("a", 1), ("b", 2));
}
