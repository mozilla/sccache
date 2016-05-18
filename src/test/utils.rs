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

#[cfg(unix)]
use libc;
use std::env;
use std::fs::{self,File};
use std::io;
use std::path::{Path,PathBuf};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempdir::TempDir;

pub struct TestFixture {
    /// Temp directory.
    pub tempdir: TempDir,
    /// $PATH
    pub paths: String,
    /// Binaries created in $PATH
    pub bins: Vec<PathBuf>,
}

pub const SUBDIRS: &'static [&'static str] = &["a", "b", "c"];
pub const BIN_NAME: &'static str = "bin";

pub fn create_file<F : FnOnce(File) -> io::Result<()>>(dir: &Path, path: &str, fill_contents: F) -> io::Result<PathBuf> {
    let b = dir.join(path);
    let f = try!(fs::File::create(&b));
    try!(fill_contents(f));
    b.canonicalize()
}

pub fn touch(dir: &Path, path: &str) -> io::Result<PathBuf> {
    create_file(dir, path, |_f| Ok(()))
}

#[cfg(unix)]
pub fn mk_bin_contents<F : FnOnce(File) -> io::Result<()>>(dir: &Path, path: &str, fill_contents: F) -> io::Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let bin = dir.join(path);
    let f = try!(fs::OpenOptions::new()
                 .write(true)
                 .create(true)
                 .mode(0o666 | (libc::S_IXUSR as u32))
                 .open(&bin));
    try!(fill_contents(f));
    bin.canonicalize()
}

#[cfg(unix)]
pub fn mk_bin(dir: &Path, path: &str) -> io::Result<PathBuf> {
    mk_bin_contents(dir, path, |_f| Ok(()))
}

#[cfg(not(unix))]
pub fn mk_bin_contents<F : FnOnce(File) -> io::Result<()>>(dir: &Path, path: &str, contents: F) -> io::Result<PathBuf> {
    create_file(dir, path, contents)
}

#[cfg(not(unix))]
pub fn mk_bin(dir: &Path, path: &str) -> io::Result<PathBuf> {
    touch(dir, path)
}

impl TestFixture {
    pub fn new() -> TestFixture {
        let tempdir = TempDir::new("sccache_find_in_path").unwrap();
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        let mut paths = vec!();
        let mut bins = vec!();
        for d in SUBDIRS.iter() {
            let p = tempdir.path().join(d);
            builder.create(&p).unwrap();
            bins.push(mk_bin(&p, &BIN_NAME).unwrap());
            paths.push(p);
        }
        TestFixture {
            tempdir: tempdir,
            paths: env::join_paths(paths).unwrap().to_str().unwrap().to_owned(),
            bins: bins,
        }
    }

    #[allow(dead_code)]
    pub fn touch(&self, path: &str) -> io::Result<PathBuf> {
        touch(self.tempdir.path(), &path)
    }

    pub fn mk_bin(&self, path: &str) -> io::Result<PathBuf> {
        mk_bin(self.tempdir.path(), &path)
    }
}
