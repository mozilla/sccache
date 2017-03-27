// Copyright 2017 Mozilla Foundation
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

use futures_cpupool::CpuPool;
use sha1;
use std::ffi::OsStr;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Duration;

use errors::*;

/// Calculate the SHA-1 digest of the contents of `path`, running
/// the actual hash computation on a background thread in `pool`.
pub fn sha1_digest<T>(path: T, pool: &CpuPool) -> SFuture<String>
    where T: Into<PathBuf>
{
    let path = path.into();
    Box::new(pool.spawn_fn(move || -> Result<_> {
        let f = File::open(&path).chain_err(|| "Failed to open file for hashing")?;
        let mut m = sha1::Sha1::new();
        let mut reader = BufReader::new(f);
        loop {
            let mut buffer = [0; 1024];
            let count = reader.read(&mut buffer[..])?;
            if count == 0 {
                break;
            }
            m.update(&buffer[..count]);
        }
        Ok(m.digest().to_string())
    }))
}

/// Format `duration` as seconds with a fractional component.
pub fn fmt_duration_as_secs(duration: &Duration) -> String
{
    format!("{}.{:03}s", duration.as_secs(), duration.subsec_nanos() / 1000_000)
}


#[cfg(unix)]
pub fn os_str_bytes(s: &OsStr) -> &[u8]
{
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes()
}

#[cfg(windows)]
pub fn os_str_bytes(s: &OsStr) -> &[u8]
{
    use std::mem;
    unsafe { mem::transmute(s) }
}

#[test]
fn test_os_str_bytes() {
    // Just very basic sanity checks in case anyone changes the underlying
    // representation of OsStr on Windows.
    assert_eq!(os_str_bytes(OsStr::new("hello")), b"hello");
    assert_eq!(os_str_bytes(OsStr::new("你好")), "你好".as_bytes());
}
