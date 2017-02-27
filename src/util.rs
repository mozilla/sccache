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
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;

use errors::*;

/// Calculate the SHA-1 digest of the contents of `path`, running
/// the actual hash computation on a background thread in `pool`.
pub fn sha1_digest<T>(path: T, pool: &CpuPool) -> SFuture<String>
    where T: Into<PathBuf>
{
    let path = path.into();
    Box::new(pool.spawn_fn(move || -> Result<_> {
        let f = File::open(&path)?;
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
