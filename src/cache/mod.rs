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

use compiler::Compiler;
use sha1;
use std::env;

/// The cache is versioned by the inputs to `hash_key`.
const CACHE_VERSION : &'static [u8] = b"2";

#[allow(dead_code)]
pub fn hash_key(compiler: &Compiler, args: &Vec<String>, preprocessor_output: &[u8]) -> String {
    let mut m = sha1::Sha1::new();
    m.update(compiler.digest.as_bytes());
    //TODO: use basename
    m.update(compiler.executable.as_bytes());
    m.update(CACHE_VERSION);
    let last = args.len() - 1;
    for (i, arg) in args.iter().enumerate() {
        m.update(arg.as_bytes());
        if i < last {
            m.update(&b" "[..]);
        }
    }
    //TODO: should probably propogate these over from the client.
    for var in ["MACOSX_DEPLOYMENT_TARGET", "IPHONEOS_DEPLOYMENT_TARGET"].iter() {
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
}
