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
pub const CACHE_VERSION : &'static [u8] = b"2";

/// Environment variables that are factored into the cache key.
pub const CACHED_ENV_VARS : &'static [&'static str] = &[
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
];

/// Compute the hash key of `compiler` compiling `preprocessor_output` with `args`.
#[allow(dead_code)]
pub fn hash_key(compiler: &Compiler, args: &Vec<String>, preprocessor_output: &[u8]) -> String {
    // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
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
