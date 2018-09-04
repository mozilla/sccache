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

#![recursion_limit = "128"]

#[cfg(feature = "ar")]
extern crate ar;
extern crate atty;
extern crate base64;
extern crate bincode;
extern crate byteorder;
extern crate bytes;
#[cfg(feature = "chrono")]
extern crate chrono;
#[macro_use]
extern crate clap;
#[cfg(feature = "rust-crypto")]
extern crate crypto;
#[cfg(unix)]
extern crate daemonize;
extern crate directories;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate filetime;
#[cfg(feature = "flate2")]
extern crate flate2;
#[macro_use]
extern crate futures;
extern crate futures_cpupool;
#[cfg(feature = "hyper")]
extern crate hyper;
#[cfg(test)]
extern crate itertools;
#[cfg(feature = "jsonwebtoken")]
extern crate jsonwebtoken as jwt;
#[cfg(windows)]
extern crate kernel32;
#[macro_use]
extern crate lazy_static;
extern crate local_encoding;
#[macro_use]
extern crate log;
extern crate libc;
extern crate lru_disk_cache;
#[cfg(feature = "memcached")]
extern crate memcached;
#[cfg(windows)]
extern crate mio_named_pipes;
extern crate num_cpus;
extern crate number_prefix;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate rand;
extern crate ring;
#[cfg(feature = "redis")]
extern crate redis;
extern crate regex;
#[cfg(feature = "reqwest")]
extern crate reqwest;
extern crate retry;
#[cfg(feature = "rouille")]
#[macro_use(router)]
extern crate rouille;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate strip_ansi_escapes;
extern crate tar;
extern crate tempdir;
extern crate tempfile;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_process;
extern crate tokio_proto;
extern crate tokio_serde_bincode;
extern crate tokio_service;
extern crate toml;
#[cfg(any(feature = "gcs", feature = "azure"))]
extern crate url;
extern crate uuid;
extern crate walkdir;
extern crate which;
#[cfg(windows)]
extern crate winapi;
extern crate zip;

// To get macros in scope, this has to be first.
#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
pub mod errors;

#[cfg(feature = "azure")]
mod azure;
mod cache;
mod client;
mod cmdline;
mod commands;
mod compiler;
pub mod config;
pub mod dist;
mod jobserver;
mod mock_command;
mod protocol;
pub mod server;
#[cfg(feature = "simple-s3")]
mod simples3;
mod util;

use std::env;
use std::io::Write;

pub fn main() {
    init_logging();
    // Initialise config
    let _ = config::CONFIG.caches.len();
    std::process::exit(match cmdline::parse() {
        Ok(cmd) => match commands::run_command(cmd) {
            Ok(s) => s,
            Err(e) => {
                let stderr = &mut std::io::stderr();
                writeln!(stderr, "error: {}", e).unwrap();

                for e in e.iter().skip(1) {
                    writeln!(stderr, "caused by: {}", e).unwrap();
                }
                2
            }
        },
        Err(e) => {
            println!("sccache: {}", e);
            cmdline::get_app().print_help().unwrap();
            println!("");
            1
        }
    });
}

fn init_logging() {
    if env::var("RUST_LOG").is_ok() {
        match env_logger::try_init() {
            Ok(_) => (),
            Err(e) => panic!(format!("Failed to initalize logging: {:?}", e)),
        }
    }
}
