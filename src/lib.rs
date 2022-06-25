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

#![deny(rust_2018_idioms)]
#![allow(clippy::type_complexity, clippy::new_without_default)]
#![recursion_limit = "256"]

#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate counted_array;
#[cfg(feature = "jsonwebtoken")]
use jsonwebtoken as jwt;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(feature = "rouille")]
#[macro_use(router)]
extern crate rouille;
#[macro_use]
extern crate serde_derive;

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
pub mod lru_disk_cache;
mod mock_command;
mod protocol;
pub mod server;
#[cfg(feature = "simple-s3")]
mod simples3;
#[doc(hidden)]
pub mod util;

use std::env;

/// Used to denote the environment variable that controls
/// logging for sccache, and sccache-dist.
pub const LOGGING_ENV: &str = "SCCACHE_LOG";

pub fn main() {
    init_logging();
    std::process::exit(match cmdline::parse() {
        Ok(cmd) => match commands::run_command(cmd) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sccache: error: {}", e);
                for e in e.chain().skip(1) {
                    eprintln!("sccache: caused by: {}", e);
                }
                2
            }
        },
        Err(e) => {
            println!("sccache: {}", e);
            for e in e.chain().skip(1) {
                println!("sccache: caused by: {}", e);
            }
            cmdline::get_app().print_help().unwrap();
            println!();
            1
        }
    });
}

fn init_logging() {
    if env::var(LOGGING_ENV).is_ok() {
        match env_logger::Builder::from_env(LOGGING_ENV).try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}
