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
#![allow(
    clippy::type_complexity,
    clippy::new_without_default,
    clippy::blocks_in_conditions
)]
#![recursion_limit = "256"]

#[macro_use]
extern crate log;
#[cfg(feature = "rouille")]
#[macro_use(router)]
extern crate rouille;
// To get macros in scope, this has to be first.
#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
pub mod errors;

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
mod net;
mod protocol;
pub mod server;
#[doc(hidden)]
pub mod util;

use std::env;

/// VERSION is the pkg version of sccache.
///
/// This version is safe to be used in cache services to indicate the version
/// that sccache ie.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Used to denote the environment variable that controls
/// logging for sccache, and sccache-dist.
pub const LOGGING_ENV: &str = "SCCACHE_LOG";

pub fn main() {
    init_logging();

    let incr_env_strs = ["CARGO_BUILD_INCREMENTAL", "CARGO_INCREMENTAL"];
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!("sccache: increment compilation is  prohibited.");
                std::process::exit(1);
            }
            _ => (),
        });

    let command = match cmdline::try_parse() {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            // If the error is from clap then let them handle formatting and exiting
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache: {some_other_err}");
                for source in some_other_err.chain().skip(1) {
                    println!("sccache: caused by: {source}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match commands::run_command(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache: error: {}", e);
            for e in e.chain().skip(1) {
                eprintln!("sccache: caused by: {}", e);
            }
            2
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
