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
#![recursion_limit = "128"]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate counted_array;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate futures;
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
mod mock_command;
mod protocol;
pub mod server;
#[cfg(feature = "simple-s3")]
mod simples3;
#[doc(hidden)]
pub mod util;

use std::env;
use std::io::Write;

pub fn main() {
    init_logging();
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
            for e in e.iter().skip(1) {
                println!("caused by: {}", e);
            }
            cmdline::get_app().print_help().unwrap();
            println!();
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
