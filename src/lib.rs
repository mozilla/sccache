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
#![recursion_limit = "256"]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate counted_array;
#[macro_use]
extern crate futures;
use commands::DEFAULT_PORT;
use get_port::{tcp::TcpPort, Ops};
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

const LOGGING_ENV: &str = "SCCACHE_LOG";

pub fn main() {
    init_logging();

    if !check_valid_port_available(true) {
        std::process::exit(1);
    }

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
            Err(e) => panic!(format!("Failed to initalize logging: {:?}", e)),
        }
    }
}

///Returns true iff a valid port configuration for the cmdline command exists optionally printing error messages for the user
fn check_valid_port_available(print_error_message: bool) -> bool {
    let host = "127.0.0.1";

    // Check default port
    let default_port_valid = TcpPort::is_port_available(host, DEFAULT_PORT);

    // Check port set via env var SCCACHE_SERVER_PORT
    let mut env_port_valid = false;
    let mut env_port: u16 = 0;

    let env_var_raw = env::var("SCCACHE_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok());

    if env_var_raw.is_some() {
        env_port = env_var_raw.unwrap();
        env_port_valid = TcpPort::is_port_available(host, env_port);
    }

    // If neither are valid for binding a new server
    if !env_port_valid && !default_port_valid {
        let cmdline_command = cmdline::parse();

        if cmdline_command.is_ok() {
            let cmd = cmdline_command.unwrap();
            
            // and we are running a --start-server 
            if cmd == cmdline::Command::StartServer {
                if print_error_message {
                    let mut chosen_port = DEFAULT_PORT;
                    let mut user_output_port_term = "default port";
                    let mut user_output_verb = "setting";

                    if env_var_raw.is_some() {
                        chosen_port = env_port;
                        user_output_port_term = "user-provided port";
                        user_output_verb = "resetting"
                    }

                    eprintln!(
                        "sccache: Server startup failed: Unable to use {} {}",
                        user_output_port_term, chosen_port
                    );
                    eprintln!(
                        "sccache: Try {} SCCACHE_SERVER_PORT to a different port",
                        user_output_verb
                    );
                    eprintln!(
                        "sccache: If a server is already running on port {} use 'sccache --stop-server' instead.",
                        chosen_port
                    );
                }

                return false;
            }
        }
    }

    // Reaching here means we validated, though the later usage of the port
    // could still suffer from a Time of Check is not Time of Use failure
    return true;
}
