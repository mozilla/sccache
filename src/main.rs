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

#![cfg_attr(feature = "unstable", feature(windows_process_extensions))]

extern crate app_dirs;
extern crate chrono;
extern crate clap;
extern crate crypto;
#[cfg(unix)]
extern crate daemonize;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate filetime;
#[macro_use]
extern crate futures;
extern crate futures_cpupool;
extern crate hyper;
extern crate hyper_tls;
#[cfg(windows)]
extern crate kernel32;
extern crate local_encoding;
#[macro_use]
extern crate log;
extern crate lru_disk_cache;
extern crate fern;
extern crate libc;
#[cfg(windows)]
extern crate named_pipe;
extern crate number_prefix;
extern crate protobuf;
extern crate regex;
extern crate retry;
extern crate rustc_serialize;
extern crate serde_json;
extern crate sha1;
extern crate tempdir;
extern crate time;
extern crate tokio_core;
extern crate tokio_process;
extern crate tokio_proto;
extern crate tokio_service;
extern crate uuid;
#[cfg(windows)]
extern crate winapi;
extern crate which;
extern crate zip;

// To get macros in scope, this has to be first.
#[cfg(test)]
#[macro_use]
mod test;

mod cache;
mod client;
mod cmdline;
mod commands;
mod compiler;
mod errors;
mod mock_command;
mod protocol;
mod server;
mod simples3;

use std::env;

fn main() {
    init_logging();
    std::process::exit(match cmdline::parse() {
        Ok(cmd) => commands::run_command(cmd),
        Err(e) => {
            println!("sccache: {}", e);
            cmdline::get_app().print_help().unwrap();
            println!("");
            1
        }
    });
}

fn init_logging() {
    match if env::var("RUST_LOG").is_ok() {
        env_logger::init()
            .map_err(|e| format!("{:?}", e))
    } else {
        match env::var("SCCACHE_LOG_LEVEL") {
            Ok(log_level) => {
                let log_level = match &*log_level.to_lowercase() {
                    "off" => log::LogLevelFilter::Off,
                    "trace" => log::LogLevelFilter::Trace,
                    "debug" => log::LogLevelFilter::Debug,
                    "info" => log::LogLevelFilter::Info,
                    "warn" => log::LogLevelFilter::Warn,
                    "error" => log::LogLevelFilter::Error,
                    _ => panic!("Invalid log level {}", log_level),
                };

                let logger_config = fern::DispatchConfig {
                    format: Box::new(|msg: &str, level: &log::LogLevel, _location: &log::LogLocation| {
                        format!("[{}][{}] {}", time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(), level, msg)
                    }),
                    //TODO: only the server process should output to the log file.
                    output: vec![fern::OutputConfig::stdout(), fern::OutputConfig::file("sccache.log")],
                    level: log::LogLevelFilter::Trace,
                };
                fern::init_global_logger(logger_config, log_level)
                    .map_err(|e| format!("{:?}", e))
            },
            Err(_) => Ok(()),
        }
    } {
        Ok(_) => (),
        Err(e) => panic!(format!("Failed to initalize logging: {}", e)),
    }
}
