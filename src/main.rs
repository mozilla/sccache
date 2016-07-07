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

extern crate clap;
extern crate env_logger;
extern crate filetime;
extern crate kernel32;
#[macro_use] 
extern crate log;
extern crate fern;
extern crate libc;
extern crate mio;
extern crate number_prefix;
extern crate protobuf;
extern crate retry;
extern crate rusoto;
extern crate sha1;
extern crate tempdir;
extern crate time;
extern crate winapi;
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
mod mock_command;
mod protocol;
mod server;

use std::env;

fn main() {
    init_logging();
    std::process::exit(commands::run_command(cmdline::parse()));
}


fn init_logging(){

    let logger_config = fern::DispatchConfig {
        format: Box::new(|msg: &str, level: &log::LogLevel, _location: &log::LogLocation| {
            format!("[{}][{}] {}", time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(), level, msg)
        }),
        output: vec![fern::OutputConfig::stdout(), fern::OutputConfig::file("sccache2.log")],
        level: log::LogLevelFilter::Trace,
    };

    // Set current log level depending on environment variable
    let log_level = match &*env::var("SCCACHE2_LOG_LEVEL").unwrap_or("warn".to_owned()).to_lowercase() {
        "off" => log::LogLevelFilter::Off,
        "error" => log::LogLevelFilter::Error,
        "info" => log::LogLevelFilter::Info,
        "debug" => log::LogLevelFilter::Debug,
        "trace" => log::LogLevelFilter::Trace,
        _=> log::LogLevelFilter::Warn,
    };

    if let Err(e) = fern::init_global_logger(logger_config, log_level)
    {
        panic!("Failed to initialize global logger: {}", e);
    }
}
