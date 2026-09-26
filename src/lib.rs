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

pub mod cache;
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

    // Logging is initialized after parsing so the compile-wrapper case can keep
    // sccache's own log records off the wrapped compiler's stderr.
    init_logging(&command);

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

fn init_logging(command: &cmdline::Command) {
    if env::var(LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        // When sccache runs as a compiler wrapper (`sccache <compiler> ...`) it
        // shares stderr with the wrapped compiler. Build tools treat any
        // unexpected stderr on a feature probe as a compiler failure: libtool's
        // `-fPIC` check sets `pic_flag=""` on non-empty stderr, producing non-PIC
        // objects that then fail to link into a shared library. sccache's own log
        // records must never reach that stderr. Send them to SCCACHE_ERROR_LOG
        // when set; otherwise keep stderr only for an interactive terminal (so
        // `SCCACHE_LOG=debug sccache gcc ...` at a prompt still shows logs) and
        // discard them when stderr is captured by a build.
        if matches!(command, cmdline::Command::Compile { .. }) {
            use std::io::IsTerminal;
            let target: Option<Box<dyn std::io::Write + Send + 'static>> =
                match env::var("SCCACHE_ERROR_LOG") {
                    Ok(path) if !path.is_empty() => Some(
                        std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&path)
                            .map(|f| Box::new(f) as Box<dyn std::io::Write + Send + 'static>)
                            .unwrap_or_else(|_| Box::new(std::io::sink())),
                    ),
                    _ if !std::io::stderr().is_terminal() => Some(Box::new(std::io::sink())),
                    _ => None,
                };
            if let Some(target) = target {
                builder.target(env_logger::Target::Pipe(target));
            }
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}
