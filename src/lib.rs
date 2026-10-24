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

// The instrumented binary built by `scripts/build-pgo.sh` (`--cfg pgo_training`)
// has to flush its own profile counters on Windows. sccache leaves through
// `std::process::exit`, which is `libc::exit` on Unix but `ExitProcess` on
// Windows; the latter skips the `atexit` handler the LLVM profiling runtime
// writes the counters from, so the training runs would leave no profile behind.
#[cfg(all(pgo_training, windows))]
unsafe extern "C" {
    fn __llvm_profile_write_file() -> i32;
}

/// Terminates the process with `code`, flushing the PGO counters when the
/// binary was built for profile training on Windows.
fn exit(code: i32) -> ! {
    #[cfg(all(pgo_training, windows))]
    // SAFETY: `__llvm_profile_write_file` is provided by the LLVM profiling
    // runtime, which is linked in whenever this cfg is set (the same build
    // passes `-Cprofile-generate`). It takes no arguments and only writes the
    // counter file named by `LLVM_PROFILE_FILE`.
    unsafe {
        __llvm_profile_write_file();
    }
    std::process::exit(code)
}

pub fn main() {
    init_logging();

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
                exit(1);
            }
        },
    };

    exit(match commands::run_command(command) {
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
        let mut builder = env_logger::Builder::from_env(LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}
