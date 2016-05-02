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

use clap::{App, AppSettings};
use std::env;

/// A specific command to run.
pub enum Command {
    /// Show usage and exit.
    Usage,
    /// Show cache statistics and exit.
    ShowStats,
    /// Run background server.
    InternalStartServer,
    /// Start background server as a subprocess.
    StartServer,
    /// Stop background server.
    StopServer,
    /// Run a compiler command.
    Compile {
        /// The command to execute
        cmdline: Vec<String>,
        /// The directory in which to execute the command.
        cwd: String,
    },
}

/// Get the `App` used for argument parsing.
fn get_app<'a, 'b>() -> App<'a, 'b> {
    App::new("sccache")
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::TrailingVarArg)
        .args_from_usage(
            "-s --show-stats 'show cache statistics'
             --start-server  'start background server'
             --stop-server   'stop background server'
             [cmd]... 'commands to run'"
                )
}

/// Print usage summary and return a `Command::Usage`.
fn usage() -> Command {
    get_app().print_help().unwrap();
    Command::Usage
}

/// Parse the commandline into a `Command` to execute.
pub fn parse<'a>() -> Command {
    let matches = get_app().get_matches();

    // The internal start server command is passed in the environment.
    let internal_start_server = match env::var("SCCACHE_START_SERVER") {
        Ok(val) => val == "1",
        Err(_) => false,
    };
    let show_stats = matches.is_present("show-stats");
    let start_server = matches.is_present("start-server");
    let stop_server = matches.is_present("stop-server");
    let cmd = matches.values_of("cmd");
    // Ensure that we've only received one command to run.
    fn is_some<T>(x : &Option<T>) -> bool {
        x.is_some() // .as_ref().and(Some(true)).unwrap_or(false)
    }
    if [
        internal_start_server,
        show_stats,
        start_server,
        stop_server,
        is_some(&cmd),
            ].iter()
        .fold(0, |acc, &x| acc + (x as usize)) > 1 {
            println!("sccache: Too many commands specified");
            return usage();
        }
    if internal_start_server {
        Command::InternalStartServer
    } else if show_stats {
        Command::ShowStats
    } else if start_server {
        Command::StartServer
    } else if stop_server {
        Command::StopServer
    } else if let Some(a) = cmd {
        if let Some(cwd) = env::current_dir().ok()
            .and_then(|d| d.to_str().and_then(|s| Some(s.to_owned()))) {
                Command::Compile {
                    cmdline: a.map(|s| s.to_owned()).collect(),
                    cwd: cwd,
                }
            } else {
                println!("sccache: Couldn't determine current working directory");
                usage()
            }
    } else {
        println!("sccache: No command specified");
        usage()
    }
}
