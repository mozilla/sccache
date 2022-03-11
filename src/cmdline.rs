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

use crate::errors::*;
use clap::{error::ErrorKind, IntoApp, Parser};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use which::which_in;

#[derive(clap::ArgEnum, Debug, Clone)]
pub enum StatsFormat {
    Text,
    Json,
}

impl Default for StatsFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// A specific command to run.
pub enum Command {
    /// Show cache statistics and exit.
    ShowStats(StatsFormat),
    /// Run background server.
    InternalStartServer,
    /// Start background server as a subprocess.
    StartServer,
    /// Stop background server.
    StopServer,
    /// Zero cache statistics and exit.
    ZeroStats,
    /// Show the status of the distributed client.
    DistStatus,
    /// Perform a login to authenticate for distributed compilation.
    DistAuth,
    /// Package a toolchain for distributed compilation (executable, out)
    PackageToolchain(PathBuf, PathBuf),
    /// Run a compiler command.
    Compile {
        /// The binary to execute.
        exe: OsString,
        /// The commandline arguments to pass to `exe`.
        cmdline: Vec<OsString>,
        /// The directory in which to execute the command.
        cwd: PathBuf,
        /// The environment variables to use for execution.
        env_vars: Vec<(OsString, OsString)>,
    },
}

#[derive(Parser)]
#[clap(version)]
#[clap(trailing_var_arg = true)]
#[clap(after_help = concat!(
        "Enabled features:\n",
        "    S3:        ", cfg!(feature = "s3"), "\n",
        "    Redis:     ", cfg!(feature = "redis"), "\n",
        "    Memcached: ", cfg!(feature = "memcached"), "\n",
        "    GCS:       ", cfg!(feature = "gcs"), "\n",
        "    Azure:     ", cfg!(feature = "azure"), "\n")
)]
struct Opts {
    /// authenticate for distributed compilation
    #[clap(long)]
    dist_auth: bool,
    /// show status of the distributed client
    #[clap(long)]
    dist_status: bool,
    /// show cache statistics
    #[clap(short, long)]
    show_stats: bool,
    /// start background server
    #[clap(long)]
    start_server: bool,
    /// stop background server
    #[clap(long)]
    stop_server: bool,
    /// zero statistic counters
    #[clap(short, long)]
    zero_stats: bool,

    /// package toolchain for distributed compilation
    #[clap(long, number_of_values = 2)]
    package_toolchain: Vec<PathBuf>,
    /// set output format of statistics
    #[clap(long, arg_enum, default_value_t = StatsFormat::default())]
    stats_format: StatsFormat,

    cmd: Vec<OsString>,
}

/// Parse the commandline into a `Command` to execute.
pub fn parse() -> Command {
    match try_parse() {
        Ok(cmd) => cmd,
        Err(e) => {
            println!("sccache: {e}");
            for e in e.chain().skip(1) {
                println!("sccache: caused by: {e}");
            }
            let mut clap_command = Opts::command();
            clap_command.print_help().unwrap();
            std::process::exit(1);
        }
    }
}

fn try_parse() -> Result<Command> {
    trace!("parse");
    let cwd =
        env::current_dir().context("sccache: Couldn't determine current working directory")?;
    // The internal start server command is passed in the environment.
    let internal_start_server = match env::var("SCCACHE_START_SERVER") {
        Ok(val) => val == "1",
        Err(_) => false,
    };
    let mut args: Vec<_> = env::args_os().collect();
    if !internal_start_server {
        if let Ok(exe) = env::current_exe() {
            match exe
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_lowercase())
            {
                // If the executable has its standard name, do nothing.
                Some(ref e) if e == env!("CARGO_PKG_NAME") => {}
                // Otherwise, if it was copied/hardlinked under a different $name, act
                // as if it were invoked with `sccache $name`, but avoid $name resolving
                // to ourselves again if it's in the PATH.
                _ => {
                    if let (Some(path), Some(exe_filename)) = (env::var_os("PATH"), exe.file_name())
                    {
                        match which_in(exe_filename, Some(&path), &cwd) {
                            Ok(ref full_path)
                                if full_path.canonicalize()? == exe.canonicalize()? =>
                            {
                                if let Some(dir) = full_path.parent() {
                                    let path = env::join_paths(
                                        env::split_paths(&path).filter(|p| p != dir),
                                    )
                                    .ok();
                                    if let Ok(full_path) = which_in(exe_filename, path, &cwd) {
                                        args[0] = full_path.into();
                                    }
                                }
                            }
                            Ok(full_path) => args[0] = full_path.into(),
                            Err(_) => {}
                        }
                        args.insert(0, env!("CARGO_PKG_NAME").into());
                    }
                }
            }
        }
    }

    let Opts {
        dist_auth,
        dist_status,
        show_stats,
        start_server,
        stop_server,
        zero_stats,
        package_toolchain,
        stats_format,
        cmd,
    } = Opts::parse_from(args);

    // Ensure that we've only received one command to run.
    if [
        dist_auth,
        dist_status,
        internal_start_server,
        show_stats,
        start_server,
        stop_server,
        zero_stats,
        !cmd.is_empty(),
        !package_toolchain.is_empty(),
    ]
    .iter()
    .filter(|&&x| x)
    .count()
        > 1
    {
        let mut clap_command = Opts::command();
        clap_command
            .error(ErrorKind::ArgumentConflict, "Only one command can be run")
            .exit();
    }

    if internal_start_server {
        Ok(Command::InternalStartServer)
    } else if show_stats {
        Ok(Command::ShowStats(stats_format))
    } else if start_server {
        Ok(Command::StartServer)
    } else if stop_server {
        Ok(Command::StopServer)
    } else if zero_stats {
        Ok(Command::ZeroStats)
    } else if dist_auth {
        Ok(Command::DistAuth)
    } else if dist_status {
        Ok(Command::DistStatus)
    } else if let [executable, out] = package_toolchain.as_slice() {
        Ok(Command::PackageToolchain(executable.into(), out.into()))
    } else if let [exe, cmdline @ ..] = cmd.as_slice() {
        let mut env_vars: Vec<_> = env::vars_os().collect();

        // If we're running under rr, avoid the `LD_PRELOAD` bits, as it will
        // almost surely do the wrong thing, as the compiler gets executed
        // in a different process tree.
        //
        // FIXME: Maybe we should strip out `LD_PRELOAD` always?
        if env::var_os("RUNNING_UNDER_RR").is_some() {
            env_vars.retain(|(k, _v)| k != "LD_PRELOAD" && k != "RUNNING_UNDER_RR");
        }

        Ok(Command::Compile {
            exe: exe.to_owned(),
            cmdline: cmdline.to_owned(),
            cwd,
            env_vars,
        })
    } else {
        let mut clap_command = Opts::command();
        clap_command
            .error(ErrorKind::ArgumentConflict, "No command specified")
            .exit();
    }
}
