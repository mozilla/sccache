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
use clap::ValueSource;
use clap::{error::ErrorKind, ArgGroup, IntoApp, Parser};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use which::which_in;

const ENV_VAR_SCCACHE_START_SERVER: &str = "SCCACHE_START_SERVER";

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
#[clap(group(
    ArgGroup::new("one_and_only_one")
        .args(&[
            "dist-auth",
            "dist-status",
            "show-stats",
            "start-server",
            "stop-server",
            "zero-stats",
            "package-toolchain",
            "cmd",
        ])
        .required(true)
))]
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
    #[clap(long, hide_env = true, env = ENV_VAR_SCCACHE_START_SERVER)]
    start_server: bool,
    /// stop background server
    #[clap(long)]
    stop_server: bool,
    /// zero statistic counters
    #[clap(short, long)]
    zero_stats: bool,

    /// package toolchain for distributed compilation
    #[clap(long, number_of_values = 2, value_names = &["EXECUTABLE", "OUT"])]
    package_toolchain: Vec<PathBuf>,
    /// set output format of statistics
    #[clap(long, arg_enum, value_name = "FORMAT", default_value_t = StatsFormat::default())]
    stats_format: StatsFormat,

    cmd: Vec<OsString>,
}

/// Parse the commandline into a `Command` to execute.
pub fn parse() -> Command {
    match try_parse() {
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
    }
}

fn try_parse() -> Result<Command> {
    trace!("parse");
    let cwd =
        env::current_dir().context("sccache: Couldn't determine current working directory")?;

    // We only if the value is `1` so unset it otherwise
    let internal_start_server = match env::var(ENV_VAR_SCCACHE_START_SERVER).as_deref() {
        Ok("1") => true,
        _ => {
            env::remove_var(ENV_VAR_SCCACHE_START_SERVER);
            false
        }
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

    let opts_result = Opts::try_parse_from(&args);

    // A command can either be from `ENV_VAR_SCCACHE_START_SERVER` being set or from command-line
    // args. Validate things so that error messages are nice and the returned opts are correct
    let opts = match (internal_start_server, opts_result) {
        (true, Err(e)) => {
            // Return a more obvious error message when there is a conflict from
            // `ENV_VAR_SCCACHE_START_SERVER` being used with another command
            if e.kind() == ErrorKind::ArgumentConflict {
                bail!("`{ENV_VAR_SCCACHE_START_SERVER}=1` can't be used with other commands");
            } else {
                return Err(e.into());
            }
        }
        (false, Err(e)) => {
            return Err(e.into());
        }
        (true, Ok(mut opts)) => {
            // `start_server` is used to smuggle `ENV_VAR_SCCACHE_START_SERVER` into the arg group,
            // but they should still conflict, so check the source of `start_server` to see if they
            // were both set or not
            let opts_matches = Opts::command().try_get_matches_from(&args)?;
            if let Some(ValueSource::EnvVariable) = opts_matches.value_source("start-server") {
                opts.start_server = false;
                opts
            } else {
                bail!("`{ENV_VAR_SCCACHE_START_SERVER}=1` can't be used with other commands");
            }
        }
        (false, Ok(opts)) => opts,
    };

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
    } = opts;

    Ok(if internal_start_server {
        Command::InternalStartServer
    } else if show_stats {
        Command::ShowStats(stats_format)
    } else if start_server {
        Command::StartServer
    } else if stop_server {
        Command::StopServer
    } else if zero_stats {
        Command::ZeroStats
    } else if dist_auth {
        Command::DistAuth
    } else if dist_status {
        Command::DistStatus
    } else if let [executable, out] = package_toolchain.as_slice() {
        Command::PackageToolchain(executable.into(), out.into())
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

        Command::Compile {
            exe: exe.to_owned(),
            cmdline: cmdline.to_owned(),
            cwd,
            env_vars,
        }
    } else {
        unreachable!("`ArgGroup` should enforce a single command to be run");
    })
}
