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
use clap::{App, AppSettings, Arg};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use which::which_in;

arg_enum! {
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    #[derive(PartialEq)]
    pub enum StatsFormat {
        text,
        json
    }
}

/// A specific command to run.
#[derive(PartialEq)]
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

/// Get the `App` used for argument parsing.
pub fn get_app<'a, 'b>() -> App<'a, 'b> {
    App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::TrailingVarArg)
        .after_help(concat!(
                "Enabled features:\n",
                "    S3:        ", cfg!(feature = "s3"), "\n",
                "    Redis:     ", cfg!(feature = "redis"), "\n",
                "    Memcached: ", cfg!(feature = "memcached"), "\n",
                "    GCS:       ", cfg!(feature = "gcs"), "\n",
                "    Azure:     ", cfg!(feature = "azure"), "\n")
                )
        .args_from_usage(
            "-s --show-stats  'show cache statistics'
             --start-server   'start background server'
             --stop-server    'stop background server'
             -z, --zero-stats 'zero statistics counters'
             --dist-auth      'authenticate for distributed compilation'
             --dist-status    'show status of the distributed client'"
                )
        .arg(Arg::from_usage("--package-toolchain <executable> <out> 'package toolchain for distributed compilation'")
             .required(false))
        .arg(Arg::from_usage("--stats-format  'set output format of statistics'")
             .possible_values(&StatsFormat::variants())
             .default_value("text"))
        .arg(
            Arg::with_name("cmd")
                .multiple(true)
                .use_delimiter(false)
                )
}

/// Parse the commandline into a `Command` to execute.
pub fn parse() -> Result<Command> {
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
    let matches = get_app().get_matches_from(args);

    let show_stats = matches.is_present("show-stats");
    let start_server = matches.is_present("start-server");
    let stop_server = matches.is_present("stop-server");
    let zero_stats = matches.is_present("zero-stats");
    let dist_auth = matches.is_present("dist-auth");
    let dist_status = matches.is_present("dist-status");
    let package_toolchain = matches.is_present("package-toolchain");
    let cmd = matches.values_of_os("cmd");
    // Ensure that we've only received one command to run.
    fn is_some<T>(x: &Option<T>) -> bool {
        x.is_some()
    }
    if [
        internal_start_server,
        show_stats,
        start_server,
        stop_server,
        zero_stats,
        package_toolchain,
        is_some(&cmd),
    ]
    .iter()
    .filter(|&&x| x)
    .count()
        > 1
    {
        bail!("Too many commands specified");
    }
    if internal_start_server {
        Ok(Command::InternalStartServer)
    } else if show_stats {
        let fmt =
            value_t!(matches.value_of("stats-format"), StatsFormat).unwrap_or_else(|e| e.exit());
        Ok(Command::ShowStats(fmt))
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
    } else if package_toolchain {
        let mut values = matches
            .values_of_os("package-toolchain")
            .expect("Parsed package-toolchain but no values");
        assert!(values.len() == 2);
        let (executable, out) = (
            values.next().expect("package-toolchain missing value 1"),
            values.next().expect("package-toolchain missing value 2"),
        );
        Ok(Command::PackageToolchain(executable.into(), out.into()))
    } else if let Some(mut args) = cmd {
        if let Some(exe) = args.next() {
            let cmdline = args.map(|s| s.to_owned()).collect::<Vec<_>>();
            let mut env_vars = env::vars_os().collect::<Vec<_>>();

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
                cmdline,
                cwd,
                env_vars,
            })
        } else {
            bail!("No compile command");
        }
    } else {
        bail!("No command specified");
    }
}
