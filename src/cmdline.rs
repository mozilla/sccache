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
use clap::{Arg, ArgAction, ArgGroup, ValueEnum, error::ErrorKind};
use same_file::is_same_file;
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use which::which_in_all;

const ENV_VAR_INTERNAL_START_SERVER: &str = "SCCACHE_START_SERVER";

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum StatsFormat {
    #[default]
    Text,
    Json,
}

impl StatsFormat {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl FromStr for StatsFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => bail!("Unrecognized stats format: {:?}", s),
        }
    }
}

/// A specific command to run.
pub enum Command {
    /// Show cache statistics and exit.
    ShowStats(StatsFormat, bool),
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
    DebugPreprocessorCacheEntries,
}

fn flag_infer_long_and_short(name: &'static str) -> Arg {
    flag_infer_long(name).short(name.chars().next().expect("Name needs at least one char"))
}

fn flag_infer_long(name: &'static str) -> Arg {
    Arg::new(name).long(name)
}

/// Get the [`clap::Command`] used for argument parsing.
fn get_clap_command() -> clap::Command {
    clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .max_term_width(110)
        .after_help(concat!(
            "Enabled features:\n",
            "    S3:        ",
            cfg!(feature = "s3"),
            "\n",
            "    Redis:     ",
            cfg!(feature = "redis"),
            "\n",
            "    Memcached: ",
            cfg!(feature = "memcached"),
            "\n",
            "    GCS:       ",
            cfg!(feature = "gcs"),
            "\n",
            "    GHA:       ",
            cfg!(feature = "gha"),
            "\n",
            "    Azure:     ",
            cfg!(feature = "azure"),
            "\n",
            "    WebDAV:    ",
            cfg!(feature = "webdav"),
            "\n",
            "    OSS:       ",
            cfg!(feature = "oss"),
            "\n",
            "    COS:       ",
            cfg!(feature = "cos"),
            "\n"
        ))
        .args(&[
            flag_infer_long_and_short("show-stats")
                .help("show cache statistics")
                .action(ArgAction::SetTrue),
            flag_infer_long("show-adv-stats")
                .help("show advanced cache statistics")
                .action(ArgAction::SetTrue),
            flag_infer_long("start-server")
                .help("start background server")
                .action(ArgAction::SetTrue),
            flag_infer_long("debug-preprocessor-cache")
                .help("show all preprocessor cache entries")
                .action(ArgAction::SetTrue),
            flag_infer_long("stop-server")
                .help("stop background server")
                .action(ArgAction::SetTrue),
            flag_infer_long_and_short("zero-stats")
                .help("zero statistics counters")
                .action(ArgAction::SetTrue),
            flag_infer_long("dist-auth")
                .help("authenticate for distributed compilation")
                .action(ArgAction::SetTrue),
            flag_infer_long("dist-status")
                .help("show status of the distributed client")
                .action(ArgAction::SetTrue),
            flag_infer_long("package-toolchain")
                .help("package toolchain for distributed compilation")
                .value_parser(clap::value_parser!(PathBuf))
                .num_args(2)
                .value_names(["EXE", "OUT"]),
            flag_infer_long("stats-format")
                .help("set output format of statistics")
                .value_name("FMT")
                .value_parser(clap::value_parser!(StatsFormat))
                .default_value(StatsFormat::default().as_str()),
            Arg::new("CMD")
                .value_parser(clap::value_parser!(OsString))
                .trailing_var_arg(true)
                .action(ArgAction::Append),
        ])
        .group(
            ArgGroup::new("one_and_only_one")
                .args([
                    "dist-auth",
                    "debug-preprocessor-cache",
                    "dist-status",
                    "show-stats",
                    "show-adv-stats",
                    "start-server",
                    "stop-server",
                    "zero-stats",
                    "package-toolchain",
                    "CMD",
                ])
                .required(true),
        )
}

/// Find the first `name` in `path` that is not `self_exe`, so that a link to
/// sccache named after a compiler wraps the real compiler further down PATH.
/// Files are compared by identity, which catches symlinks as well as hardlinks.
/// A candidate that cannot be opened is skipped.
fn find_real_command(name: &OsStr, path: &OsStr, cwd: &Path, self_exe: &Path) -> Option<PathBuf> {
    which_in_all(name, Some(path), cwd)
        .ok()?
        .find(|p| is_same_file(p, self_exe).is_ok_and(|same| !same))
}

/// Parse the commandline args into a `Result<Command>` to execute.
pub fn try_parse() -> Result<Command> {
    trace!("parse");

    let cwd =
        env::current_dir().context("sccache: Couldn't determine current working directory")?;

    // We only care if it's `1`
    let internal_start_server = env::var(ENV_VAR_INTERNAL_START_SERVER).as_deref() == Ok("1");
    let mut args: Vec<_> = env::args_os().collect();

    if !internal_start_server {
        // current_exe() follows symlinks on some OSes, so try argv[0] to get the original invocation
        if let Ok(exe) = match env::args().next() {
            Some(s) if !s.is_empty() => Ok(PathBuf::from(s)),
            _ => env::current_exe(),
        } {
            match exe
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_lowercase())
            {
                // If the executable has its standard name, do nothing.
                Some(ref e) if e == env!("CARGO_PKG_NAME") => {}
                // Otherwise, if it was copied/linked under a different $name, act
                // as if it were invoked with `sccache $name`, but avoid $name resolving
                // to ourselves again if it's in the PATH.
                _ => {
                    if let (Some(path), Some(exe_filename)) = (env::var_os("PATH"), exe.file_name())
                    {
                        let self_exe = env::current_exe()?;
                        // Without a real $name to wrap, we would end up wrapping
                        // ourselves and recursing forever (e.g. via `$name -vV`).
                        let Some(full_path) =
                            find_real_command(exe_filename, &path, &cwd, &self_exe)
                        else {
                            bail!(
                                "`{}` not found in PATH (`{}` is {} itself and cannot wrap itself)",
                                exe_filename.display(),
                                exe.display(),
                                env!("CARGO_PKG_NAME"),
                            );
                        };
                        args[0] = full_path.into();
                        args.insert(0, env!("CARGO_PKG_NAME").into());
                    }
                }
            }
        }
    }

    let matches_result = get_clap_command().try_get_matches_from(args);

    // A command can either be from `ENV_VAR_INTERNAL_START_SERVER` being set or from command-line
    // args. Validate things so that error messages are nice and the returned opts are correct
    match (internal_start_server, matches_result) {
        (true, Err(e)) => {
            // Need to make sure that the error from `clap` is due to a missing command and not
            // some other issue
            if e.kind() == ErrorKind::MissingRequiredArgument {
                Ok(Command::InternalStartServer)
            } else {
                Err(e.into())
            }
        }
        (false, Err(e)) => Err(e.into()),
        (true, Ok(_)) => {
            // `ENV_VAR_INTERNAL_START_SERVER` and a match means that more than one command was
            // provided
            bail!("`{ENV_VAR_INTERNAL_START_SERVER}=1` can't be used with other commands");
        }
        (false, Ok(matches)) => {
            if matches.get_flag("show-stats") {
                let fmt = matches
                    .get_one("stats-format")
                    .cloned()
                    .expect("There is a default value");
                Ok(Command::ShowStats(fmt, false))
            } else if matches.get_flag("show-adv-stats") {
                let fmt = matches
                    .get_one("stats-format")
                    .cloned()
                    .expect("There is a default value");
                Ok(Command::ShowStats(fmt, true))
            } else if matches.get_flag("start-server") {
                Ok(Command::StartServer)
            } else if matches.get_flag("debug-preprocessor-cache") {
                Ok(Command::DebugPreprocessorCacheEntries)
            } else if matches.get_flag("stop-server") {
                Ok(Command::StopServer)
            } else if matches.get_flag("zero-stats") {
                Ok(Command::ZeroStats)
            } else if matches.get_flag("dist-auth") {
                Ok(Command::DistAuth)
            } else if matches.get_flag("dist-status") {
                Ok(Command::DistStatus)
            } else if matches.contains_id("package-toolchain") {
                let mut toolchain_values = matches
                    .get_many("package-toolchain")
                    .expect("`package-toolchain` requires two values")
                    .cloned()
                    .collect::<Vec<PathBuf>>();
                let maybe_out = toolchain_values.pop();
                let maybe_exe = toolchain_values.pop();
                match (maybe_exe, maybe_out) {
                    (Some(exe), Some(out)) => Ok(Command::PackageToolchain(exe, out)),
                    _ => unreachable!("clap should enforce two values"),
                }
            } else if matches.contains_id("CMD") {
                let mut env_vars = env::vars_os().collect::<Vec<_>>();

                // If we're running under rr, avoid the `LD_PRELOAD` bits, as it will
                // almost surely do the wrong thing, as the compiler gets executed
                // in a different process tree.
                env_vars.retain(|(k, _v)| {
                    k != "LD_PRELOAD"
                        && k != "RUNNING_UNDER_RR"
                        && k != "HOSTNAME"
                        && k != "PWD"
                        && k != "HOST"
                        && k != "RPM_BUILD_ROOT"
                        && k != "SOURCE_DATE_EPOCH"
                        && k != "RPM_PACKAGE_RELEASE"
                        && k != "MINICOM"
                        && k != "DESTDIR"
                        && k != "RPM_PACKAGE_VERSION"
                        && k != "CARGO_MAKEFLAGS"
                });

                let cmd = matches
                    .get_many("CMD")
                    .expect("CMD is required")
                    .cloned()
                    .collect::<Vec<OsString>>();
                match cmd.as_slice() {
                    [exe, cmdline @ ..] => Ok(Command::Compile {
                        exe: exe.to_owned(),
                        cmdline: cmdline.to_owned(),
                        cwd,
                        env_vars,
                    }),
                    _ => unreachable!("clap should enforce at least one value in cmd"),
                }
            } else {
                unreachable!("Either the arg group or env variable should provide a command");
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::find_real_command;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn find_real_command_skips_every_link_to_self() {
        let tmp = tempfile::tempdir().unwrap();
        let self_exe = tmp.path().join("sccache");
        fs::write(&self_exe, "").unwrap();
        fs::set_permissions(&self_exe, fs::Permissions::from_mode(0o755)).unwrap();

        // A symlink and a hardlink to sccache named `cc`, ahead of the real one.
        let dirs: Vec<_> = ["link1", "link2", "real"]
            .iter()
            .map(|d| tmp.path().join(d))
            .collect();
        for dir in &dirs {
            fs::create_dir(dir).unwrap();
        }
        symlink(&self_exe, dirs[0].join("cc")).unwrap();
        fs::hard_link(&self_exe, dirs[1].join("cc")).unwrap();
        let real = dirs[2].join("cc");
        fs::write(&real, "").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();

        let path = std::env::join_paths(&dirs).unwrap();
        assert_eq!(
            find_real_command("cc".as_ref(), &path, tmp.path(), &self_exe),
            Some(real)
        );

        // Without the real one, there is nothing to wrap.
        let path = std::env::join_paths(&dirs[..2]).unwrap();
        assert_eq!(
            find_real_command("cc".as_ref(), &path, tmp.path(), &self_exe),
            None
        );
    }
}
