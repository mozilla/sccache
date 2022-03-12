use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::bail;
use clap::{ArgEnum, ArgGroup, Parser, Subcommand};
use sccache::{
    config::{self, scheduler::ServerAuth as SchedulerServerAuth},
    dist::ServerId,
};
use syslog::Facility;

use crate::cmdline::{AuthSubcommand as ExternalAuthSubcommand, Command as ExternalCommand};

#[derive(Parser)]
#[clap(version)]
#[clap(propagate_version = true)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Auth(AuthOpts),
    Scheduler(SchedulerOpts),
    Server(ServerOpts),
}

#[derive(Parser)]
struct AuthOpts {
    #[clap(subcommand)]
    subcommand: AuthCommand,
}

#[derive(Subcommand)]
enum AuthCommand {
    GenerateJwtHs256Key,
    GenerateJwtHs256ServerToken(ServerTokenOpts),
    GenerateSharedToken(SharedTokenOpts),
}

#[derive(Parser)]
#[clap(group(
    ArgGroup::new("key_source_mutual_exclusion")
        .args(&["secret-key", "config"])
        .required(true)
))]
struct ServerTokenOpts {
    /// Generate a key for the specified server
    #[clap(long, value_name = "SERVER_ADDR")]
    server: SocketAddr,
    /// Use specified key to create the token
    #[clap(long, value_name = "KEY")]
    secret_key: Option<String>,
    /// Use the key from the scheduler config file at PATH
    #[clap(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[derive(Parser)]
struct SharedTokenOpts {
    /// Use the specified number of bits of randomness
    #[clap(long, default_value_t = TokenBits::default())]
    bits: TokenBits,
}

#[derive(Debug)]
struct TokenBits(usize);

impl TokenBits {
    fn as_bytes(&self) -> usize {
        self.0 / 8
    }
}

impl Default for TokenBits {
    fn default() -> Self {
        // Size based on https://briansmith.org/rustdoc/ring/hmac/fn.recommended_key_len.html
        Self(256)
    }
}

impl FromStr for TokenBits {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bits: usize = s.parse()?;
        if bits % 8 != 0 || bits < 64 || bits > 4_096 {
            bail!("Number of bits must be divisible by 8, greater than 64 and less than 4096")
        }

        Ok(Self(bits))
    }
}

impl fmt::Display for TokenBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Parser)]
struct SchedulerOpts {
    /// Use the scheduler config file at PATH
    #[clap(long, value_name = "PATH")]
    config: PathBuf,
    /// Log to the syslog with LEVEL
    #[clap(long, value_name = "LEVEL", arg_enum)]
    syslog: LogLevel,
}

#[derive(ArgEnum, Clone, Copy)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(log_level: LogLevel) -> Self {
        match log_level {
            LogLevel::Error => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Info => Self::Info,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace,
        }
    }
}

#[derive(Parser)]
struct ServerOpts {
    /// Use the server config file at PATH
    #[clap(long, value_name = "PATH")]
    config: PathBuf,
    /// Log to the syslog with LEVEL
    #[clap(long, value_name = "LEVEL", arg_enum)]
    syslog: LogLevel,
}

/// Parse the commandline into a `Command` to execute.
pub fn parse() -> ExternalCommand {
    match try_parse() {
        Ok(cmd) => cmd,
        Err(e) => {
            println!("sccache-dist: {e}");
            for e in e.chain().skip(1) {
                println!("sccache-dist: caused by: {e}");
            }
            std::process::exit(1);
        }
    }
}

fn check_init_syslog(name: &str, log_level: LogLevel) {
    let level = log::LevelFilter::from(log_level);
    drop(syslog::init(Facility::LOG_DAEMON, level, Some(name)));
}

fn try_parse() -> anyhow::Result<ExternalCommand> {
    let Opts { command } = Opts::parse();
    Ok(match command {
        Command::Auth(AuthOpts { subcommand }) => ExternalCommand::Auth(match subcommand {
            AuthCommand::GenerateJwtHs256Key => ExternalAuthSubcommand::Base64 {
                num_bytes: TokenBits::default().as_bytes(),
            },
            AuthCommand::GenerateJwtHs256ServerToken(ServerTokenOpts {
                server,
                config,
                secret_key,
            }) => {
                let secret_key = match (config, secret_key) {
                    (Some(config), None) => {
                        if let Some(config) = config::scheduler::from_path(&config)? {
                            match config.server_auth {
                                SchedulerServerAuth::JwtHS256 { secret_key } => secret_key,
                                SchedulerServerAuth::Insecure
                                | SchedulerServerAuth::Token { .. } => {
                                    bail!("Scheduler not configured with JWT HS256")
                                }
                            }
                        } else {
                            bail!("Could not load config")
                        }
                    }
                    (None, Some(secret_key)) => secret_key,
                    _ => unreachable!("Prevented by `key_source_mutual_exclusion` `ArgGroup`"),
                };

                ExternalAuthSubcommand::JwtHS256ServerToken {
                    secret_key,
                    server_id: ServerId::new(server),
                }
            }
            AuthCommand::GenerateSharedToken(SharedTokenOpts { bits }) => {
                ExternalAuthSubcommand::Base64 {
                    num_bytes: bits.as_bytes(),
                }
            }
        }),
        Command::Scheduler(SchedulerOpts { config, syslog }) => {
            check_init_syslog("sccache-scheduler", syslog);

            if let Some(config) = config::scheduler::from_path(&config)? {
                ExternalCommand::Scheduler(config)
            } else {
                bail!("Could not load config")
            }
        }
        Command::Server(ServerOpts { config, syslog }) => {
            check_init_syslog("sccache-buildserver", syslog);

            if let Some(config) = config::server::from_path(&config)? {
                ExternalCommand::Server(config)
            } else {
                bail!("Could not load config")
            }
        }
    })
}
