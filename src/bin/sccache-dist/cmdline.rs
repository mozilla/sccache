use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::bail;
use clap::{ArgEnum, IntoApp, Parser, Subcommand};
use sccache::{config, dist::ServerId};
use syslog::Facility;

pub enum Command {
    Auth(AuthSubcommand),
    Scheduler(config::scheduler::Config),
    Server(config::server::Config),
}

pub enum AuthSubcommand {
    Base64 {
        num_bytes: usize,
    },
    JwtHS256ServerToken {
        secret_key: String,
        server_id: ServerId,
    },
}

#[derive(Parser)]
#[clap(version)]
struct Opts {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    Auth(AuthOpts),
    Scheduler(SchedulerOpts),
    Server(ServerOpts),
}

#[derive(Parser)]
struct AuthOpts {
    #[clap(subcommand)]
    subcommand: CliAuthSubcommand,
}

#[derive(Subcommand)]
enum CliAuthSubcommand {
    GenerateJwtHs256Key,
    GenerateJwtHs256Token(ServerTokenOpts),
    GenerateSharedToken(SharedTokenOpts),
}

#[derive(Parser)]
struct ServerTokenOpts {
    /// Generate a key for the specified server
    #[clap(long, value_name = "SERVER_ADDR")]
    server: SocketAddr,
    /// Use specified key to create the token
    #[clap(long, value_name = "KEY", required_unless_present = "config")]
    secret_key: Option<String>,
    /// Use the key from the scheduler config file at PATH
    #[clap(long, value_name = "PATH", required_unless_present = "secret_key")]
    config: Option<PathBuf>,
}

#[derive(Parser)]
struct SharedTokenOpts {
    /// Use the specified number of bits of randomness
    #[clap(long, default_value_t = TokenBits(256))]
    bits: TokenBits,
}

#[derive(Debug)]
struct TokenBits(usize);

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

///
/// Parse the commandline into a `Command` to execute.
pub fn parse() -> Command {
    match try_parse() {
        Ok(cmd) => cmd,
        Err(e) => {
            println!("sccache-dist: {e}");
            for e in e.chain().skip(1) {
                println!("sccache-dist: caused by: {e}");
            }
            let mut clap_command = Opts::command();
            clap_command.print_help().unwrap();
            std::process::exit(1);
        }
    }
}

fn check_init_syslog<'a>(name: &str, log_level: LogLevel) {
    let level = log::LevelFilter::from(log_level);
    drop(syslog::init(Facility::LOG_DAEMON, level, Some(name)));
}

fn try_parse() -> anyhow::Result<Command> {
    let Opts { command } = Opts::parse();
    Ok(match command {
        CliCommand::Auth(AuthOpts { subcommand }) => Command::Auth(match subcommand {
            // Size based on https://briansmith.org/rustdoc/ring/hmac/fn.recommended_key_len.html
            CliAuthSubcommand::GenerateJwtHs256Key => AuthSubcommand::Base64 { num_bytes: 256 / 8 },
            CliAuthSubcommand::GenerateJwtHs256Token(ServerTokenOpts {
                server,
                config,
                secret_key,
            }) => {
                let secret_key = match (config, secret_key) {
                    (Some(config), None) => {
                        if let Some(config) = config::scheduler::from_path(&config)? {
                            match config.server_auth {
                                config::scheduler::ServerAuth::JwtHS256 { secret_key } => {
                                    secret_key
                                }
                                config::scheduler::ServerAuth::Insecure
                                | config::scheduler::ServerAuth::Token { token: _ } => {
                                    bail!("Scheduler not configured with JWT HS256")
                                }
                            }
                        } else {
                            bail!("Could not load config")
                        }
                    }
                    (None, Some(secret_key)) => secret_key,
                    _ => unreachable!("Prevented by `required_unless_present` with `clap`"),
                };

                AuthSubcommand::JwtHS256ServerToken {
                    secret_key,
                    server_id: ServerId::new(server),
                }
            }
            CliAuthSubcommand::GenerateSharedToken(SharedTokenOpts { bits }) => {
                AuthSubcommand::Base64 {
                    num_bytes: bits.0 / 8,
                }
            }
        }),
        CliCommand::Scheduler(SchedulerOpts { config, syslog }) => {
            check_init_syslog("sccache-scheduler", syslog);

            if let Some(config) = config::scheduler::from_path(&config)? {
                Command::Scheduler(config)
            } else {
                bail!("Could not load config")
            }
        }
        CliCommand::Server(ServerOpts { config, syslog }) => {
            check_init_syslog("sccache-buildserver", syslog);

            if let Some(config) = config::server::from_path(&config)? {
                Command::Server(config)
            } else {
                bail!("Could not load config")
            }
        }
    })
}
