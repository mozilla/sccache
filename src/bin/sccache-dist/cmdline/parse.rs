use std::{env, ffi::OsString, fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::bail;
use clap::{Arg, ArgGroup, Command as ClapCommand};
use sccache::{config, dist::ServerId};
use syslog::Facility;

use crate::cmdline::{AuthSubcommand, Command};

#[derive(Debug)]
struct TokenLength(usize);

impl TokenLength {
    fn as_bytes(&self) -> usize {
        self.0 / 8
    }

    fn from_bits(bits: &str) -> anyhow::Result<Self> {
        let bits: usize = bits.parse()?;
        if bits % 8 != 0 || bits < 64 || bits > 4_096 {
            bail!("Number of bits must be divisible by 8, greater than 64 and less than 4096")
        }

        Ok(Self(bits))
    }
}

impl fmt::Display for TokenLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    fn values() -> &'static [Self] {
        &[
            Self::Error,
            Self::Warn,
            Self::Info,
            Self::Debug,
            Self::Trace,
        ]
    }
}

impl FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let variant = match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => bail!("Unknown log level: {:?}", s),
        };

        Ok(variant)
    }
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

/// Parse the commandline into a `Command` to execute.
pub fn parse() -> Command {
    match try_parse_from(env::args()) {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache-dist: {some_other_err}");
                for source_err in some_other_err.chain().skip(1) {
                    println!("sccache-dist: caused by: {source_err}");
                }
                std::process::exit(1);
            }
        },
    }
}

fn flag_infer_long(name: &'static str) -> Arg<'static> {
    Arg::new(name).long(name)
}

fn get_clap_command() -> ClapCommand<'static> {
    let syslog = flag_infer_long("syslog")
        .help("Log to the syslog with LEVEL")
        .value_name("LEVEL")
        .possible_values(LogLevel::values().iter().map(LogLevel::as_str));
    let config_with_help_message =
        |help: &'static str| flag_infer_long("config").help(help).value_name("PATH");

    ClapCommand::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .subcommand(
            ClapCommand::new("auth")
                .subcommand_required(true)
                .subcommand(ClapCommand::new("generate-jwt-hs256-key"))
                .subcommand(
                    ClapCommand::new("generate-jwt-hs256-server-token")
                        .args(&[
                            flag_infer_long("server")
                                .help("Generate a key for the specified server")
                                .value_name("SERVER_ADDR")
                                .required(true),
                            flag_infer_long("secret-key")
                                .help("Use specified key to create the token")
                                .value_name("KEY"),
                            config_with_help_message(
                                "Use the key from the scheduler config file at PATH",
                            ),
                        ])
                        .group(
                            ArgGroup::new("key_source_mutual_exclusion")
                                .args(&["config", "secret-key"])
                                .required(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("generate-shared-token").arg(
                        flag_infer_long("bits")
                            .help("Use the specified number of bits of randomness")
                            .value_name("BITS")
                            .default_value("256")
                            .validator(TokenLength::from_bits),
                    ),
                ),
        )
        .subcommand(ClapCommand::new("scheduler").args(&[
            config_with_help_message("Use the scheduler config file at PATH").required(true),
            syslog.clone(),
        ]))
        .subcommand(ClapCommand::new("server").args(&[
            config_with_help_message("Use the server config file at PATH").required(true),
            syslog,
        ]))
}

fn check_init_syslog(name: &str, log_level: LogLevel) {
    let level = log::LevelFilter::from(log_level);
    drop(syslog::init(Facility::LOG_DAEMON, level, Some(name)));
}

fn try_parse_from(
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
) -> anyhow::Result<Command> {
    let matches = get_clap_command().try_get_matches_from(args)?;

    Ok(match matches.subcommand() {
        Some(("auth", matches)) => Command::Auth(match matches.subcommand() {
            // Size based on https://briansmith.org/rustdoc/ring/hmac/fn.recommended_key_len.html
            Some(("generate-jwt-hs256-key", _)) => AuthSubcommand::Base64 { num_bytes: 256 / 8 },
            Some(("generate-jwt-hs256-server-token", matches)) => {
                let server_addr: SocketAddr = matches.value_of_t("server")?;
                let server_id = ServerId::new(server_addr);

                let secret_key = if matches.is_present("config") {
                    let config_path: PathBuf = matches.value_of_t("config")?;
                    if let Some(config) = config::scheduler::from_path(&config_path)? {
                        match config.server_auth {
                            config::scheduler::ServerAuth::JwtHS256 { secret_key } => secret_key,
                            config::scheduler::ServerAuth::Insecure
                            | config::scheduler::ServerAuth::Token { .. } => {
                                bail!("Scheduler not configured with JWT HS256")
                            }
                        }
                    } else {
                        bail!("Could not load config")
                    }
                } else {
                    matches.value_of_t("secret-key")?
                };

                AuthSubcommand::JwtHS256ServerToken {
                    secret_key,
                    server_id,
                }
            }
            Some(("generate-shared-token", matches)) => {
                let token_bits = TokenLength::from_bits(
                    matches.value_of("bits").expect("clap provides default"),
                )
                .expect("clap uses `from_bits` as a validator");

                AuthSubcommand::Base64 {
                    num_bytes: token_bits.as_bytes(),
                }
            }
            _ => unreachable!("Subcommand is enforced by clap"),
        }),
        Some(("scheduler", matches)) => {
            if matches.is_present("syslog") {
                let log_level: LogLevel = matches.value_of_t("syslog")?;
                check_init_syslog("sccache-scheduler", log_level);
            }

            let config_path: PathBuf = matches.value_of_t("config")?;
            if let Some(config) = config::scheduler::from_path(&config_path)? {
                Command::Scheduler(config)
            } else {
                bail!("Could not load config")
            }
        }
        Some(("server", matches)) => {
            if matches.is_present("syslog") {
                let log_level: LogLevel = matches.value_of_t("syslog")?;
                check_init_syslog("sccache-buildserver", log_level);
            }

            let config_path: PathBuf = matches.value_of_t("config")?;
            if let Some(config) = config::server::from_path(&config_path)? {
                Command::Server(config)
            } else {
                bail!("Could not load config")
            }
        }
        _ => unreachable!("Subcommand is enforced by clap"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "sccache-dist";

    fn auth_generate_shared_tokens_bits(bit_val: &'static str) -> Vec<&'static str> {
        vec![EXE, "auth", "generate-shared-token", "--bits", bit_val]
    }

    fn auth_generate_jwt_hs256_server_token(subcommand_args: &[&'static str]) -> Vec<&'static str> {
        let mut args = vec![EXE, "auth", "generate-jwt-hs256-server-token"];
        args.extend_from_slice(subcommand_args);
        args
    }

    #[test]
    fn debug_assert() {
        get_clap_command().debug_assert()
    }

    #[test]
    fn missing_required_subcommands_fails() {
        let args_sets = &[vec![EXE], vec![EXE, "auth"]];

        for args in args_sets {
            assert!(try_parse_from(args).is_err());
        }
    }

    #[test]
    fn invalid_token_bits_fails() {
        let invalid_vals = vec!["not_a_num", "58", "8000", "70"];

        for invalid_val in invalid_vals {
            let args = auth_generate_shared_tokens_bits(invalid_val);
            assert!(try_parse_from(args).is_err());
        }
    }

    #[test]
    fn auth_generate_server_token_needs_key_source() {
        let server_args = &["--server", "127.0.0.1:4321"];

        let no_key = auth_generate_jwt_hs256_server_token(server_args);
        assert!(try_parse_from(no_key).is_err());

        let mut too_many_keys = auth_generate_jwt_hs256_server_token(server_args);
        too_many_keys.extend_from_slice(&["--secret-key", "secret", "--config", "some/path.toml"]);
        assert!(try_parse_from(too_many_keys).is_err());
    }

    // This is all just to work around `PartialEq` not being on some of the values used in variants
    // for `Command` yet
    fn assert_args_parse_to_auth(args: Vec<&'static str>, ideal_auth: AuthSubcommand) {
        match try_parse_from(&args) {
            Ok(Command::Auth(auth)) => assert_eq!(auth, ideal_auth),
            _ => panic!("Bad parsing for: {:#?}", args),
        }
    }

    #[test]
    fn auth_generate_jwt_hs256_key_good() {
        let args = vec![EXE, "auth", "generate-jwt-hs256-key"];

        assert_args_parse_to_auth(args, AuthSubcommand::Base64 { num_bytes: 256 / 8 });
    }

    #[test]
    fn auth_generate_jwt_hs256_server_token_good() {
        let base = auth_generate_jwt_hs256_server_token(&["--server", "127.0.0.1:4321"]);
        let server_socket: SocketAddr = "127.0.0.1:4321".parse().unwrap();
        let server_id = ServerId::new(server_socket);

        let mut secret_key = base.clone();
        secret_key.extend_from_slice(&["--secret-key", "very secret"]);
        assert_args_parse_to_auth(
            secret_key,
            AuthSubcommand::JwtHS256ServerToken {
                server_id,
                secret_key: "very secret".to_owned(),
            },
        );

        // TODO: need some sample config to be used here
        // let mut config = base;
        // config.extend_from_slice(&["--config", "some/path.toml"]);
    }

    #[test]
    fn auth_generate_shared_token_good() {
        let raw_to_expected_bit_vals = &[
            ("64", 64 / 8),
            ("128", 128 / 8),
            ("136", 136 / 8),
            ("4000", 4_000 / 8),
        ];

        for (raw, expected) in raw_to_expected_bit_vals {
            let args = auth_generate_shared_tokens_bits(raw);
            assert_args_parse_to_auth(
                args,
                AuthSubcommand::Base64 {
                    num_bytes: *expected,
                },
            );
        }
    }

    // TODO: add tests for with sample config file
    // #[test]
    // fn scheduler_good() {
    //     todo!()
    // }

    // TODO: add tests for with sample config file
    // #[test]
    // fn server_good() {
    //     todo!()
    // }
}
