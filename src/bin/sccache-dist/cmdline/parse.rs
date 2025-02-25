// Copyright 2022 <LovecraftianHorror@pm.me>
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

use std::{
    ffi::OsString,
    fmt,
    io::BufWriter,
    net::{SocketAddr, TcpStream, UdpSocket},
    path::PathBuf,
    process,
};

use anyhow::{anyhow, bail};
use clap::{Arg, ArgGroup, Command as ClapCommand};
use sccache::{config, dist::ServerId};
use syslog::{unix, BasicLogger, Formatter3164, LoggerBackend};
use syslog::{Facility, Logger};

use crate::cmdline::{AuthSubcommand, Command};
#[derive(Debug, Clone)]
struct TokenLength(usize);

impl TokenLength {
    fn as_bytes(&self) -> usize {
        self.0 / 8
    }

    fn from_bits(bits: &str) -> anyhow::Result<Self> {
        let bits: usize = bits.parse()?;

        if bits & 0x7 != 0 {
            Err(anyhow!("Number of bits must be divisible by 8"))
        } else if bits < 64 {
            Err(anyhow!(
                "Number of bits must be greater than or equal to 64"
            ))
        } else if bits > 4_096 {
            Err(anyhow!("Number of bits must be less than or equal to 4096"))
        } else {
            Ok(Self(bits))
        }
    }
}

impl fmt::Display for TokenLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn flag_infer_long(name: &'static str) -> Arg {
    Arg::new(name).long(name)
}

fn get_clap_command() -> ClapCommand {
    let syslog = flag_infer_long("syslog")
        .help("Log to the syslog with LEVEL")
        .value_name("LEVEL");
    let config_with_help_message = |help: &'static str| {
        flag_infer_long("config")
            .help(help)
            .value_name("PATH")
            .value_parser(clap::value_parser!(PathBuf))
    };

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
                                .value_parser(clap::value_parser!(SocketAddr))
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
                                .args(["config", "secret-key"])
                                .required(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("generate-shared-token").arg(
                        flag_infer_long("bits")
                            .help("Use the specified number of bits of randomness")
                            .value_name("BITS")
                            .default_value("256")
                            .value_parser(TokenLength::from_bits),
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

fn check_init_syslog(name: &str, log_filter: &str) {
    let facility = Facility::LOG_DAEMON;
    let process = name.to_string();
    let pid = process::id();
    let mut formatter = Formatter3164 {
        facility,
        hostname: None,
        process,
        pid,
    };

    let backend = if let Ok(logger) = unix(formatter.clone()) {
        logger.backend
    } else {
        formatter.hostname = Some(hostname::get().unwrap().to_string_lossy().to_string());
        if let Ok(tcp_stream) = TcpStream::connect(("127.0.0.1", 601)) {
            LoggerBackend::Tcp(BufWriter::new(tcp_stream))
        } else {
            let udp_addr = "127.0.0.1:514".parse().unwrap();
            let udp_stream = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
            LoggerBackend::Udp(udp_stream, udp_addr)
        }
    };

    let mut builder = env_filter::Builder::new();
    builder.parse(log_filter);
    let filter = builder.build();
    log::set_max_level(filter.filter());

    let logger =
        env_filter::FilteredLog::new(BasicLogger::new(Logger { formatter, backend }), filter);
    drop(log::set_boxed_logger(Box::new(logger)));
}

/// Parse commandline `args` into a `Result<Command>` to execute.
pub fn try_parse_from(
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
) -> anyhow::Result<Command> {
    let matches = get_clap_command().try_get_matches_from(args)?;

    Ok(match matches.subcommand() {
        Some(("auth", matches)) => Command::Auth(match matches.subcommand() {
            // Size based on https://briansmith.org/rustdoc/ring/hmac/fn.recommended_key_len.html
            Some(("generate-jwt-hs256-key", _)) => AuthSubcommand::Base64 { num_bytes: 256 / 8 },
            Some(("generate-jwt-hs256-server-token", matches)) => {
                let server_addr = matches
                    .get_one("server")
                    .expect("`server` is required and it can be parsed to a `SocketAddr`");
                let server_id = ServerId::new(*server_addr);

                let secret_key = if matches.contains_id("config") {
                    let config_path = matches
                        .get_one::<PathBuf>("config")
                        .expect("`config` is required and it can be parsed to a `PathBuf`");
                    if let Some(config) = config::scheduler::from_path(config_path)? {
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
                    matches
                        .get_one::<String>("secret-key")
                        .expect("`secret-key` is required")
                        .to_string()
                };

                AuthSubcommand::JwtHS256ServerToken {
                    secret_key,
                    server_id,
                }
            }
            Some(("generate-shared-token", matches)) => {
                let token_bits = matches
                    .get_one::<TokenLength>("bits")
                    .expect("clap provides default");

                AuthSubcommand::Base64 {
                    num_bytes: token_bits.as_bytes(),
                }
            }
            _ => unreachable!("Subcommand is enforced by clap"),
        }),
        Some(("scheduler", matches)) => {
            if matches.contains_id("syslog") {
                let log_level = matches
                    .get_one::<String>("syslog")
                    .expect("`syslog` is required");
                check_init_syslog("sccache-scheduler", log_level.as_str());
            }

            let config_path = matches
                .get_one::<PathBuf>("config")
                .expect("`config` is required");
            if let Some(config) = config::scheduler::from_path(config_path)? {
                Command::Scheduler(config)
            } else {
                bail!("Could not load config")
            }
        }
        Some(("server", matches)) => {
            if matches.contains_id("syslog") {
                let log_level = matches
                    .get_one::<String>("syslog")
                    .expect("`syslog` is required");
                check_init_syslog("sccache-buildserver", log_level.as_str());
            }

            let config_path = matches
                .get_one::<PathBuf>("config")
                .expect("`config` is required");
            if let Some(config) = config::server::from_path(config_path)? {
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
}
