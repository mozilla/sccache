use sccache::{config, dist::ServerId};

mod parse;

pub use parse::try_parse_from;

#[derive(Debug)]
pub enum Command {
    Auth(AuthSubcommand),
    Scheduler(config::scheduler::Config),
    Server(config::server::Config),
}

#[derive(Debug, PartialEq)]
pub enum AuthSubcommand {
    Base64 {
        num_bytes: usize,
    },
    JwtHS256ServerToken {
        secret_key: String,
        server_id: ServerId,
    },
}
