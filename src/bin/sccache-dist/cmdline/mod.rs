use sccache::{config, dist::ServerId};

mod parse;

pub use parse::parse;

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
