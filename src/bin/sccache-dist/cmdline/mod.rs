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

use sccache::{config, dist::ServerId};

mod parse;

pub use parse::try_parse_from;

#[derive(Debug)]
pub enum Command {
    Auth(AuthSubcommand),
    Scheduler(config::scheduler::Config),
    Server(config::server::Config),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthSubcommand {
    Base64 {
        num_bytes: usize,
    },
    JwtHS256ServerToken {
        secret_key: String,
        server_id: ServerId,
    },
}
