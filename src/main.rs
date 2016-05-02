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

extern crate clap;
extern crate env_logger;
#[macro_use] extern crate log;
extern crate libc;
extern crate mio;
extern crate protobuf;
extern crate retry;

mod client;
mod cmdline;
mod commands;
mod compiler;
mod mock_command;
mod protocol;
mod server;
#[cfg(test)]
mod test;

fn main() {
    env_logger::init().unwrap();
    std::process::exit(commands::run_command(cmdline::parse()));
}
