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

use ::client::{
    connect_to_server,
};
use ::commands::{
    do_compile,
    request_shutdown,
    request_stats,
};
use mio::Sender;
use ::mock_command::*;
use ::server::{
    ServerMessage,
    create_server,
    run_server,
};
use std::thread;

fn run_server_thread() -> (u16, Sender<ServerMessage>, thread::JoinHandle<()>) {
    // Create a server, run it on a background thread.
    let (server, event_loop) = create_server(0).unwrap();
    assert!(server.port() > 0);
    let port = server.port();
    let sender = event_loop.channel();
    (port, sender, thread::spawn(move || {
        run_server(server, event_loop).unwrap()
    }))
}

#[test]
fn test_server_shutdown() {
    let (port, _, child) = run_server_thread();
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    // Ask it to shut down
    request_shutdown(conn).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_stats() {
    let (port, sender, child) = run_server_thread();
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    // Ask it for stats.
    let stats = request_stats(conn).unwrap();
    assert!(stats.get_stats().len() > 0);
    // Now signal it to shut down.
    sender.send(ServerMessage::Shutdown).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_unhandled_compile() {
    let (port, sender, child) = run_server_thread();
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    let mut creator = MockCommandCreator::new();
    creator.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
    // Ask the server to compile something.
    //TODO: MockCommand should validate these!
    let cmdline = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
    let cwd = "/foo/bar".to_owned();
    assert_eq!(0, do_compile(&mut creator, conn, cmdline, cwd).unwrap());
    // Make sure we ran a mock process.
    assert_eq!(0, creator.children.len());
    // Shut down the server.
    sender.send(ServerMessage::Shutdown).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}
