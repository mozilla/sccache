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
use env_logger;
use mio::Sender;
use ::mock_command::*;
use ::server::{
    ServerMessage,
    create_server,
    run_server,
};
use std::io::Cursor;
use std::sync::{Arc,Mutex,mpsc};
use std::thread;

/// Run a server on a background thread, and return a tuple of useful things.
///
/// * The port on which the server is listening.
/// * A `Sender` which can be used to send messages to the server.
///   (Most usefully, ServerMessage::Shutdown.)
/// * An `Arc`-and-`Mutex`-wrapped `MockCommandCreator` which the server will
///   use for all process creation.
/// * The `JoinHandle` for the server thread.
fn run_server_thread() -> (u16, Sender<ServerMessage>, Arc<Mutex<MockCommandCreator>>, thread::JoinHandle<()>) {
    // Create a server on a background thread, get some useful bits from it.
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (server, event_loop) = create_server::<Arc<Mutex<MockCommandCreator>>>(0).unwrap();
        assert!(server.port() > 0);
        let port = server.port();
        let sender = event_loop.channel();
        let creator = server.command_creator();
        tx.send((port, sender, creator)).unwrap();
        run_server(server, event_loop).unwrap()
    });
    let (port, sender, creator) = rx.recv().unwrap();
    (port, sender, creator, handle)
}

#[test]
fn test_server_shutdown() {
    let (port, _, _, child) = run_server_thread();
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    // Ask it to shut down
    request_shutdown(conn).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_stats() {
    let (port, sender, _, child) = run_server_thread();
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
    let (port, sender, server_creator, child) = run_server_thread();
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    {
        let mut c = server_creator.lock().unwrap();
        // The server will check the compiler, so pretend to be an unsupported
        // compiler.
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
    }
    // Ask the server to compile something.
    //TODO: MockCommand should validate these!
    let cmdline = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
    let cwd = "/foo/bar".to_owned();
    let client_creator = Arc::new(Mutex::new(MockCommandCreator::new()));
    {
        let mut c = client_creator.lock().unwrap();
        // Actual client output.
        //TODO: do_compile should take stdout/stderr handles!
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "some stdout", "some stderr")));
    }
    let mut stdout = Cursor::new(Vec::new());
    let mut stderr = Cursor::new(Vec::new());
    let path = None;
    assert_eq!(0, do_compile(client_creator.clone(), conn, cmdline, cwd, path, &mut stdout, &mut stderr).unwrap());
    // Make sure we ran the mock processes.
    assert_eq!(0, server_creator.lock().unwrap().children.len());
    assert_eq!(0, client_creator.lock().unwrap().children.len());
    //TODO: make local process execution capture output so we can check
    // stdout + stderr
    // Shut down the server.
    sender.send(ServerMessage::Shutdown).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_compile() {
    env_logger::init().unwrap();
    let (port, sender, server_creator, child) = run_server_thread();
    // Connect to the server.
    const STDOUT : &'static str = "some stdout";
    const STDERR : &'static str = "some stderr";
    let conn = connect_to_server(port).unwrap();
    {
        let mut c = server_creator.lock().unwrap();
        // The server will check the compiler. Pretend it's GCC.
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "gcc", "")));
        // Actual compiler invocation.
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), STDOUT, STDERR)));
    }
    // Ask the server to compile something.
    //TODO: MockCommand should validate these!
    let cmdline = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
    let cwd = "/foo/bar".to_owned();
    // This creator shouldn't create any processes. It will assert if
    // it tries to.
    let client_creator = Arc::new(Mutex::new(MockCommandCreator::new()));
    let mut stdout = Cursor::new(Vec::new());
    let mut stderr = Cursor::new(Vec::new());
    let path = None;
    assert_eq!(0, do_compile(client_creator.clone(), conn, cmdline, cwd, path, &mut stdout, &mut stderr).unwrap());
    // Make sure we ran the mock processes.
    assert_eq!(0, server_creator.lock().unwrap().children.len());
    assert_eq!(STDOUT.as_bytes(), &stdout.into_inner()[..]);
    assert_eq!(STDERR.as_bytes(), &stderr.into_inner()[..]);
    // Shut down the server.
    sender.send(ServerMessage::Shutdown).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}
