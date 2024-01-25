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

use crate::cache::disk::DiskCache;
use crate::cache::{CacheMode, PreprocessorCacheModeConfig};
use crate::client::connect_to_server;
use crate::commands::{do_compile, request_shutdown, request_stats};
use crate::jobserver::Client;
use crate::mock_command::*;
use crate::server::{DistClientContainer, SccacheServer, ServerMessage};
use crate::test::utils::*;
use fs::File;
use fs_err as fs;
use futures::channel::oneshot::{self, Sender};
#[cfg(not(target_os = "macos"))]
use serial_test::serial;
use std::io::{Cursor, Write};
#[cfg(not(target_os = "macos"))]
use std::net::TcpListener;
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::u64;
use tokio::runtime::Runtime;

/// Options for running the server in tests.
#[derive(Default)]
struct ServerOptions {
    /// The server's idle shutdown timeout.
    idle_timeout: Option<u64>,
    /// The maximum size of the disk cache.
    cache_size: Option<u64>,
}

/// Run a server on a background thread, and return a tuple of useful things.
///
/// * The port on which the server is listening.
/// * A `Sender` which can be used to send messages to the server.
///   (Most usefully, ServerMessage::Shutdown.)
/// * An `Arc`-and-`Mutex`-wrapped `MockCommandCreator` which the server will
///   use for all process creation.
/// * The `JoinHandle` for the server thread.
fn run_server_thread<T>(
    cache_dir: &Path,
    options: T,
) -> (
    u16,
    Sender<ServerMessage>,
    Arc<Mutex<MockCommandCreator>>,
    thread::JoinHandle<()>,
)
where
    T: Into<Option<ServerOptions>> + Send + 'static,
{
    let options = options.into();
    let cache_dir = cache_dir.to_path_buf();

    let cache_size = options
        .as_ref()
        .and_then(|o| o.cache_size.as_ref())
        .copied()
        .unwrap_or(u64::MAX);
    // Create a server on a background thread, get some useful bits from it.
    let (tx, rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let handle = thread::spawn(move || {
        let runtime = Runtime::new().unwrap();
        let dist_client = DistClientContainer::new_disabled();
        let storage = Arc::new(DiskCache::new(
            &cache_dir,
            cache_size,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
        ));

        let client = unsafe { Client::new() };
        let srv = SccacheServer::new(0, runtime, client, dist_client, storage).unwrap();
        let mut srv: SccacheServer<Arc<Mutex<MockCommandCreator>>> = srv;
        assert!(srv.port() > 0);
        if let Some(options) = options {
            if let Some(timeout) = options.idle_timeout {
                srv.set_idle_timeout(Duration::from_millis(timeout));
            }
        }
        let port = srv.port();
        let creator = srv.command_creator().clone();
        tx.send((port, creator)).unwrap();
        srv.run(shutdown_rx).unwrap();
    });
    let (port, creator) = rx.recv().unwrap();
    (port, shutdown_tx, creator, handle)
}

#[test]
fn test_server_shutdown() {
    let f = TestFixture::new();
    let (port, _sender, _storage, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    // Ask it to shut down
    request_shutdown(conn).unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

/// The server will shutdown when requested when the idle timeout is disabled.
#[test]
fn test_server_shutdown_no_idle() {
    let f = TestFixture::new();
    // Set a ridiculously low idle timeout.
    let (port, _sender, _storage, child) = run_server_thread(
        f.tempdir.path(),
        ServerOptions {
            idle_timeout: Some(0),
            ..Default::default()
        },
    );

    let conn = connect_to_server(port).unwrap();
    request_shutdown(conn).unwrap();
    child.join().unwrap();
}

#[test]
fn test_server_idle_timeout() {
    let f = TestFixture::new();
    // Set a ridiculously low idle timeout.
    let (_port, _sender, _storage, child) = run_server_thread(
        f.tempdir.path(),
        ServerOptions {
            idle_timeout: Some(1),
            ..Default::default()
        },
    );
    // Don't connect to it.
    // Ensure that it shuts down.
    // It would be nice to have an explicit timeout here so we don't hang
    // if something breaks...
    child.join().unwrap();
}

#[test]
fn test_server_stats() {
    let f = TestFixture::new();
    let (port, sender, _storage, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    // Ask it for stats.
    let info = request_stats(conn).unwrap();
    assert_eq!(0, info.stats.compile_requests);
    // Include sccache ver (cli) to validate.
    assert_eq!(env!("CARGO_PKG_VERSION"), info.version);
    // Now signal it to shut down.
    sender.send(ServerMessage::Shutdown).ok().unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_unsupported_compiler() {
    let f = TestFixture::new();
    let (port, sender, server_creator, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    let conn = connect_to_server(port).unwrap();
    {
        let mut c = server_creator.lock().unwrap();
        // fail rust driver check
        c.next_command_spawns(Ok(MockChild::new(exit_status(1), "hello", "error")));
        // The server will check the compiler, so pretend to be an unsupported
        // compiler.
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "hello", "error")));
    }
    // Ask the server to compile something.
    //TODO: MockCommand should validate these!
    let exe = &f.bins[0];
    let cmdline = vec!["-c".into(), "file.c".into(), "-o".into(), "file.o".into()];
    let cwd = f.tempdir.path();
    // This creator shouldn't create any processes. It will assert if
    // it tries to.
    let client_creator = new_creator();
    let mut stdout = Cursor::new(Vec::new());
    let mut stderr = Cursor::new(Vec::new());
    let path = Some(f.paths);
    let mut runtime = Runtime::new().unwrap();
    let res = do_compile(
        client_creator,
        &mut runtime,
        conn,
        exe,
        cmdline,
        cwd,
        path,
        vec![],
        &mut stdout,
        &mut stderr,
    );
    match res {
        Ok(_) => panic!("do_compile should have failed!"),
        Err(e) => assert_eq!("Compiler not supported: \"error\"", e.to_string()),
    }
    // Make sure we ran the mock processes.
    assert_eq!(0, server_creator.lock().unwrap().children.len());
    // Shut down the server.
    sender.send(ServerMessage::Shutdown).ok().unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_compile() {
    let _ = env_logger::try_init();
    let f = TestFixture::new();
    let gcc = f.mk_bin("gcc").unwrap();
    let (port, sender, server_creator, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    const PREPROCESSOR_STDOUT: &[u8] = b"preprocessor stdout";
    const PREPROCESSOR_STDERR: &[u8] = b"preprocessor stderr";
    const STDOUT: &[u8] = b"some stdout";
    const STDERR: &[u8] = b"some stderr";
    let conn = connect_to_server(port).unwrap();
    // Write a dummy input file so the preprocessor cache mode can work
    std::fs::write(f.tempdir.path().join("file.c"), "whatever").unwrap();
    {
        let mut c = server_creator.lock().unwrap();
        // The server will check the compiler. Pretend it's GCC.
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")));
        // Preprocessor invocation.
        c.next_command_spawns(Ok(MockChild::new(
            exit_status(0),
            PREPROCESSOR_STDOUT,
            PREPROCESSOR_STDERR,
        )));
        // Compiler invocation.
        //TODO: wire up a way to get data written to stdin.
        let obj = f.tempdir.path().join("file.o");
        c.next_command_calls(move |_| {
            // Pretend to compile something.
            let mut f = File::create(&obj)?;
            f.write_all(b"file contents")?;
            Ok(MockChild::new(exit_status(0), STDOUT, STDERR))
        });
    }
    // Ask the server to compile something.
    //TODO: MockCommand should validate these!
    let exe = &gcc;
    let cmdline = vec!["-c".into(), "file.c".into(), "-o".into(), "file.o".into()];
    let cwd = f.tempdir.path();
    // This creator shouldn't create any processes. It will assert if
    // it tries to.
    let client_creator = new_creator();
    let mut stdout = Cursor::new(Vec::new());
    let mut stderr = Cursor::new(Vec::new());
    let path = Some(f.paths);
    let mut runtime = Runtime::new().unwrap();
    assert_eq!(
        0,
        do_compile(
            client_creator,
            &mut runtime,
            conn,
            exe,
            cmdline,
            cwd,
            path,
            vec![],
            &mut stdout,
            &mut stderr
        )
        .unwrap()
    );
    // Make sure we ran the mock processes.
    assert_eq!(0, server_creator.lock().unwrap().children.len());
    assert_eq!(STDOUT, stdout.into_inner().as_slice());
    assert_eq!(STDERR, stderr.into_inner().as_slice());
    // Shut down the server.
    sender.send(ServerMessage::Shutdown).ok().unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
#[serial]
// test fails intermittently on macos:
// https://github.com/mozilla/sccache/issues/234
#[cfg(not(target_os = "macos"))]
fn test_server_port_in_use() {
    // Bind an arbitrary free port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sccache = find_sccache_binary();
    let output = Command::new(sccache)
        .arg("--start-server")
        .env(
            "SCCACHE_SERVER_PORT",
            listener.local_addr().unwrap().port().to_string(),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    let s = String::from_utf8_lossy(&output.stderr);
    const MSG: &str = "Server startup failed:";
    assert!(
        s.contains(MSG),
        "Output did not contain '{}':\n========\n{}\n========",
        MSG,
        s
    );
}
