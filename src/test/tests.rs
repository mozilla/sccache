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

use crate::cache::CacheMode;
use crate::cache::disk::DiskCache;
use crate::client::connect_to_server;
use crate::commands::{do_compile, request_shutdown, request_stats};
use crate::config::PreprocessorCacheModeConfig;
use crate::jobserver::Client;
use crate::mock_command::*;
use crate::server::{DistClientContainer, SccacheServer};
use crate::test::utils::*;
use fs::File;
use fs_err as fs;
use futures::channel::oneshot::{self, Sender};
use std::io::{Cursor, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
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
///   to request an explicit shutdown.
/// * An `Arc`-and-`Mutex`-wrapped `MockCommandCreator` which the server will
///   use for all process creation.
/// * The `JoinHandle` for the server thread.
fn run_server_thread<T>(
    cache_dir: &Path,
    options: T,
) -> (
    crate::net::SocketAddr,
    Sender<()>,
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
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = thread::spawn(move || {
        let runtime = Runtime::new().unwrap();
        let dist_client = DistClientContainer::new_disabled();
        let storage = Arc::new(DiskCache::new(
            &cache_dir,
            cache_size,
            runtime.handle(),
            PreprocessorCacheModeConfig::default(),
            CacheMode::ReadWrite,
            vec![],
        ));

        let client = Client::new();
        let srv = SccacheServer::new(0, runtime, client, dist_client, storage).unwrap();
        let mut srv: SccacheServer<_, Arc<Mutex<MockCommandCreator>>> = srv;
        let addr = srv.local_addr().unwrap();
        assert!(matches!(addr, crate::net::SocketAddr::Net(a) if a.port() > 0));
        if let Some(options) = options
            && let Some(timeout) = options.idle_timeout
        {
            srv.set_idle_timeout(Duration::from_millis(timeout));
        }
        let creator = srv.command_creator().clone();
        tx.send((addr, creator)).unwrap();
        srv.run(shutdown_rx).unwrap();
    });
    let (addr, creator) = rx.recv().unwrap();
    (addr, shutdown_tx, creator, handle)
}

#[test]
fn test_server_shutdown() {
    let f = TestFixture::new();
    let (addr, _sender, _storage, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    let conn = connect_to_server(&addr).unwrap();
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
    let (addr, _sender, _storage, child) = run_server_thread(
        f.tempdir.path(),
        ServerOptions {
            idle_timeout: Some(0),
            ..Default::default()
        },
    );

    let conn = connect_to_server(&addr).unwrap();
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
    let (addr, sender, _storage, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    let conn = connect_to_server(&addr).unwrap();
    // Ask it for stats.
    let info = request_stats(conn).unwrap();
    assert_eq!(0, info.stats.compile_requests);
    // Include sccache ver (cli) to validate.
    assert_eq!(env!("CARGO_PKG_VERSION"), info.version);
    // Now signal it to shut down.
    sender.send(()).ok().unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_unsupported_compiler() {
    let f = TestFixture::new();
    let (addr, sender, server_creator, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    let conn = connect_to_server(&addr).unwrap();
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
    sender.send(()).ok().unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

#[test]
fn test_server_compile() {
    let _ = env_logger::try_init();
    let f = TestFixture::new();
    let gcc = f.mk_bin("gcc").unwrap();
    let (addr, sender, server_creator, child) = run_server_thread(f.tempdir.path(), None);
    // Connect to the server.
    const PREPROCESSOR_STDOUT: &[u8] = b"preprocessor stdout";
    const PREPROCESSOR_STDERR: &[u8] = b"preprocessor stderr";
    const STDOUT: &[u8] = b"some stdout";
    const STDERR: &[u8] = b"some stderr";
    let conn = connect_to_server(&addr).unwrap();
    // Write a dummy input file so the preprocessor cache mode can work
    std::fs::write(f.tempdir.path().join("file.c"), "whatever").unwrap();
    {
        let mut c = server_creator.lock().unwrap();
        // The server will check the compiler. Pretend it's GCC.
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "compiler_id=gcc", "")));
        // The assembler version and path probes.
        c.next_command_spawns(Ok(MockChild::new(
            exit_status(0),
            "GNU assembler (GNU Binutils) 2.42",
            "",
        )));
        c.next_command_spawns(Ok(MockChild::new(exit_status(0), "as", "")));
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
    sender.send(()).ok().unwrap();
    // Ensure that it shuts down.
    child.join().unwrap();
}

/// A [`Write`] sink shared with the fake server.
///
/// This is needed so it can observe how much the client has written
/// at a given point in the protocol exchange.
#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const RMETA_NOTIFICATION: &[u8] = b"{\"artifact\":\"/t/libdep.rmeta\",\"emit\":\"metadata\"}\n";
const OTHER_STDERR: &[u8] = b"{\"artifact\":\"/t/libdep.rlib\",\"emit\":\"link\"}\n";

/// Accepts one connection as a fake daemon.
///
/// The fake one replies to a compile request until a `.rmeta` notification comes.
/// It leaves it for caller to continue working on it.
fn fake_daemon_until_rmeta_notification(listener: std::net::TcpListener) -> std::net::TcpStream {
    use crate::protocol::{CompileResponse, Request, Response};
    use crate::util::write_length_prefixed_bincode;
    use byteorder::{BigEndian, ByteOrder};
    use std::io::Read;

    let (mut sock, _) = listener.accept().unwrap();
    let mut len = [0; 4];
    sock.read_exact(&mut len).unwrap();
    let mut req = vec![0; BigEndian::read_u32(&len) as usize];
    sock.read_exact(&mut req).unwrap();
    assert!(matches!(
        bincode::deserialize::<Request>(&req).unwrap(),
        Request::Compile(_)
    ));

    write_length_prefixed_bincode(
        &mut sock,
        Response::Compile(CompileResponse::CompileStarted),
    )
    .unwrap();
    write_length_prefixed_bincode(
        &mut sock,
        Response::ArtifactNotification(RMETA_NOTIFICATION.to_vec()),
    )
    .unwrap();
    sock
}

/// Runs a client compiling `dep` against daemon at `addr`.
fn compile_dep(
    creator: Arc<Mutex<MockCommandCreator>>,
    f: &TestFixture,
    addr: &crate::net::SocketAddr,
    stderr: &SharedWriter,
) -> crate::errors::Result<i32> {
    let rustc = f.mk_bin("rustc").unwrap();
    let conn = connect_to_server(addr).unwrap();
    let cmdline = vec![
        "--crate-name".into(),
        "dep".into(),
        "src/lib.rs".into(),
        "--emit=dep-info,metadata,link".into(),
    ];
    let mut stdout = Cursor::new(Vec::new());
    let mut runtime = Runtime::new().unwrap();
    do_compile(
        creator,
        &mut runtime,
        conn,
        &rustc,
        cmdline,
        f.tempdir.path(),
        Some(f.paths.clone()),
        vec![],
        &mut stdout,
        &mut stderr.clone(),
    )
}

#[test]
fn test_cli_rmeta_notification_delivery_from_daemon() {
    use crate::compiler::ColorMode;
    use crate::protocol::{CompileFinished, Response};
    use crate::util::write_length_prefixed_bincode;

    let _ = env_logger::try_init();
    let f = TestFixture::new();
    let stderr = SharedWriter::default();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = crate::net::SocketAddr::Net(listener.local_addr().unwrap());
    let server_stderr = stderr.clone();
    let server = thread::spawn(move || -> Vec<u8> {
        let mut sock = fake_daemon_until_rmeta_notification(listener);

        // This waits until the client writes what it has at this point,
        // to ensure stderr gets the notification before we proceed to write more.
        sock.set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while server_stderr.0.lock().unwrap().is_empty() {
            match sock.peek(&mut [0]) {
                Ok(0) => break,
                Ok(_) => panic!("unexpected data from client"),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(_) => assert!(
                    std::time::Instant::now() < deadline,
                    "client neither wrote nor hung up"
                ),
            }
        }

        let written_before_finished = server_stderr.0.lock().unwrap().clone();

        // The client may have given up on us by now.
        // The stderr is rustc's as-is, so it carries the notification too;
        // the client is expected to drop that copy.
        let _ = write_length_prefixed_bincode(
            &mut sock,
            Response::CompileFinished(CompileFinished {
                retcode: Some(0),
                signal: None,
                stdout: vec![],
                stderr: [RMETA_NOTIFICATION, OTHER_STDERR].concat(),
                color_mode: ColorMode::Off,
            }),
        );
        written_before_finished
    });

    let retcode = compile_dep(new_creator(), &f, &addr, &stderr).unwrap();
    let written_before_finished = server.join().unwrap();

    assert_eq!(0, retcode);
    assert_eq!(
        RMETA_NOTIFICATION,
        written_before_finished.as_slice(),
        "stderr written before CompileFinished"
    );
    // The daemon leaves rustc's stderr intact.
    // Client will dedup stderr if already forwarded.
    assert_eq!(
        [RMETA_NOTIFICATION, OTHER_STDERR].concat(),
        *stderr.0.lock().unwrap(),
        "stderr written in total"
    );
}

/// This makes sure that if the daemon dies between the rmeta notification and codegen,
/// sccache falls back to a normal compilation.
#[test]
fn test_cli_rmeta_notification_delivery_after_daemon_disconnect() {
    let _ = env_logger::try_init();
    let f = TestFixture::new();
    let stderr = SharedWriter::default();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = crate::net::SocketAddr::Net(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let sock = fake_daemon_until_rmeta_notification(listener);
        // The daemon dies mid-compile.
        drop(sock);
    });

    // The fallback compile.
    let creator = new_creator();
    next_command(
        &creator,
        Ok(MockChild::new(
            exit_status(0),
            "",
            [RMETA_NOTIFICATION, OTHER_STDERR].concat(),
        )),
    );

    let retcode = compile_dep(creator.clone(), &f, &addr, &stderr).unwrap();
    server.join().unwrap();

    assert_eq!(0, retcode);
    assert_eq!(
        0,
        creator.lock().unwrap().children.len(),
        "fallback rustc ran"
    );
    // The fallback rustc emitted the notification the daemon had already streamed,
    // and the client then dedups it.
    assert_eq!(
        [RMETA_NOTIFICATION, OTHER_STDERR].concat(),
        *stderr.0.lock().unwrap(),
        "stderr written in total"
    );
}
