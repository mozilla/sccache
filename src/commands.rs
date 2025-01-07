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

use crate::cache::storage_from_config;
use crate::client::{connect_to_server, connect_with_retry, ServerConnection};
use crate::cmdline::{Command, StatsFormat};
use crate::compiler::ColorMode;
use crate::config::{default_disk_cache_dir, Config};
use crate::jobserver::Client;
use crate::mock_command::{CommandChild, CommandCreatorSync, ProcessCommandCreator, RunCommand};
use crate::protocol::{Compile, CompileFinished, CompileResponse, Request, Response};
use crate::server::{self, DistInfo, ServerInfo, ServerStartup, ServerStats};
use crate::util::daemonize;
use byteorder::{BigEndian, ByteOrder};
use fs::{File, OpenOptions};
use fs_err as fs;
use log::Level::Trace;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process;
use std::time::Duration;
use strip_ansi_escapes::Writer;
use tokio::io::AsyncReadExt;
use tokio::runtime::Runtime;
use walkdir::WalkDir;
use which::which_in;

use crate::errors::*;

/// The default sccache server port.
pub const DEFAULT_PORT: u16 = 4226;

/// The number of milliseconds to wait for server startup.
const SERVER_STARTUP_TIMEOUT: Duration = Duration::from_millis(10000);

/// Get the port on which the server should listen.
fn get_addr() -> crate::net::SocketAddr {
    #[cfg(unix)]
    if let Ok(addr) = env::var("SCCACHE_SERVER_UDS") {
        if let Ok(uds) = crate::net::SocketAddr::parse_uds(&addr) {
            return uds;
        }
    }
    let port = env::var("SCCACHE_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    crate::net::SocketAddr::with_port(port)
}

/// Check if ignoring all response errors
fn ignore_all_server_io_errors() -> bool {
    match env::var("SCCACHE_IGNORE_SERVER_IO_ERROR") {
        Ok(ignore_server_error) => ignore_server_error == "1",
        Err(_) => false,
    }
}

async fn read_server_startup_status<R: AsyncReadExt + Unpin>(
    mut server: R,
) -> Result<ServerStartup> {
    // This is an async equivalent of ServerConnection::read_one_response
    let mut bytes = [0u8; 4];
    server.read_exact(&mut bytes[..]).await?;

    let len = BigEndian::read_u32(&bytes);
    let mut data = vec![0; len as usize];
    server.read_exact(data.as_mut_slice()).await?;

    Ok(bincode::deserialize(&data)?)
}

/// Re-execute the current executable as a background server, and wait
/// for it to start up.
#[cfg(not(windows))]
fn run_server_process(startup_timeout: Option<Duration>) -> Result<ServerStartup> {
    trace!("run_server_process");
    let tempdir = tempfile::Builder::new().prefix("sccache").tempdir()?;
    let socket_path = tempdir.path().join("sock");
    let runtime = Runtime::new()?;
    let exe_path = env::current_exe()?;
    let workdir = exe_path.parent().expect("executable path has no parent?!");

    // Spawn a blocking task to bind the Unix socket. Note that the socket
    // must be bound before spawning `_child` below to avoid a race between
    // the parent binding the socket and the child connecting to it.
    let listener = {
        let _guard = runtime.enter();
        tokio::net::UnixListener::bind(&socket_path)?
    };

    let _child = process::Command::new(&exe_path)
        .current_dir(workdir)
        .env("SCCACHE_START_SERVER", "1")
        .env("SCCACHE_STARTUP_NOTIFY", &socket_path)
        .env("RUST_BACKTRACE", "1")
        .spawn()?;

    let startup = async move {
        let (socket, _) = listener.accept().await?;

        read_server_startup_status(socket).await
    };

    let timeout = startup_timeout.unwrap_or(SERVER_STARTUP_TIMEOUT);
    runtime.block_on(async move {
        match tokio::time::timeout(timeout, startup).await {
            Ok(result) => result,
            Err(_elapsed) => Ok(ServerStartup::TimedOut),
        }
    })
}

#[cfg(not(windows))]
fn redirect_stderr(f: File) {
    use libc::dup2;
    use std::os::unix::io::IntoRawFd;
    // Ignore errors here.
    unsafe {
        dup2(f.into_raw_fd(), 2);
    }
}

#[cfg(windows)]
fn redirect_stderr(f: File) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};
    // Ignore errors here.
    unsafe {
        SetStdHandle(STD_ERROR_HANDLE, f.into_raw_handle() as _);
    }
}

/// Create the log file and return an error if cannot be created
fn create_error_log() -> Result<File> {
    trace!("Create the log file");
    let name = match env::var("SCCACHE_ERROR_LOG") {
        Ok(filename) if !filename.is_empty() => filename,
        _ => {
            bail!("Cannot read variable 'SCCACHE_ERROR_LOG'");
        }
    };

    let f = match OpenOptions::new().create(true).append(true).open(&name) {
        Ok(f) => f,
        Err(_) => {
            bail!("Cannot open/write log file '{}'", &name);
        }
    };
    Ok(f)
}

/// If `SCCACHE_ERROR_LOG` is set, redirect stderr to it.
fn redirect_error_log(f: File) -> Result<()> {
    debug!("redirecting stderr into {:?}", f);
    redirect_stderr(f);
    Ok(())
}

/// Re-execute the current executable as a background server.
#[cfg(windows)]
fn run_server_process(startup_timeout: Option<Duration>) -> Result<ServerStartup> {
    use futures::StreamExt;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use tokio::net::windows::named_pipe;
    use uuid::Uuid;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    trace!("run_server_process");

    // Create a mini event loop and register our named pipe server
    let runtime = Runtime::new()?;
    let pipe_name = &format!(r"\\.\pipe\{}", Uuid::new_v4().as_simple());

    // Spawn a server which should come back and connect to us
    let exe_path = env::current_exe()?;
    let mut exe = OsStr::new(&exe_path)
        .encode_wide()
        .chain(Some(0u16))
        .collect::<Vec<u16>>();
    let mut envp = {
        let mut v = vec![];
        let extra_vars = vec![
            (OsString::from("SCCACHE_START_SERVER"), OsString::from("1")),
            (
                OsString::from("SCCACHE_STARTUP_NOTIFY"),
                OsString::from(&pipe_name),
            ),
            (OsString::from("RUST_BACKTRACE"), OsString::from("1")),
        ];
        for (key, val) in env::vars_os().chain(extra_vars) {
            v.extend(
                key.encode_wide()
                    .chain(Some('=' as u16))
                    .chain(val.encode_wide())
                    .chain(Some(0)),
            );
        }
        v.push(0);
        v
    };
    let workdir = exe_path
        .parent()
        .expect("executable path has no parent?!")
        .as_os_str()
        .encode_wide()
        .chain(Some(0u16))
        .collect::<Vec<u16>>();

    // TODO: Expose `bInheritHandles` argument of `CreateProcessW` through the
    //       standard library's `Command` type and then use that instead.
    let mut pi = PROCESS_INFORMATION {
        hProcess: 0,
        hThread: 0,
        dwProcessId: 0,
        dwThreadId: 0,
    };
    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as _;
    if unsafe {
        CreateProcessW(
            exe.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            envp.as_mut_ptr().cast(),
            workdir.as_ptr(),
            &si,
            &mut pi,
        ) != 0
    } {
        unsafe {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    } else {
        return Err(io::Error::last_os_error().into());
    }

    fn create_named_pipe(
        pipe_name: &str,
        is_first: bool,
    ) -> io::Result<named_pipe::NamedPipeServer> {
        named_pipe::ServerOptions::new()
            .first_pipe_instance(is_first)
            .reject_remote_clients(true)
            .access_inbound(true)
            .access_outbound(true)
            .in_buffer_size(65536)
            .out_buffer_size(65536)
            .create(pipe_name)
    }

    let startup = async move {
        let pipe = create_named_pipe(pipe_name, true)?;

        let incoming = futures::stream::try_unfold(pipe, |listener| async move {
            listener.connect().await?;
            let new_listener = create_named_pipe(pipe_name, false)?;
            Ok::<_, io::Error>(Some((listener, new_listener)))
        });

        futures::pin_mut!(incoming);
        let socket = incoming.next().await;
        let socket = socket.unwrap(); // incoming() never returns None

        read_server_startup_status(socket?).await
    };

    let timeout = startup_timeout.unwrap_or(SERVER_STARTUP_TIMEOUT);
    runtime.block_on(async move {
        match tokio::time::timeout(timeout, startup).await {
            Ok(result) => result,
            Err(_elapsed) => Ok(ServerStartup::TimedOut),
        }
    })
}

/// Attempt to connect to an sccache server listening on `addr`, or start one if no server is running.
fn connect_or_start_server(
    addr: &crate::net::SocketAddr,
    startup_timeout: Option<Duration>,
) -> Result<ServerConnection> {
    trace!("connect_or_start_server({addr})");
    match connect_to_server(addr) {
        Ok(server) => Ok(server),
        Err(ref e)
            if (e.kind() == io::ErrorKind::ConnectionRefused
                || e.kind() == io::ErrorKind::TimedOut)
                || (e.kind() == io::ErrorKind::NotFound && addr.is_unix_path()) =>
        {
            // If the connection was refused we probably need to start
            // the server.
            match run_server_process(startup_timeout)? {
                ServerStartup::Ok { addr: actual_addr } => {
                    if addr.to_string() != actual_addr {
                        // bail as the next connect_with_retry will fail
                        bail!(
                            "sccache: Listening on address {actual_addr} instead of {addr}"
                        );
                    }
                }
                ServerStartup::AddrInUse => {
                    debug!("AddrInUse: possible parallel server bootstraps, retrying..")
                }
                ServerStartup::TimedOut => bail!("Timed out waiting for server startup. Maybe the remote service is unreachable?\nRun with SCCACHE_LOG=debug SCCACHE_NO_DAEMON=1 to get more information"),
                ServerStartup::Err { reason } => bail!("Server startup failed: {}\nRun with SCCACHE_LOG=debug SCCACHE_NO_DAEMON=1 to get more information", reason),
            }
            let server = connect_with_retry(addr)?;
            Ok(server)
        }
        Err(e) => Err(e.into()),
    }
}

/// Send a `ZeroStats` request to the server, and return the `ServerInfo` request if successful.
pub fn request_zero_stats(mut conn: ServerConnection) -> Result<()> {
    debug!("request_stats");
    let response = conn.request(Request::ZeroStats).context(
        "failed to send zero statistics command to server or failed to receive response",
    )?;
    if let Response::ZeroStats = response {
        Ok(())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `GetStats` request to the server, and return the `ServerInfo` request if successful.
pub fn request_stats(mut conn: ServerConnection) -> Result<ServerInfo> {
    debug!("request_stats");
    let response = conn.request(Request::GetStats).context(
        "Failed to send data to or receive data from server. Mismatch of client/server versions?",
    )?;
    if let Response::Stats(stats) = response {
        Ok(*stats)
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `DistStatus` request to the server, and return `DistStatus` if successful.
pub fn request_dist_status(mut conn: ServerConnection) -> Result<DistInfo> {
    debug!("request_dist_status");
    let response = conn
        .request(Request::DistStatus)
        .context("Failed to send data to or receive data from server")?;
    if let Response::DistStatus(info) = response {
        Ok(info)
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `Shutdown` request to the server, and return the `ServerInfo` contained within the response if successful.
pub fn request_shutdown(mut conn: ServerConnection) -> Result<ServerInfo> {
    debug!("request_shutdown");
    //TODO: better error mapping
    let response = conn
        .request(Request::Shutdown)
        .context("Failed to send data to or receive data from server")?;
    if let Response::ShuttingDown(stats) = response {
        Ok(*stats)
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `Compile` request to the server, and return the server response if successful.
fn request_compile<W, X, Y>(
    conn: &mut ServerConnection,
    exe: W,
    args: &[X],
    cwd: Y,
    env_vars: Vec<(OsString, OsString)>,
) -> Result<CompileResponse>
where
    W: AsRef<Path>,
    X: AsRef<OsStr>,
    Y: AsRef<Path>,
{
    let req = Request::Compile(Compile {
        exe: exe.as_ref().to_owned().into(),
        cwd: cwd.as_ref().to_owned().into(),
        args: args.iter().map(|a| a.as_ref().to_owned()).collect(),
        env_vars,
    });
    trace!("request_compile: {:?}", req);
    //TODO: better error mapping?
    let response = conn
        .request(req)
        .context("Failed to send data to or receive data from server")?;
    if let Response::Compile(response) = response {
        Ok(response)
    } else {
        bail!("Unexpected response from server")
    }
}

/// Return the signal that caused a process to exit from `status`.
#[cfg(unix)]
#[allow(dead_code)]
fn status_signal(status: process::ExitStatus) -> Option<i32> {
    status.signal()
}

/// Not implemented for non-Unix.
#[cfg(not(unix))]
#[allow(dead_code)]
fn status_signal(_status: process::ExitStatus) -> Option<i32> {
    None
}

/// Handle `response`, the output from running a compile on the server.
/// Return the compiler exit status.
fn handle_compile_finished(
    response: CompileFinished,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32> {
    trace!("handle_compile_finished");
    fn write_output(
        stream: impl IsTerminal,
        writer: &mut dyn Write,
        data: &[u8],
        color_mode: ColorMode,
    ) -> Result<()> {
        // rustc uses the `termcolor` crate which explicitly checks for TERM=="dumb", so
        // match that behavior here.
        let dumb_term = env::var("TERM").map(|v| v == "dumb").unwrap_or(false);
        // If the compiler options explicitly requested color output, or if this output stream
        // is a terminal and the compiler options didn't explicitly request non-color output,
        // then write the compiler output directly.
        if color_mode == ColorMode::On
            || (!dumb_term && stream.is_terminal() && color_mode != ColorMode::Off)
        {
            writer.write_all(data)?;
        } else {
            // Remove escape codes (and thus colors) while writing.
            let mut writer = Writer::new(writer);
            writer.write_all(data)?;
        }
        Ok(())
    }
    // It might be nice if the server sent stdout/stderr as the process
    // ran, but then it would have to also save them in the cache as
    // interleaved streams to really make it work.
    write_output(
        std::io::stdout(),
        stdout,
        &response.stdout,
        response.color_mode,
    )?;
    write_output(
        std::io::stderr(),
        stderr,
        &response.stderr,
        response.color_mode,
    )?;

    if let Some(ret) = response.retcode {
        trace!("compiler exited with status {}", ret);
        Ok(ret)
    } else if let Some(signal) = response.signal {
        println!("sccache: Compiler killed by signal {}", signal);
        Ok(-2)
    } else {
        println!("sccache: Missing compiler exit status!");
        Ok(-3)
    }
}

/// Handle `response`, the response from sending a `Compile` request to the server. Return the compiler exit status.
///
/// If the server returned `CompileStarted`, wait for a `CompileFinished` and
/// print the results.
///
/// If the server returned `UnhandledCompile`, run the compilation command
/// locally using `creator` and return the result.
#[allow(clippy::too_many_arguments)]
fn handle_compile_response<T>(
    mut creator: T,
    runtime: &mut Runtime,
    conn: &mut ServerConnection,
    response: CompileResponse,
    exe: &Path,
    cmdline: Vec<OsString>,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32>
where
    T: CommandCreatorSync,
{
    match response {
        CompileResponse::CompileStarted => {
            debug!("Server sent CompileStarted");
            // Wait for CompileFinished.
            match conn.read_one_response() {
                Ok(Response::CompileFinished(result)) => {
                    return handle_compile_finished(result, stdout, stderr)
                }
                Ok(_) => bail!("unexpected response from server"),
                Err(e) => {
                    match e.downcast_ref::<io::Error>() {
                        Some(io_e) if io_e.kind() == io::ErrorKind::UnexpectedEof => {
                            eprintln!(
                                "sccache: warning: The server looks like it shut down \
                                 unexpectedly, compiling locally instead"
                            );
                        }
                        _ => {
                            //TODO: something better here?
                            if ignore_all_server_io_errors() {
                                eprintln!(
                                    "sccache: warning: error reading compile response from server \
                                     compiling locally instead"
                                );
                            } else {
                                return Err(e)
                                    .context("error reading compile response from server");
                            }
                        }
                    }
                }
            }
        }
        CompileResponse::UnsupportedCompiler(s) => {
            debug!("Server sent UnsupportedCompiler: {:?}", s);
            bail!("Compiler not supported: {:?}", s);
        }
        CompileResponse::UnhandledCompile => {
            debug!("Server sent UnhandledCompile");
        }
    };

    let mut cmd = creator.new_command_sync(exe);
    cmd.args(&cmdline).current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("running command: {:?}", cmd);
    }

    let status = runtime.block_on(async move {
        let child = cmd.spawn().await?;
        child
            .wait()
            .await
            .with_context(|| "failed to wait for a child")
    })?;

    Ok(status.code().unwrap_or_else(|| {
        if let Some(sig) = status_signal(status) {
            println!("sccache: Compile terminated by signal {}", sig);
        }
        // Arbitrary.
        2
    }))
}

/// Send a `Compile` request to the sccache server `conn`, and handle the response.
///
/// The first entry in `cmdline` will be looked up in `path` if it is not
/// an absolute path.
/// See `request_compile` and `handle_compile_response`.
#[allow(clippy::too_many_arguments)]
pub fn do_compile<T>(
    creator: T,
    runtime: &mut Runtime,
    mut conn: ServerConnection,
    exe: &Path,
    cmdline: Vec<OsString>,
    cwd: &Path,
    path: Option<OsString>,
    env_vars: Vec<(OsString, OsString)>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32>
where
    T: CommandCreatorSync,
{
    trace!("do_compile");
    let exe_path = which_in(exe, path, cwd)?;
    let res = request_compile(&mut conn, &exe_path, &cmdline, cwd, env_vars)?;
    handle_compile_response(
        creator, runtime, &mut conn, res, &exe_path, cmdline, cwd, stdout, stderr,
    )
}

/// Run `cmd` and return the process exit status.
pub fn run_command(cmd: Command) -> Result<i32> {
    // Config isn't required for all commands, but if it's broken then we should flag
    // it early and loudly.
    let config = &Config::load()?;
    let startup_timeout = config.server_startup_timeout;

    match cmd {
        Command::ShowStats(fmt, advanced) => {
            trace!("Command::ShowStats({:?})", fmt);
            let stats = match connect_to_server(&get_addr()) {
                Ok(srv) => request_stats(srv).context("failed to get stats from server")?,
                // If there is no server, spawning a new server would start with zero stats
                // anyways, so we can just return (mostly) empty stats directly.
                Err(_) => {
                    let runtime = Runtime::new()?;
                    let storage = storage_from_config(config, runtime.handle()).ok();
                    runtime.block_on(ServerInfo::new(ServerStats::default(), storage.as_deref()))?
                }
            };
            match fmt {
                StatsFormat::Text => stats.print(advanced),
                StatsFormat::Json => serde_json::to_writer(&mut io::stdout(), &stats)?,
            }
        }
        Command::DebugPreprocessorCacheEntries => {
            trace!("Command::DebugPreprocessorCacheEntries");
            let entries_dir = default_disk_cache_dir().join("preprocessor");
            for entry in WalkDir::new(entries_dir).sort_by_file_name().into_iter() {
                let preprocessor_cache_entry_file = entry?;
                let path = preprocessor_cache_entry_file.path();
                if !path.is_file() {
                    continue;
                }
                println!("=========================");
                println!("Showing preprocessor entry file {}", &path.display());
                let contents = std::fs::read(path)?;
                let preprocessor_cache_entry =
                    crate::compiler::PreprocessorCacheEntry::read(&contents)?;
                println!("{:#?}", preprocessor_cache_entry);
                println!("=========================");
            }
        }
        Command::InternalStartServer => {
            trace!("Command::InternalStartServer");
            if env::var("SCCACHE_ERROR_LOG").is_ok() {
                let f = create_error_log()?;
                // Can't report failure here, we're already daemonized.
                daemonize()?;
                redirect_error_log(f)?;
            } else {
                // We aren't asking for a log file
                daemonize()?;
            }
            server::start_server(config, &get_addr())?;
        }
        Command::StartServer => {
            trace!("Command::StartServer");
            println!("sccache: Starting the server...");
            let startup =
                run_server_process(startup_timeout).context("failed to start server process")?;
            match startup {
                ServerStartup::Ok { addr } => {
                    println!("sccache: Listening on address {addr}");
                }
                ServerStartup::TimedOut => bail!("Timed out waiting for server startup"),
                ServerStartup::AddrInUse => bail!("Server startup failed: Address in use"),
                ServerStartup::Err { reason } => bail!("Server startup failed: {}", reason),
            }
        }
        Command::StopServer => {
            trace!("Command::StopServer");
            println!("Stopping sccache server...");
            let server = connect_to_server(&get_addr()).context("couldn't connect to server")?;
            let stats = request_shutdown(server)?;
            stats.print(false);
        }
        Command::ZeroStats => {
            trace!("Command::ZeroStats");
            let conn = connect_or_start_server(&get_addr(), startup_timeout)?;
            request_zero_stats(conn).context("couldn't zero stats on server")?;
            eprintln!("Statistics zeroed.");
        }
        #[cfg(feature = "dist-client")]
        Command::DistAuth => {
            use crate::config;
            use crate::dist;
            use url::Url;

            match &config.dist.auth {
                config::DistAuth::Token { .. } => {
                    info!("No authentication needed for type 'token'")
                }
                config::DistAuth::Oauth2CodeGrantPKCE {
                    client_id,
                    auth_url,
                    token_url,
                } => {
                    let cached_config = config::CachedConfig::load()?;

                    let parsed_auth_url = Url::parse(auth_url)
                        .map_err(|_| anyhow!("Failed to parse URL {}", auth_url))?;
                    let token = dist::client_auth::get_token_oauth2_code_grant_pkce(
                        client_id,
                        parsed_auth_url,
                        token_url,
                    )?;

                    cached_config
                        .with_mut(|c| {
                            c.dist.auth_tokens.insert(auth_url.to_owned(), token);
                        })
                        .context("Unable to save auth token")?;
                    println!("Saved token")
                }
                config::DistAuth::Oauth2Implicit {
                    client_id,
                    auth_url,
                } => {
                    let cached_config = config::CachedConfig::load()?;

                    let parsed_auth_url = Url::parse(auth_url)
                        .map_err(|_| anyhow!("Failed to parse URL {}", auth_url))?;
                    let token =
                        dist::client_auth::get_token_oauth2_implicit(client_id, parsed_auth_url)?;

                    cached_config
                        .with_mut(|c| {
                            c.dist.auth_tokens.insert(auth_url.to_owned(), token);
                        })
                        .context("Unable to save auth token")?;
                    println!("Saved token")
                }
            };
        }
        #[cfg(not(feature = "dist-client"))]
        Command::DistAuth => bail!(
            "Distributed compilation not compiled in, please rebuild with the dist-client feature"
        ),
        Command::DistStatus => {
            trace!("Command::DistStatus");
            let srv = connect_or_start_server(&get_addr(), startup_timeout)?;
            let status =
                request_dist_status(srv).context("failed to get dist-status from server")?;
            serde_json::to_writer(&mut io::stdout(), &status)?;
        }
        #[cfg(feature = "dist-client")]
        Command::PackageToolchain(executable, out) => {
            use crate::compiler;

            trace!("Command::PackageToolchain({})", executable.display());
            let runtime = Runtime::new()?;
            let jobserver = Client::new();
            let creator = ProcessCommandCreator::new(&jobserver);
            let args: Vec<_> = env::args_os().collect();
            let env: Vec<_> = env::vars_os().collect();
            let out_file = File::create(out)?;
            let cwd = env::current_dir().expect("A current working dir should exist");

            let pool = runtime.handle().clone();
            runtime.block_on(async move {
                compiler::get_compiler_info(creator, &executable, &cwd, &args, &env, &pool, None)
                    .await
                    .map(|compiler| compiler.0.get_toolchain_packager())
                    .and_then(|packager| packager.write_pkg(out_file))
            })?
        }
        #[cfg(not(feature = "dist-client"))]
        Command::PackageToolchain(_executable, _out) => bail!(
            "Toolchain packaging not compiled in, please rebuild with the dist-client feature"
        ),
        Command::Compile {
            exe,
            cmdline,
            cwd,
            env_vars,
        } => {
            trace!("Command::Compile {{ {:?}, {:?}, {:?} }}", exe, cmdline, cwd);
            let jobserver = Client::new();
            let conn = connect_or_start_server(&get_addr(), startup_timeout)?;
            let mut runtime = Runtime::new()?;
            let res = do_compile(
                ProcessCommandCreator::new(&jobserver),
                &mut runtime,
                conn,
                exe.as_ref(),
                cmdline,
                &cwd,
                env::var_os("PATH"),
                env_vars,
                &mut io::stdout(),
                &mut io::stderr(),
            );
            return res.context("failed to execute compile");
        }
    }

    Ok(0)
}
