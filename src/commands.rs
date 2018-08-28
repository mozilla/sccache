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

use atty::{self, Stream};
use bincode;
use byteorder::{ByteOrder, BigEndian};
use client::{
    connect_to_server,
    connect_with_retry,
    ServerConnection,
};
use cmdline::{Command, StatsFormat};
use compiler::ColorMode;
use futures::Future;
use jobserver::Client;
use log::Level::Trace;
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
    RunCommand,
};
use protocol::{Request, Response, CompileResponse, CompileFinished, Compile};
use serde_json;
use server::{self, ServerInfo, ServerStartup};
use std::env;
use std::ffi::{OsStr,OsString};
use std::fs::{File, OpenOptions};
use std::io::{
    self,
    Write,
};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{
    Path,
};
use std::process;
use strip_ansi_escapes::Writer;
use tokio_core::reactor::Core;
use tokio_io::AsyncRead;
use tokio_io::io::read_exact;
use util::run_input_output;
use which::which_in;

use errors::*;

/// The default sccache server port.
pub const DEFAULT_PORT: u16 = 4226;

/// The number of milliseconds to wait for server startup.
const SERVER_STARTUP_TIMEOUT_MS: u32 = 5000;

/// Get the port on which the server should listen.
fn get_port() -> u16 {
    env::var("SCCACHE_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

fn read_server_startup_status<R: AsyncRead>(server: R) -> impl Future<Item=ServerStartup, Error=Error> {
    // This is an async equivalent of ServerConnection::read_one_response
    read_exact(server, [0u8; 4]).map_err(Error::from).and_then(|(server, bytes)| {
        let len = BigEndian::read_u32(&bytes);
        let data = vec![0; len as usize];
        read_exact(server, data).map_err(Error::from).and_then(|(_server, data)| {
            Ok(bincode::deserialize(&data)?)
        })
    })
}

/// Re-execute the current executable as a background server, and wait
/// for it to start up.
#[cfg(not(windows))]
fn run_server_process() -> Result<ServerStartup> {
    extern crate tokio_uds;

    use futures::Stream;
    use std::time::Duration;
    use tempdir::TempDir;
    use tokio_core::reactor::Timeout;

    trace!("run_server_process");
    let tempdir = TempDir::new("sccache")?;
    let socket_path = tempdir.path().join("sock");
    let mut core = Core::new()?;
    let handle = core.handle();
    let listener = tokio_uds::UnixListener::bind(&socket_path)?;
    let exe_path = env::current_exe()?;
    let _child = process::Command::new(exe_path)
            .env("SCCACHE_START_SERVER", "1")
            .env("SCCACHE_STARTUP_NOTIFY", &socket_path)
            .env("RUST_BACKTRACE", "1")
            .spawn()?;

    let startup = listener.incoming().into_future().map_err(|e| e.0);
    let startup = startup.map_err(Error::from).and_then(|(socket, _rest)| {
        let socket = socket.unwrap(); // incoming() never returns None
        read_server_startup_status(socket)
    });

    let timeout = Duration::from_millis(SERVER_STARTUP_TIMEOUT_MS.into());
    let timeout = Timeout::new(timeout, &handle)?.map_err(Error::from)
        .map(|()| ServerStartup::TimedOut);
    match core.run(startup.select(timeout)) {
        Ok((e, _other)) => Ok(e),
        Err((e, _other)) => Err(e.into()),
    }
}

/// Pipe `cmd`'s stdio to `/dev/null`, unless a specific env var is set.
#[cfg(not(windows))]
fn daemonize() -> Result<()> {
    use daemonize::Daemonize;
    use libc;
    use std::mem;

    match env::var("SCCACHE_NO_DAEMON") {
        Ok(ref val) if val == "1" => {}
        _ => {
            Daemonize::new().start().chain_err(|| {
                "failed to daemonize"
            })?;
        }
    }

    static mut PREV_SIGSEGV: *mut libc::sigaction = 0 as *mut _;
    static mut PREV_SIGBUS: *mut libc::sigaction = 0 as *mut _;
    static mut PREV_SIGILL: *mut libc::sigaction = 0 as *mut _;

    // We don't have a parent process any more once we've reached this point,
    // which means that no one's probably listening for our exit status.
    // In order to assist with debugging crashes of the server we configure our
    // rlimit to allow core dumps and we also install a signal handler for
    // segfaults which at least prints out what just happened.
    unsafe {
        match env::var("SCCACHE_ALLOW_CORE_DUMPS") {
            Ok(ref val) if val == "1" => {
                let rlim = libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &rlim);
            }
            _ => {}
        }

        PREV_SIGSEGV = Box::into_raw(Box::new(mem::zeroed::<libc::sigaction>()));
        PREV_SIGBUS = Box::into_raw(Box::new(mem::zeroed::<libc::sigaction>()));
        PREV_SIGILL = Box::into_raw(Box::new(mem::zeroed::<libc::sigaction>()));
        let mut new: libc::sigaction = mem::zeroed();
        new.sa_sigaction = handler as usize;
        new.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigaction(libc::SIGSEGV, &new, &mut *PREV_SIGSEGV);
        libc::sigaction(libc::SIGBUS, &new, &mut *PREV_SIGBUS);
        libc::sigaction(libc::SIGILL, &new, &mut *PREV_SIGILL);
    }

    return Ok(());

    extern fn handler(signum: libc::c_int,
                      _info: *mut libc::siginfo_t,
                      _ptr: *mut libc::c_void) {
        use std::fmt::{Result, Write};

        struct Stderr;

        impl Write for Stderr {
            fn write_str(&mut self, s: &str) -> Result {
                unsafe {
                    let bytes = s.as_bytes();
                    libc::write(libc::STDERR_FILENO,
                                bytes.as_ptr() as *const _,
                                bytes.len());
                    Ok(())
                }
            }
        }

        unsafe {
            drop(writeln!(Stderr, "signal {} received", signum));

            // Configure the old handler and then resume the program. This'll
            // likely go on to create a core dump if one's configured to be
            // created.
            match signum {
                libc::SIGBUS => libc::sigaction(signum, &*PREV_SIGBUS, 0 as *mut _),
                libc::SIGILL => libc::sigaction(signum, &*PREV_SIGILL, 0 as *mut _),
                _ => libc::sigaction(signum, &*PREV_SIGSEGV, 0 as *mut _),
            };
        }
    }
}

/// This is a no-op on Windows.
#[cfg(windows)]
fn daemonize() -> Result<()> { Ok(()) }

#[cfg(not(windows))]
fn redirect_stderr(f: File) -> Result<()> {
    use libc::dup2;
    use std::os::unix::io::IntoRawFd;
    // Ignore errors here.
    unsafe { dup2(f.into_raw_fd(), 2); }
    Ok(())
}

#[cfg(windows)]
fn redirect_stderr(f: File) -> Result<()> {
    use winapi::um::winbase::STD_ERROR_HANDLE;
    use winapi::um::processenv::SetStdHandle;
    use std::os::windows::io::IntoRawHandle;
    // Ignore errors here.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, f.into_raw_handle()); }
    Ok(())
}

/// If `SCCACHE_ERROR_LOG` is set, redirect stderr to it.
fn redirect_error_log() -> Result<()> {
    let name = match env::var("SCCACHE_ERROR_LOG") {
        Ok(filename) => filename,
        _ => return Ok(()),
    };
    let f = OpenOptions::new().create(true).append(true).open(name)?;
    redirect_stderr(f)
}

/// Re-execute the current executable as a background server.
#[cfg(windows)]
fn run_server_process() -> Result<ServerStartup> {
    use kernel32;
    use mio_named_pipes::NamedPipe;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use std::time::Duration;
    use tokio_core::reactor::{Core, Timeout, PollEvented};
    use uuid::Uuid;
    use winapi::um::winbase::{CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP};
    use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOW, CreateProcessW};
    use winapi::shared::minwindef::{TRUE, FALSE, LPVOID, DWORD};

    trace!("run_server_process");

    // Create a mini event loop and register our named pipe server
    let mut core = Core::new()?;
    let handle = core.handle();
    let pipe_name = format!(r"\\.\pipe\{}", Uuid::new_v4().simple());
    let server = NamedPipe::new(&pipe_name)?;
    let server = PollEvented::new(server, &handle)?;

    // Connect a client to our server, and we'll wait below if it's still in
    // progress.
    match server.get_ref().connect() {
        Ok(()) => {}
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e.into()),
    }

    // Spawn a server which should come back and connect to us
    let exe_path = env::current_exe()?;
	let mut exe = OsStr::new(&exe_path)
						.encode_wide()
						.chain(Some(0u16))
                        .collect::<Vec<u16>>();
    let mut envp = {
        let mut v = vec!();
        let extra_vars =
        vec![
            (OsString::from("SCCACHE_START_SERVER"), OsString::from("1")),
            (OsString::from("SCCACHE_STARTUP_NOTIFY"), OsString::from(&pipe_name)),
            (OsString::from("RUST_BACKTRACE"), OsString::from("1")),
        ];
        for (key, val) in env::vars_os().chain(extra_vars) {
            v.extend(key.encode_wide().chain(Some('=' as u16))
                                      .chain(val.encode_wide())
                                      .chain(Some(0)));
        }
        v.push(0);
        v
    };

    // TODO: Expose `bInheritHandles` argument of `CreateProcessW` through the
    //       standard library's `Command` type and then use that instead.
	let mut pi = PROCESS_INFORMATION {
		hProcess: ptr::null_mut(),
		hThread: ptr::null_mut(),
		dwProcessId: 0,
        dwThreadId: 0,
    };
    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
    if unsafe { CreateProcessW(exe.as_mut_ptr(),
                               ptr::null_mut(),
                               ptr::null_mut(),
                               ptr::null_mut(),
                               FALSE,
                               CREATE_UNICODE_ENVIRONMENT |
                                  DETACHED_PROCESS |
                                  CREATE_NEW_PROCESS_GROUP,
                               envp.as_mut_ptr() as LPVOID,
                               ptr::null(),
                               &mut si,
                               &mut pi) == TRUE } {
        unsafe {
            kernel32::CloseHandle(pi.hProcess);
            kernel32::CloseHandle(pi.hThread);
        }
    } else {
        return Err(io::Error::last_os_error().into())
    }

    let result = read_server_startup_status(server);

    let timeout = Duration::from_millis(SERVER_STARTUP_TIMEOUT_MS.into());
    let timeout = Timeout::new(timeout, &handle)?.map_err(Error::from)
        .map(|()| ServerStartup::TimedOut);
    match core.run(result.select(timeout)) {
        Ok((e, _other)) => Ok(e),
        Err((e, _other)) => Err(e).chain_err(|| "failed waiting for server to start"),
    }
}

/// Attempt to connect to an sccache server listening on `port`, or start one if no server is running.
fn connect_or_start_server(port: u16) -> Result<ServerConnection> {
    trace!("connect_or_start_server({})", port);
    match connect_to_server(port) {
        Ok(server) => Ok(server),
        Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused ||
                      e.kind() == io::ErrorKind::TimedOut => {
            // If the connection was refused we probably need to start
            // the server.
            //TODO: check startup value!
            let _startup = run_server_process()?;
            let server = connect_with_retry(port)?;
            Ok(server)
        }
        Err(e) => Err(e.into())
    }
}

/// Send a `ZeroStats` request to the server, and return the `ServerInfo` request if successful.
pub fn request_zero_stats(mut conn: ServerConnection) -> Result<ServerInfo> {
    debug!("request_stats");
    let response = conn.request(Request::ZeroStats).chain_err(|| {
        "failed to send zero statistics command to server or failed to receive respone"
    })?;
    if let Response::Stats(stats) = response {
        Ok(stats)
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `GetStats` request to the server, and return the `ServerInfo` request if successful.
pub fn request_stats(mut conn: ServerConnection) -> Result<ServerInfo> {
    debug!("request_stats");
    let response = conn.request(Request::GetStats).chain_err(|| {
        "Failed to send data to or receive data from server"
    })?;
    if let Response::Stats(stats) = response {
        Ok(stats)
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `Shutdown` request to the server, and return the `ServerInfo` contained within the response if successful.
pub fn request_shutdown(mut conn: ServerConnection) -> Result<ServerInfo> {
    debug!("request_shutdown");
    //TODO: better error mapping
    let response = conn.request(Request::Shutdown).chain_err(|| {
        "Failed to send data to or receive data from server"
    })?;
    if let Response::ShuttingDown(stats) = response {
        Ok(stats)
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `Compile` request to the server, and return the server response if successful.
fn request_compile<W, X, Y>(conn: &mut ServerConnection, exe: W, args: &Vec<X>, cwd: Y,
                            env_vars: Vec<(OsString, OsString)>) -> Result<CompileResponse>
    where W: AsRef<Path>,
          X: AsRef<OsStr>,
          Y: AsRef<Path>,
{
    let req = Request::Compile(Compile {
        exe: exe.as_ref().to_owned().into(),
        cwd: cwd.as_ref().to_owned().into(),
        args: args.iter().map(|a| a.as_ref().to_owned()).collect(),
        env_vars: env_vars,
    });
    trace!("request_compile: {:?}", req);
    //TODO: better error mapping?
    let response = conn.request(req).chain_err(|| {
        "Failed to send data to or receive data from server"
    })?;
    if let Response::Compile(response) = response {
        Ok(response)
    } else {
        bail!("Unexpected response from server")
    }
}

/// Return the signal that caused a process to exit from `status`.
#[cfg(unix)]
#[allow(dead_code)]
fn status_signal(status : process::ExitStatus) -> Option<i32> {
    status.signal()
}

/// Not implemented for non-Unix.
#[cfg(not(unix))]
#[allow(dead_code)]
fn status_signal(_status : process::ExitStatus) -> Option<i32> {
    None
}

/// Handle `response`, the output from running a compile on the server.
/// Return the compiler exit status.
fn handle_compile_finished(response: CompileFinished,
                           stdout: &mut Write,
                           stderr: &mut Write) -> Result<i32> {
    trace!("handle_compile_finished");
    fn write_output(stream: Stream,
                    writer: &mut Write,
                    data: &[u8],
                    color_mode: ColorMode) -> Result<()> {
        // If the compiler options explicitly requested color output, or if this output stream
        // is a terminal and the compiler options didn't explicitly request non-color output,
        // then write the compiler output directly.
        if color_mode == ColorMode::On || (atty::is(stream) && color_mode != ColorMode::Off)  {
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
    write_output(Stream::Stdout, stdout, &response.stdout, response.color_mode)?;
    write_output(Stream::Stderr, stderr, &response.stderr, response.color_mode)?;

    if let Some(ret) = response.retcode {
        trace!("compiler exited with status {}", ret);
        Ok(ret)
    } else if let Some(signal) = response.signal {
        println!("Compiler killed by signal {}", signal);
        Ok(-2)
    } else {
        println!("Missing compiler exit status!");
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
fn handle_compile_response<T>(mut creator: T,
                              core: &mut Core,
                              conn: &mut ServerConnection,
                              response: CompileResponse,
                              exe: &Path,
                              cmdline: Vec<OsString>,
                              cwd: &Path,
                              stdout: &mut Write,
                              stderr: &mut Write) -> Result<i32>
    where T : CommandCreatorSync,
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
                Err(Error(ErrorKind::Io(ref e), _))
                    if e.kind() == io::ErrorKind::UnexpectedEof =>
                {
					writeln!(io::stderr(),
							 "warning: sccache server looks like it shut down \
                              unexpectedly, compiling locally instead").unwrap();
                }
				Err(e) => return Err(e).chain_err(|| {
                    //TODO: something better here?
                    "error reading compile response from server"
                }),
            }
        }
        CompileResponse::UnsupportedCompiler => {
            debug!("Server sent UnsupportedCompiler");
            bail!("Compiler not supported");
        }
        CompileResponse::UnhandledCompile => {
            debug!("Server sent UnhandledCompile");
        }
    };

    //TODO: possibly capture output here for testing.
    let mut cmd = creator.new_command_sync(exe);
    cmd.args(&cmdline)
        .current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("running command: {:?}", cmd);
    }
    match core.run(run_input_output(cmd, None)) {
        Ok(output) | Err(Error(ErrorKind::ProcessError(output), _)) => {
            if !output.stdout.is_empty() {
                stdout.write_all(&output.stdout)?;
            }
            if !output.stderr.is_empty() {
                stderr.write_all(&output.stderr)?;
            }
            Ok(output.status.code().unwrap_or_else(|| {
                if let Some(sig) = status_signal(output.status) {
                    println!("Compile terminated by signal {}", sig);
                }
                // Arbitrary.
                2
            }))
        }
        Err(e) => Err(e),
    }
}

/// Send a `Compile` request to the sccache server `conn`, and handle the response.
///
/// The first entry in `cmdline` will be looked up in `path` if it is not
/// an absolute path.
/// See `request_compile` and `handle_compile_response`.
pub fn do_compile<T>(creator: T,
                     core: &mut Core,
                     mut conn: ServerConnection,
                     exe: &Path,
                     cmdline: Vec<OsString>,
                     cwd: &Path,
                     path: Option<OsString>,
                     env_vars: Vec<(OsString, OsString)>,
                     stdout: &mut Write,
                     stderr: &mut Write) -> Result<i32>
    where T: CommandCreatorSync,
{
    trace!("do_compile");
    let exe_path = which_in(exe, path, &cwd)?;
    let res = request_compile(&mut conn, &exe_path, &cmdline, &cwd, env_vars)?;
    handle_compile_response(creator, core, &mut conn, res, &exe_path, cmdline, cwd, stdout, stderr)
}

/// Run `cmd` and return the process exit status.
pub fn run_command(cmd: Command) -> Result<i32> {
    match cmd {
        Command::ShowStats(fmt) => {
            trace!("Command::ShowStats({:?})", fmt);
            let srv = connect_or_start_server(get_port())?;
            let stats = request_stats(srv).chain_err(|| {
                "failed to get stats from server"
            })?;
            match fmt {
                StatsFormat::text => stats.print(),
                StatsFormat::json => serde_json::to_writer(&mut io::stdout(), &stats)?,
            }
        }
        Command::InternalStartServer => {
            trace!("Command::InternalStartServer");
            // Can't report failure here, we're already daemonized.
            daemonize()?;
            redirect_error_log()?;
            server::start_server(get_port())?;
        }
        Command::StartServer => {
            trace!("Command::StartServer");
            println!("Starting sccache server...");
            let startup = run_server_process().chain_err(|| {
                "failed to start server process"
            })?;
            match startup {
                ServerStartup::Ok { port } => {
                    if port != DEFAULT_PORT {
                        println!("Listening on port {}", port);
                    }
                }
                ServerStartup::TimedOut => {
                    bail!("Timed out waiting for server startup")
                }
                ServerStartup::Err { reason } => {
                    bail!("Server startup failed: {}", reason)
                }
            }
        }
        Command::StopServer => {
            trace!("Command::StopServer");
            println!("Stopping sccache server...");
            let server = connect_to_server(get_port()).chain_err(|| {
                "couldn't connect to server"
            })?;
            let stats = request_shutdown(server)?;
            stats.print();
        }
        Command::Compile { exe, cmdline, cwd, env_vars } => {
            trace!("Command::Compile {{ {:?}, {:?}, {:?} }}", exe, cmdline, cwd);
            let jobserver = unsafe { Client::new() };
            let conn = connect_or_start_server(get_port())?;
            let mut core = Core::new()?;
            let res = do_compile(ProcessCommandCreator::new(&core.handle(), &jobserver),
                                 &mut core,
                                 conn,
                                 exe.as_ref(),
                                 cmdline,
                                 &cwd,
                                 env::var_os("PATH"),
                                 env_vars,
                                 &mut io::stdout(),
                                 &mut io::stderr());
            return res.chain_err(|| {
                "failed to execute compile"
            })
        }
        Command::ZeroStats => {
            trace!("Command::ZeroStats");
            let conn = connect_or_start_server(get_port())?;
            let stats = request_zero_stats(conn).chain_err(|| {
                "couldn't zero stats on server"
            })?;
            stats.print();
        }
    }

    Ok(0)
}
