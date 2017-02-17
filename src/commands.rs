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

use client::{
    connect_to_server,
    connect_with_retry,
    ServerConnection,
};
use cmdline::Command;
use compiler::{
    run_input_output,
};
use log::LogLevel::Trace;
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
    RunCommand,
};
use number_prefix::{
    binary_prefix,
    Prefixed,
    Standalone,
};
use protobuf::RepeatedField;
use protocol::{
    CacheStats,
    ClientRequest,
    Compile,
    CompileFinished,
    CompileStarted,
    GetStats,
    Shutdown,
    UnhandledCompile,
    ZeroStats,
};
use server;
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
use tokio_core::reactor::Core;
use which::which_in;

use errors::*;

/// The default sccache server port.
pub const DEFAULT_PORT: u16 = 4226;

/// The number of milliseconds to wait for server startup.
const SERVER_STARTUP_TIMEOUT_MS: u32 = 5000;

/// Possible responses from the server for a `Compile` request.
enum CompileResponse {
    /// The compilation was started.
    CompileStarted(CompileStarted),
    /// The server could not handle this compilation request.
    UnhandledCompile(UnhandledCompile),
}

// Should this just be a Result?
/// Result of background server startup.
enum ServerStartup {
    /// Server started successfully.
    Ok,
    /// Timed out waiting for server startup.
    TimedOut,
    /// Server encountered an error.
    Err(Error),
}

/// Get the port on which the server should listen.
fn get_port() -> u16 {
    env::var("SCCACHE_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Re-execute the current executable as a background server, and wait
/// for it to start up.
#[cfg(not(windows))]
fn run_server_process() -> Result<ServerStartup> {
    extern crate tokio_uds;

    use futures::{Future, Stream};
    use std::time::Duration;
    use tempdir::TempDir;
    use tokio_core::io::read_exact;
    use tokio_core::reactor::Timeout;

    trace!("run_server_process");
    let tempdir = TempDir::new("sccache")?;
    let socket_path = tempdir.path().join("sock");
    let mut core = Core::new()?;
    let handle = core.handle();
    let listener = tokio_uds::UnixListener::bind(&socket_path, &handle)?;
    let exe_path = env::current_exe()?;
    let _child = process::Command::new(exe_path)
            .env("SCCACHE_START_SERVER", "1")
            .env("SCCACHE_STARTUP_NOTIFY", &socket_path)
            .env("RUST_BACKTRACE", "1")
            .spawn()?;

    let startup = listener.incoming().into_future().map_err(|e| e.0);
    let startup = startup.and_then(|(socket, _rest)| {
        let (socket, _addr) = socket.unwrap(); // incoming() never returns None
        read_exact(socket, [0u8]).map(|(_socket, byte)| {
            if byte[0] == 0 {
                ServerStartup::Ok
            } else {
                let err = format!("Server startup failed: {}", byte[0]).into();
                ServerStartup::Err(err)
            }
        })
    });

    let timeout = Duration::from_millis(SERVER_STARTUP_TIMEOUT_MS.into());
    let timeout = Timeout::new(timeout, &handle)?.map(|()| ServerStartup::TimedOut);
    match core.run(startup.select(timeout)) {
        Ok((e, _other)) => Ok(e),
        Err((e, _other)) => Err(e.into()),
    }
}

/// Pipe `cmd`'s stdio to `/dev/null`, unless a specific env var is set.
#[cfg(not(windows))]
fn daemonize() -> Result<()> {
    use daemonize::Daemonize;
    if match env::var("SCCACHE_NO_DAEMON") {
            Ok(val) => val == "1",
            Err(_) => false,
    } {
        Ok(())
    } else {
        Daemonize::new().start().chain_err(|| {
            "failed to daemonize"
        })
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
    use kernel32::SetStdHandle;
    use winapi::winbase::STD_ERROR_HANDLE;
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
///
/// `std::process::Command` doesn't expose a way to create a
/// detatched process on Windows, so we have to roll our own.
/// TODO: remove this all when `CommandExt::creation_flags` hits stable:
/// https://github.com/rust-lang/rust/issues/37827
#[cfg(windows)]
fn run_server_process() -> Result<ServerStartup> {
    use kernel32;
    use named_pipe::PipeOptions;
    use std::io::{Read, Error};
    use std::os::windows::ffi::OsStrExt;
    use std::mem;
    use std::ptr;
    use uuid::Uuid;
    use winapi::minwindef::{TRUE,FALSE,LPVOID,DWORD};
    use winapi::processthreadsapi::{PROCESS_INFORMATION,STARTUPINFOW};
    use winapi::winbase::{CREATE_UNICODE_ENVIRONMENT,DETACHED_PROCESS,CREATE_NEW_PROCESS_GROUP};

    trace!("run_server_process");
    // Create a pipe to get startup status back from the server.
    let pipe_name = format!(r"\\.\pipe\{}", Uuid::new_v4().simple());
    let server = PipeOptions::new(&pipe_name).single()?;
    let exe_path = env::current_exe()?;
    let mut exe = OsStr::new(&exe_path)
        .encode_wide()
        .chain(Some(0u16))
        .collect::<Vec<u16>>();
    // Collect existing env vars + extra into an environment block.
    let mut envp = {
        let mut v = vec!();
        let extra_vars = vec![
            (OsString::from("SCCACHE_START_SERVER"), OsString::from("1")),
            (OsString::from("SCCACHE_STARTUP_NOTIFY"), OsString::from(&pipe_name)),
            (OsString::from("RUST_BACKTRACE"), OsString::from("1")),
        ];
        for (key, val) in env::vars_os().chain(extra_vars) {
            v.extend(key.encode_wide().chain(Some('=' as u16)).chain(val.encode_wide()).chain(Some(0)));
        }
        v.push(0);
        v
    };
    let mut pi = PROCESS_INFORMATION {
        hProcess: ptr::null_mut(),
        hThread: ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };
    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
    if unsafe { kernel32::CreateProcessW(exe.as_mut_ptr(),
                                         ptr::null_mut(),
                                         ptr::null_mut(),
                                         ptr::null_mut(),
                                         FALSE,
                                         CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                                         envp.as_mut_ptr() as LPVOID,
                                         ptr::null(),
                                         &mut si,
                                         &mut pi) == TRUE } {
        unsafe {
            kernel32::CloseHandle(pi.hProcess);
            kernel32::CloseHandle(pi.hThread);
        }
    } else {
        return Err(Error::last_os_error().into())
    }
    // Wait for a connection on the pipe.
    let mut pipe = match server.wait_ms(SERVER_STARTUP_TIMEOUT_MS)? {
        Ok(pipe) => pipe,
        Err(_) => return Ok(ServerStartup::TimedOut),
    };
    // It would be nice to have a read timeout here.
    let mut buffer = [0; 1];
    pipe.read_exact(&mut buffer)?;
    if buffer[0] == 0 {
        info!("Server started up successfully");
        Ok(ServerStartup::Ok)
    } else {
        //TODO: send error messages over the socket as well.
        error!("Server startup failed: {}", buffer[0]);
        Ok(ServerStartup::Err(format!("Server startup failed: {}", buffer[0]).into()))
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

/// Send a `ZeroStats` request to the server, and return the `CacheStats` request if successful.
pub fn request_zero_stats(mut conn : ServerConnection) -> Result<CacheStats> {
    debug!("request_stats");
    let mut req = ClientRequest::new();
    req.set_zero_stats(ZeroStats::new());
    //TODO: better error mapping
    let mut response = conn.request(req).chain_err(|| {
        "failed to send zero statistics command to server or failed to receive respone"
    })?;
    if response.has_stats() {
        Ok(response.take_stats())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `GetStats` request to the server, and return the `CacheStats` request if successful.
pub fn request_stats(mut conn : ServerConnection) -> Result<CacheStats> {
    debug!("request_stats");
    let mut req = ClientRequest::new();
    req.set_get_stats(GetStats::new());
    //TODO: better error mapping
    let mut response = conn.request(req).chain_err(|| {
        "Failed to send data to or receive data from server"
    })?;
    if response.has_stats() {
        Ok(response.take_stats())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `Shutdown` request to the server, and return the `CacheStats` contained within the response if successful.
pub fn request_shutdown(mut conn : ServerConnection) -> Result<CacheStats> {
    debug!("request_shutdown");
    let mut req = ClientRequest::new();
    req.set_shutdown(Shutdown::new());
    //TODO: better error mapping
    let mut response = conn.request(req).chain_err(|| {
        "Failed to send data to or receive data from server"
    })?;
    if response.has_shutting_down() {
        Ok(response.take_shutting_down().take_stats())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Print `stats` to stdout.
fn print_stats(stats: CacheStats) -> Result<()> {
    let formatted = stats.get_stats().iter()
        .map(|s| (s.get_name(), if s.has_count() {
            format!("{}", s.get_count())
        } else if s.has_str() {
            s.get_str().to_owned()
        } else if s.has_size() {
            match binary_prefix(s.get_size() as f64) {
                Standalone(bytes) => format!("{} bytes", bytes),
                Prefixed(prefix, n) => format!("{:.0} {}B", n, prefix),
            }
        } else {
            String::from("???")
        }))
        .collect::<Vec<_>>();
    let name_width = formatted.iter().map(|&(n, _)| n.len()).max().unwrap();
    let stat_width = formatted.iter().map(|&(_, ref s)| s.len()).max().unwrap();
    for (name, stat) in formatted {
        println!("{:<name_width$} {:>stat_width$}", name, stat, name_width=name_width, stat_width=stat_width);
    }
    Ok(())
}

/// Send a `Compile` request to the server, and return the server response if successful.
fn request_compile<W: AsRef<Path>, X: AsRef<OsStr>, Y: AsRef<Path>>(conn: &mut ServerConnection, exe: W, args: &Vec<X>, cwd: Y) -> Result<CompileResponse> {
    //TODO: It'd be nicer to send these over as raw bytes.
    let exe = exe.as_ref().to_str().ok_or("bad exe")?;
    let cwd = cwd.as_ref().to_str().ok_or("bad cwd")?;
    let args = args.iter().filter_map(|a| a.as_ref().to_str().map(|s| s.to_owned())).collect::<Vec<_>>();
    if args.is_empty() {
        bail!("bad commandline")
    }
    let mut req = ClientRequest::new();
    let mut compile = Compile::new();
    compile.set_exe(exe.to_owned());
    compile.set_cwd(cwd.to_owned());
    compile.set_command(RepeatedField::from_vec(args));
    trace!("request_compile: {:?}", compile);
    req.set_compile(compile);
    //TODO: better error mapping?
    let mut response = conn.request(req).chain_err(|| {
        "Failed to send data to or receive data from server"
    })?;
    if response.has_compile_started() {
        Ok(CompileResponse::CompileStarted(response.take_compile_started()))
    } else if response.has_unhandled_compile() {
        Ok(CompileResponse::UnhandledCompile(response.take_unhandled_compile()))
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

/// Handle `response`, the output from running a compile on the server. Return the compiler exit status.
fn handle_compile_finished(response: CompileFinished,
                           stdout: &mut Write,
                           stderr: &mut Write) -> Result<i32> {
    trace!("handle_compile_finished");
    // It might be nice if the server sent stdout/stderr as the process
    // ran, but then it would have to also save them in the cache as
    // interleaved streams to really make it work.
    if response.has_stdout() {
        try!(stdout.write_all(response.get_stdout()));
    }
    if response.has_stderr() {
        try!(stderr.write_all(response.get_stderr()));
    }
    if response.has_retcode() {
        let ret = response.get_retcode();
        trace!("compiler exited with status {}", ret);
        Ok(ret)
    } else if response.has_signal() {
        println!("Compiler killed by signal {}", response.get_signal());
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
        CompileResponse::CompileStarted(_) => {
            debug!("Server sent CompileStarted");
            // Wait for CompileFinished.
            let mut res = conn.read_one_response().chain_err(|| {
                //TODO: something better here?
                "error reading compile response from server"
            })?;
            if res.has_compile_finished() {
                trace!("Server sent CompileFinished");
                handle_compile_finished(res.take_compile_finished(),
                                        stdout, stderr)
            } else {
                bail!("unexpected response from server")
            }
        }
        CompileResponse::UnhandledCompile(_) => {
            debug!("Server sent UnhandledCompile");
            //TODO: possibly capture output here for testing.
            let mut cmd = creator.new_command_sync(exe);
            cmd.args(&cmdline)
                .current_dir(cwd);
            if log_enabled!(Trace) {
                trace!("running command: {:?}", cmd);
            }
            let output = try!(core.run(run_input_output(cmd, None)));
            if !output.stdout.is_empty() {
                try!(stdout.write_all(&output.stdout));
            }
            if !output.stderr.is_empty() {
                try!(stderr.write_all(&output.stderr));
            }
            Ok(output.status.code()
               .unwrap_or_else(|| {
                   /* TODO: this breaks type inference, figure out why
                   status_signal(status)
                   .and_then(|sig : i32| {
                   println!("Compile terminated by signal {}", sig);
                   None
               });
                    */
                   // Arbitrary.
                   2
               }))
        }
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
                     stdout: &mut Write,
                     stderr: &mut Write) -> Result<i32>
    where T : CommandCreatorSync,
{
    trace!("do_compile");
    let exe_path = which_in(exe, path, &cwd)?;
    let res = request_compile(&mut conn, &exe_path, &cmdline, &cwd)?;
    handle_compile_response(creator, core, &mut conn, res, &exe_path, cmdline, cwd, stdout, stderr)
}

/// Run `cmd` and return the process exit status.
pub fn run_command(cmd: Command) -> Result<i32> {
    match cmd {
        Command::ShowStats => {
            trace!("Command::ShowStats");
            let srv = connect_or_start_server(get_port())?;
            let response = request_stats(srv).chain_err(|| {
                "failed to get stats from server"
            })?;
            print_stats(response)?;
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
                ServerStartup::Ok => {}
                ServerStartup::TimedOut => {
                    bail!("Timed out waiting for server startup")
                }
                ServerStartup::Err(e) => {
                    return Err(e).chain_err(|| "Server startup error")
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
            print_stats(stats)?
        }
        Command::Compile { exe, cmdline, cwd } => {
            trace!("Command::Compile {{ {:?}, {:?}, {:?} }}", exe, cmdline, cwd);
            let conn = connect_or_start_server(get_port())?;
            let mut core = Core::new()?;
            let res = do_compile(ProcessCommandCreator::new(&core.handle()),
                                 &mut core,
                                 conn,
                                 exe.as_ref(),
                                 cmdline,
                                 &cwd,
                                 env::var_os("PATH"),
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
            print_stats(stats)?
        }
    }

    Ok(0)
}
