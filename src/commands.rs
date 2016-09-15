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
};
use server;
use std::env;
use std::ffi::{OsStr,OsString};
use std::io::{
    self,
    Error,
    ErrorKind,
    Write,
};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{
    Path,
};
use std::process;
use which::which_in;

/// The default sccache server port.
pub const DEFAULT_PORT : u16 = 4226;

/// Possible responses from the server for a `Compile` request.
enum CompileResponse {
    /// The compilation was started.
    CompileStarted(CompileStarted),
    /// The server could not handle this compilation request.
    UnhandledCompile(UnhandledCompile),
}

/// Pipe `cmd`'s stdio to `/dev/null`, unless a specific env var is set.
#[cfg(not(windows))]
fn maybe_redirect_stdio(cmd : &mut process::Command) {
    if !match env::var("SCCACHE_NO_DAEMON") {
            Ok(val) => val == "1",
            Err(_) => false,
    } {
        cmd.stdin(process::Stdio::null())
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null());
    }
}

/// Re-execute the current executable as a background server.
#[cfg(not(windows))]
fn run_server_process() -> io::Result<()> {
    trace!("run_server_process");
    env::current_exe().and_then(|exe_path| {
        let mut cmd = process::Command::new(exe_path);
        maybe_redirect_stdio(&mut cmd);
        cmd.env("SCCACHE_START_SERVER", "1")
            .spawn()
    }).and(Ok(()))
}

/// Re-execute the current executable as a background server.
///
/// `std::process::Command` doesn't expose a way to create a
/// detatched process on Windows, so we have to roll our own.
#[cfg(windows)]
fn run_server_process() -> io::Result<()> {
    use kernel32;
    use std::io::Error;
    use std::os::windows::ffi::OsStrExt;
    use std::mem;
    use std::ptr;
    use winapi::minwindef::{TRUE,FALSE,LPVOID,DWORD};
    use winapi::processthreadsapi::{PROCESS_INFORMATION,STARTUPINFOW};
    use winapi::winbase::{CREATE_UNICODE_ENVIRONMENT,DETACHED_PROCESS,CREATE_NEW_PROCESS_GROUP};
    trace!("run_server_process");
    env::current_exe().and_then(|exe_path| {
        let mut exe = OsStr::new(&exe_path)
            .encode_wide()
            .chain(Some(0u16))
            .collect::<Vec<u16>>();
        // Collect existing env vars + one more into an environment block.
        let mut envp = {
            let mut v = vec!();
            for (key, val) in env::vars_os().chain(Some((OsString::from("SCCACHE_START_SERVER"), OsString::from("1")))) {
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
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    })
}

/// Convert `res` into a process exit code.
///
/// If `res` is `Ok`, return `0`, else call `else_func` and then
/// return 1.
fn result_exit_code<T : FnOnce(io::Error)>(res : io::Result<()>,
                                           else_func : T) -> i32 {
    res.and(Ok(0)).unwrap_or_else(|e| {
        else_func(e);
        1
    })
}

/// Attempt to connect to an sccache server listening on `port`, or start one if no server is running.
fn connect_or_start_server(port: u16) -> io::Result<ServerConnection> {
    trace!("connect_or_start_server({})", port);
    connect_to_server(port).or_else(|e| {
        //FIXME: this can sometimes hit a connection timed out?
        if e.kind() == io::ErrorKind::ConnectionRefused {
            // If the connection was refused we probably need to start
            // the server.
            run_server_process().and_then(|()| connect_with_retry(port))
        } else {
            debug!("Error: {}", e);
            Err(e)
        }
    })
}

/// Send a `GetStats` request to the server, and return the `CacheStats` request if successful.
pub fn request_stats(mut conn : ServerConnection) -> io::Result<CacheStats> {
    debug!("request_stats");
    let mut req = ClientRequest::new();
    req.set_get_stats(GetStats::new());
    //TODO: better error mapping
    let mut response = try!(conn.request(req).or(Err(Error::new(ErrorKind::Other, "Failed to send data to or receive data from server"))));
    if response.has_stats() {
        Ok(response.take_stats())
    } else {
        Err(Error::new(ErrorKind::Other, "Unexpected server response!"))
    }
}

/// Send a `Shutdown` request to the server, and return the `CacheStats` contained within the response if successful.
pub fn request_shutdown(mut conn : ServerConnection) -> io::Result<CacheStats> {
    debug!("request_shutdown");
    let mut req = ClientRequest::new();
    req.set_shutdown(Shutdown::new());
    //TODO: better error mapping
    let mut response = try!(conn.request(req).or(Err(Error::new(ErrorKind::Other, "Failed to send data to or receive data from server"))));
    if response.has_shutting_down() {
        Ok(response.take_shutting_down().take_stats())
    } else {
        Err(Error::new(ErrorKind::Other, "Unexpected server response!"))
    }
}

/// Print `stats` to stdout.
fn print_stats(stats: CacheStats) -> io::Result<()> {
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
fn request_compile<W: AsRef<Path>, X: AsRef<OsStr>, Y: AsRef<Path>>(conn: &mut ServerConnection, exe: W, args: &Vec<X>, cwd: Y) -> io::Result<CompileResponse> {
    //TODO: It'd be nicer to send these over as raw bytes.
    let exe = try!(exe.as_ref().to_str().ok_or(Error::new(ErrorKind::Other, "Bad exe")));
    let cwd = try!(cwd.as_ref().to_str().ok_or(Error::new(ErrorKind::Other, "Bad cwd")));
    let args = args.iter().filter_map(|a| a.as_ref().to_str().map(|s| s.to_owned())).collect::<Vec<_>>();
    if args.is_empty() {
        return Err(Error::new(ErrorKind::Other, "Bad commandline"));
    }
    let mut req = ClientRequest::new();
    let mut compile = Compile::new();
    compile.set_exe(exe.to_owned());
    compile.set_cwd(cwd.to_owned());
    compile.set_command(RepeatedField::from_vec(args));
    trace!("request_compile: {:?}", compile);
    req.set_compile(compile);
    //TODO: better error mapping?
    let mut response = try!(conn.request(req).or(Err(Error::new(ErrorKind::Other, "Failed to send data to or receive data from server"))));
    if response.has_compile_started() {
        Ok(CompileResponse::CompileStarted(response.take_compile_started()))
    } else if response.has_unhandled_compile() {
        Ok(CompileResponse::UnhandledCompile(response.take_unhandled_compile()))
    } else {
        Err(Error::new(ErrorKind::Other, "Unexpected response from server"))
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
fn handle_compile_finished<T : Write, U : Write>(response : CompileFinished, stdout : &mut T, stderr : &mut U) -> io::Result<i32> {
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
fn handle_compile_response<T, U, V, W, X, Y>(mut creator: T,
                                             conn: &mut ServerConnection,
                                             response: CompileResponse,
                                             exe: W,
                                             cmdline: Vec<X>,
                                             cwd: Y,
                                             stdout: &mut U,
                                             stderr: &mut V) -> io::Result<i32>
  where T : CommandCreatorSync, U : Write, V : Write, W: AsRef<OsStr>, X: AsRef<OsStr>, Y: AsRef<Path> {
    match response {
        CompileResponse::CompileStarted(_) => {
            debug!("Server sent CompileStarted");
            // Wait for CompileFinished.
            conn.read_one_response()
                .or_else(|err| {
                    //TODO: something better here?
                    error!("Error reading compile response from server: {}", err);
                    Err(Error::new(ErrorKind::Other, "Error reading compile response from server"))
                })
                .and_then(|mut res| {
                    if res.has_compile_finished() {
                        trace!("Server sent CompileFinished");
                        handle_compile_finished(res.take_compile_finished(),
                                                stdout, stderr)
                    } else {
                        Err(Error::new(ErrorKind::Other, "Unexpected response from server"))
                    }
                })
        }
        CompileResponse::UnhandledCompile(_) => {
            debug!("Server sent UnhandledCompile");
            //TODO: possibly capture output here for testing.
            let mut cmd = creator.new_command_sync(exe.as_ref());
            cmd.args(&cmdline)
                .current_dir(cwd.as_ref());
            if log_enabled!(Trace) {
                trace!("running command: {:?}", cmd);
            }
            run_input_output(cmd, None)
                .and_then(|output| {
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
                })
        }
    }
}

/// Send a `Compile` request to the sccache server `conn`, and handle the response.
///
/// The first entry in `cmdline` will be looked up in `path` if it is not
/// an absolute path.
/// See `request_compile` and `handle_compile_response`.
pub fn do_compile<T, U, V, W, X, Y>(creator: T,
                                    mut conn: ServerConnection,
                                    exe: W,
                                    cmdline: Vec<X>,
                                    cwd: Y,
                                    path: Option<OsString>,
                                    stdout: &mut U,
                                    stderr: &mut V) -> io::Result<i32>
  where T : CommandCreatorSync, U : Write, V : Write, W: AsRef<OsStr>, X: AsRef<OsStr>, Y: AsRef<Path> {
      trace!("do_compile");
    which_in(exe, path, &cwd)
          .map_err( |x: &'static str| Error::new(ErrorKind::Other, x))
          .and_then(|exe_path| {
              request_compile(&mut conn, &exe_path, &cmdline, &cwd)
                  .and_then(|res| handle_compile_response(creator, &mut conn, res, exe_path, cmdline, cwd, stdout, stderr))
          })
}

/// Run `cmd` and return the process exit status.
pub fn run_command(cmd : Command) -> i32 {
    match cmd {
        // Actual usage gets printed in `cmdline::parse`.
        Command::Usage => 0,
        Command::ShowStats => {
            trace!("Command::ShowStats");
            result_exit_code(connect_or_start_server(DEFAULT_PORT).and_then(request_stats).and_then(print_stats),
                             |e| {
                                 println!("Couldn't get stats from server: {}", e);
                             })
        },
        Command::InternalStartServer => {
            trace!("Command::InternalStartServer");
            // Can't report failure here, we're already daemonized.
            result_exit_code(server::start_server(DEFAULT_PORT), |_| {})
        },
        Command::StartServer => {
            trace!("Command::StartServer");
            println!("Starting sccache server...");
            result_exit_code(run_server_process(), |e| {
                println!("failed to spawn server: {}", e);
            })
        },
        Command::StopServer => {
            trace!("Command::StopServer");
            println!("Stopping sccache server...");
            result_exit_code(connect_to_server(DEFAULT_PORT).and_then(request_shutdown).and_then(print_stats),
                             |_e| {
                                 //TODO: check if this was connection refused,
                                 // print error if not.
                                 println!("Couldn't connect to server");
                             })

        },
        Command::Compile { exe, cmdline, cwd } => {
            trace!("Command::Compile {{ {:?}, {:?}, {:?} }}", exe, cmdline, cwd);
            connect_or_start_server(DEFAULT_PORT)
                .and_then(|conn| do_compile(ProcessCommandCreator, conn, &exe, cmdline, &cwd, env::var_os("PATH"), &mut io::stdout(), &mut io::stderr()))
                .unwrap_or_else(|e| {
                    println!("Failed to execute compile: {}", e);
                    1
                })
        },
    }
}
