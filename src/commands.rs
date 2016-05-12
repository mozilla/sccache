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

use client::{connect_to_server,connect_with_retry,ServerConnection};
use cmdline::Command;
use compiler::{
    ProcessOutput,
    run_compiler,
};
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
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
use std::io::{self,Error,ErrorKind,Write};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process;


/// The default sccache server port.
pub const DEFAULT_PORT : u16 = 4225;

/// Possible responses from the server for a `Compile` request.
enum CompileResponse {
    /// The compilation was started.
    CompileStarted(CompileStarted),
    /// The server could not handle this compilation request.
    UnhandledCompile(UnhandledCompile),
}

/// Pipe `cmd`'s stdio to `/dev/null`, unless a specific env var is set.
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
fn run_server_process() -> io::Result<()> {
    env::current_exe().and_then(|exe_path| {
        let mut cmd = process::Command::new(exe_path);
        maybe_redirect_stdio(&mut cmd);
        cmd.env("SCCACHE_START_SERVER", "1")
            .spawn()
    }).and(Ok(()))
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
fn connect_or_start_server(port : u16) -> io::Result<ServerConnection> {
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

/// Format `size_in_bytes` as a size in sensible units.
///
/// e.g. format_size(3 * 1024 * 1024 * 1024) == "3 GB"
fn format_size(size_in_bytes : u64) -> String {
    let mut size = size_in_bytes;
    let mut remainder = 0;
    for suffix in ["bytes", "kB", "MB", "GB", "TB"].iter() {
        if size < 1024 {
            let frac = if remainder > 0 {
                let rem = (100.0 * remainder as f32 / 1024.0).trunc() as i32;
                format!(".{}", if rem % 10 == 0 { rem / 10 } else { rem })
            } else {
                "".to_owned()
            };
            return format!("{}{} {}", size, frac, suffix);
        }
        remainder = size % 1024;
        size = size / 1024;
    }
    //TODO: handle this more gracefully
    return format!("{} {}", size, "PB");
}

/// Print `stats` to stdout.
fn print_stats(stats : CacheStats) -> io::Result<()> {
    for stat in stats.get_stats().iter() {
        //TODO: properly align output
        print!("{}\t\t", stat.get_name());
        if stat.has_count() {
            print!("{}", stat.get_count());
        } else if stat.has_str() {
            print!("{}", stat.get_str());
        } else if stat.has_size() {
            print!("{}", format_size(stat.get_size()));
        }
        print!("\n");
    }
    Ok(())
}

/// Send a `Compile` request to the server, and return the server response if successful.
fn request_compile(conn : &mut ServerConnection, cmdline : &Vec<String>, cwd : &str) -> io::Result<CompileResponse> {
    let mut req = ClientRequest::new();
    let mut compile = Compile::new();
    compile.set_cwd(cwd.to_owned());
    compile.set_command(RepeatedField::from_vec(cmdline.clone()));
    req.set_compile(compile);
    //TODO: better error mapping
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
    // It might be nice if the server sent stdout/stderr as the process
    // ran, but then it would have to also save them in the cache as
    // interleaved streams to really make it work.
    if response.has_stdout() {
        try!(stdout.write(response.get_stdout()));
    }
    if response.has_stderr() {
        try!(stderr.write(response.get_stderr()));
    }
    if response.has_retcode() {
        Ok(response.get_retcode())
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
fn handle_compile_response<T : CommandCreatorSync, U : Write, V : Write>(creator : T, conn : &mut ServerConnection, response : CompileResponse, cmdline : Vec<String>, cwd : &str, stdout : &mut U, stderr : &mut V) -> io::Result<i32> {
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
            run_compiler(creator, cmdline, cwd, ProcessOutput::Inherit)
                .and_then(|output| {
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
/// See `request_compile` and `handle_compile_response`.
pub fn do_compile<T : CommandCreatorSync, U : Write, V : Write>(creator : T, mut conn : ServerConnection, cmdline : Vec<String>, cwd : String, stdout : &mut U, stderr : &mut V) -> io::Result<i32> {
    request_compile(&mut conn, &cmdline, &cwd)
        .and_then(|res| handle_compile_response(creator, &mut conn, res, cmdline, &cwd, stdout, stderr))
}

/// Run `cmd` and return the process exit status.
pub fn run_command(cmd : Command) -> i32 {
    match cmd {
        // Actual usage gets printed in `cmdline::parse`.
        Command::Usage => 1,
        Command::ShowStats => {
            result_exit_code(connect_or_start_server(DEFAULT_PORT).and_then(request_stats).and_then(print_stats),
                             |e| {
                                 println!("Couldn't get stats from server: {}", e);
                             })
        },
        Command::InternalStartServer => {
            // Can't report failure here, we're already daemonized.
            result_exit_code(server::start_server(DEFAULT_PORT), |_| {})
        },
        Command::StartServer => {
            println!("Starting sccache server...");
            result_exit_code(run_server_process(), |e| {
                println!("failed to spawn server: {}", e);
            })
        },
        Command::StopServer => {
            println!("Stopping sccache server...");
            result_exit_code(connect_to_server(DEFAULT_PORT).and_then(request_shutdown).and_then(print_stats),
                             |_e| {
                                 //TODO: check if this was connection refused,
                                 // print error if not.
                                 println!("Couldn't connect to server");
                             })

        },
        Command::Compile { cmdline, cwd } => {
            connect_or_start_server(DEFAULT_PORT)
                .and_then(|conn| do_compile(ProcessCommandCreator, conn, cmdline, cwd, &mut io::stdout(), &mut io::stderr()))
                .unwrap_or_else(|e| {
                    println!("Failed to execute compile: {}", e);
                    1
                })
        },
    }
}

#[cfg(test)]
mod test {
    use super::format_size;

    #[test]
    fn test_format_size() {
        assert_eq!("10 bytes", format_size(10));
        assert_eq!("1023 bytes", format_size(1023));
        assert_eq!("1 kB", format_size(1024));
        assert_eq!("1.5 kB", format_size(1024 + 512));
        assert_eq!("1023.99 kB", format_size(1024 * 1024 - 1));
        assert_eq!("1 MB", format_size(1024 * 1024));
        assert_eq!("1 GB", format_size(1024 * 1024 * 1024));
        assert_eq!("1.25 GB", format_size(1024 * 1024 * (1024 + 256)));
        assert_eq!("3 GB", format_size(1024 * 1024 * 1024 * 3));
        assert_eq!("1 TB", format_size(1024 * 1024 * 1024 * 1024));
        assert_eq!("1 PB", format_size(1024 * 1024 * 1024 * 1024 * 1024));
    }
}
