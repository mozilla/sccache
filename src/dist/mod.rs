#![allow(non_camel_case_types, unused)]

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Mutex;

use bincode;

use futures::{Future, future};

use tar;

use tokio_core;

use compiler::CompileCommand;
use errors::*;
use mock_command::exit_status;

#[cfg(test)]
#[macro_use]
mod test;

// TODO: Clone by assuming immutable/no GC for now
// TODO: make fields non-public?
#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub struct Toolchain {
    pub docker_img: String,
    // TODO: this should be an ID the daemon server can request, not a path
    pub archive: PathBuf,
}

// process::Output is not serialize
#[derive(Serialize, Deserialize)]
pub struct ProcessOutput {
    code: Option<i32>, // TODO: extract the extra info from the UnixCommandExt
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl From<process::Output> for ProcessOutput {
    fn from(o: process::Output) -> Self {
        ProcessOutput { code: o.status.code(), stdout: o.stdout, stderr: o.stderr }
    }
}
impl From<ProcessOutput> for process::Output {
    fn from(o: ProcessOutput) -> Self {
        // TODO: handle signals, i.e. None code
        process::Output { status: exit_status(o.code.unwrap()), stdout: o.stdout, stderr: o.stderr }
    }
}

#[derive(Hash, Eq, PartialEq)]
struct JobId(u64);
struct DaemonId(u64);

const SCHEDULER_SERVERS_PORT: u16 = 10500;
const SCHEDULER_CLIENTS_PORT: u16 = 10501;
const SERVER_CLIENTS_PORT: u16 = 10502;

// TODO: make these fields not public

// TODO: any OsString or PathBuf shouldn't be sent across the wire
// from Windows

#[derive(Serialize, Deserialize)]
pub struct JobRequest {
    pub command: CompileCommand,
    pub inputs_archive: Vec<u8>,
    pub outputs: Vec<PathBuf>,
    pub toolchain: Toolchain,
}
#[derive(Serialize, Deserialize)]
pub struct JobResult {
    pub output: ProcessOutput,
    pub outputs: Vec<(PathBuf, Vec<u8>)>,
}

#[derive(Serialize, Deserialize)]
pub struct JobAllocRequest {
    pub toolchain: Toolchain,
}
#[derive(Serialize, Deserialize)]
pub struct JobAllocResult {
    addr: SocketAddr,
}

#[derive(Serialize, Deserialize)]
pub struct AllocAssignment;

#[derive(Serialize, Deserialize)]
pub struct BuildRequest(JobRequest);
#[derive(Serialize, Deserialize)]
pub struct BuildResult {
    output: ProcessOutput,
    outputs: Vec<(PathBuf, Vec<u8>)>,
}

trait SchedulerHandler {
    // From DaemonClient
    fn handle_allocation_request(&self, JobAllocRequest) -> SFuture<JobAllocResult>;
}
pub trait SchedulerRequester {
    // To DaemonServer
    fn do_allocation_assign(&self, usize, AllocAssignment) -> SFuture<()>;
}

// This protocol is part of non-distributed sccache
trait DaemonClientHandler {
}
pub trait DaemonClientRequester: Send + Sync {
    // To Scheduler
    fn do_allocation_request(&self, JobAllocRequest) -> SFuture<JobAllocResult>;
    // To DaemonServer
    fn do_compile_request(&self, JobAllocResult, JobRequest) -> SFuture<JobResult>;

    // TODO: It's more correct to have a FnBox or Box<FnOnce> here
    fn toolchain_cache(&self, create: &mut FnMut(fs::File)) -> PathBuf;
}

trait DaemonServerHandler {
    // From Scheduler
    fn handle_allocation_assign(&self, AllocAssignment) -> SFuture<()>;
    // From DaemonClient
    fn handle_compile_request(&self, JobRequest) -> SFuture<JobResult>;
}
pub trait DaemonServerRequester {
}

// TODO: this being public is asymmetric
pub trait BuilderHandler {
    // From DaemonServer
    fn handle_compile_request(&self, BuildRequest) -> SFuture<BuildResult>;
}

enum JobStatus {
    AllocRequested(JobAllocRequest),
    AllocSuccess(DaemonId, JobAllocRequest, JobAllocResult),
    JobStarted(DaemonId, JobAllocRequest, JobAllocResult),
    JobCompleted(DaemonId, JobAllocRequest, JobAllocResult),
    // Interrupted by some error in distributed sccache
    // or maybe a failure to allocate. Nothing to do with the
    // compilation itself.
    JobFailed(DaemonId, JobAllocRequest, JobAllocResult),
}

pub struct SccacheScheduler {
    jobs: HashMap<JobId, JobStatus>,

    // Acts as a ring buffer of most recently completed jobs
    finished_jobs: VecDeque<JobStatus>,

    servers: Vec<TcpStream>,
}

impl SccacheScheduler {
    pub fn new() -> Self {
        SccacheScheduler {
            jobs: HashMap::new(),
            finished_jobs: VecDeque::new(),
            servers: vec![],
        }
    }

    pub fn start(mut self) -> ! {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        assert!(self.servers.is_empty());
        {
            let listener = TcpListener::bind(("127.0.0.1", SCHEDULER_SERVERS_PORT)).unwrap();
            let conn = listener.accept().unwrap().0;
            self.servers.push(conn);
            assert!(self.servers.len() == 1);
        }
        loop {
            let listener = TcpListener::bind(("127.0.0.1", SCHEDULER_CLIENTS_PORT)).unwrap();
            let conn = listener.accept().unwrap().0;
            core.run(future::lazy(|| {
                let req = bincode::deserialize_from(&mut &conn, bincode::Infinite).unwrap();
                self.handle_allocation_request(req).and_then(|res| {
                    f_ok(bincode::serialize_into(&mut &conn, &res, bincode::Infinite).unwrap())
                })
            })).unwrap()
        }
    }
}

impl SchedulerHandler for SccacheScheduler {
    fn handle_allocation_request(&self, req: JobAllocRequest) -> SFuture<JobAllocResult> {
        assert!(self.servers.len() == 1);
        self.do_allocation_assign(0, AllocAssignment);
        let ip_addr = self.servers[0].peer_addr().unwrap().ip();
        f_ok(JobAllocResult { addr: SocketAddr::new(ip_addr, SERVER_CLIENTS_PORT) })
    }
}
impl SchedulerRequester for SccacheScheduler {
    fn do_allocation_assign(&self, server_id: usize, req: AllocAssignment) -> SFuture<()> {
        f_ok(bincode::serialize_into(&mut &self.servers[0], &req, bincode::Infinite).unwrap())
    }
}

// TODO: possibly shouldn't be public
pub struct SccacheDaemonClient {
    cache_mutex: Mutex<()>,
}

impl SccacheDaemonClient {
    pub fn new() -> Self {
        SccacheDaemonClient {
            cache_mutex: Mutex::new(()),
        }
    }
}

impl DaemonClientHandler for SccacheDaemonClient {
}
impl DaemonClientRequester for SccacheDaemonClient {
    fn do_allocation_request(&self, req: JobAllocRequest) -> SFuture<JobAllocResult> {
        Box::new(future::lazy(move || -> SFuture<JobAllocResult> {
            let conn = TcpStream::connect(("127.0.0.1", SCHEDULER_CLIENTS_PORT)).unwrap();
            bincode::serialize_into(&mut &conn, &req, bincode::Infinite).unwrap();
            f_ok(bincode::deserialize_from(&mut &conn, bincode::Infinite).unwrap())
        }))
    }
    fn do_compile_request(&self, ja_res: JobAllocResult, req: JobRequest) -> SFuture<JobResult> {
        Box::new(future::lazy(move || -> SFuture<JobResult> {
            let conn = TcpStream::connect(ja_res.addr).unwrap();
            bincode::serialize_into(&mut &conn, &req, bincode::Infinite).unwrap();
            f_ok(bincode::deserialize_from(&mut &conn, bincode::Infinite).unwrap())
        }))
    }

    fn toolchain_cache(&self, create: &mut FnMut(fs::File)) -> PathBuf {
        {
            let _l = self.cache_mutex.lock();
            if !Path::new("/tmp/sccache_rust_cache.tar").exists() {
                let file = fs::OpenOptions::new()
                    .create_new(true)
                    .append(true)
                    .open("/tmp/sccache_rust_cache.tar");
                match file {
                    Ok(f) => create(f),
                    Err(e) => panic!("{}", e),
                }
            }
        }
        "/tmp/sccache_rust_cache.tar".into()
    }
}

pub struct SccacheDaemonServer {
    builder: Box<BuilderHandler>,
    sched_conn: TcpStream,
}

impl SccacheDaemonServer {
    pub fn new(builder: Box<BuilderHandler>) -> SccacheDaemonServer {
        SccacheDaemonServer { builder, sched_conn: TcpStream::connect(("127.0.0.1", SCHEDULER_SERVERS_PORT)).unwrap() }
    }

    pub fn start(self) -> ! {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        loop {
            let req = bincode::deserialize_from(&mut &self.sched_conn, bincode::Infinite).unwrap();
            let () = core.run(self.handle_allocation_assign(req)).unwrap();
            let listener = TcpListener::bind(("127.0.0.1", SERVER_CLIENTS_PORT)).unwrap();
            let conn = listener.accept().unwrap().0;
            core.run(future::lazy(|| {
                let req = bincode::deserialize_from(&mut &conn, bincode::Infinite).unwrap();
                self.handle_compile_request(req).and_then(|res| {
                    f_ok(bincode::serialize_into(&mut &conn, &res, bincode::Infinite).unwrap())
                })
            })).unwrap()
        }
    }
}

impl DaemonServerHandler for SccacheDaemonServer {
    fn handle_allocation_assign(&self, alloc: AllocAssignment) -> SFuture<()> {
        // TODO: track ID of incoming job so scheduler is kept up-do-date
        f_ok(())
    }
    fn handle_compile_request(&self, req: JobRequest) -> SFuture<JobResult> {
        Box::new(self.builder.handle_compile_request(BuildRequest(req)).map(|res| JobResult { output: res.output, outputs: res.outputs }))
    }
}
impl DaemonServerRequester for SccacheDaemonServer {
}

pub struct SccacheBuilder;

impl SccacheBuilder {
    pub fn new() -> SccacheBuilder {
        SccacheBuilder
    }
}

impl BuilderHandler for SccacheBuilder {
    // From DaemonServer
    fn handle_compile_request(&self, req: BuildRequest) -> SFuture<BuildResult> {
        let BuildRequest(job_req) = req;
        let command = job_req.command;
        let cache_dir = Path::new("/tmp/sccache_rust_cache");
        if cache_dir.is_dir() {
            fs::remove_dir_all("/tmp/sccache_rust_cache").unwrap();
        }
        let rel_cwd = command.cwd.strip_prefix("/").unwrap().to_str().unwrap();
        let cwd = command.cwd.to_str().unwrap();
        info!("{:?}", command.env_vars);
        info!("{:?} {:?}", command.executable, command.arguments);

        let cid = {
            let mut cmd = Command::new("docker");
            cmd.args(&["create", "-w", cwd]);
            for (k, v) in command.env_vars {
                let mut env = k;
                env.push("=");
                env.push(v);
                cmd.arg("-e").arg(env);
            }
            cmd.arg(job_req.toolchain.docker_img);
            cmd.arg(command.executable.to_str().unwrap());
            cmd.args(command.arguments);
            let output = cmd.output().unwrap();
            if !output.status.success() {
                error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
                    String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
                panic!()
            }
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };

        error!("copying in toolchain");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut fs::File::open(job_req.toolchain.archive).unwrap(), &mut process.stdin.take().unwrap());
        let output = process.wait_with_output().unwrap();
        if !output.status.success() {
            error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            panic!()
        }

        error!("copying in build dir");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut job_req.inputs_archive.as_slice(), &mut process.stdin.take().unwrap());
        let output = process.wait_with_output().unwrap();
        if !output.status.success() {
            error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            panic!()
        }

        let compile_output = Command::new("docker").args(&["start", "-a", &cid]).output().unwrap();
        println!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        error!("retrieving {:?}", job_req.outputs);
        for path in job_req.outputs {
            let path = command.cwd.join(path); // Resolve in case it's relative
            let output = Command::new("docker").args(&["cp", &format!("{}:{}", cid, path.to_str().unwrap()), "-"]).output().unwrap();
            if !output.status.success() {
                error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
                    String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
                panic!()
            }
            outputs.push((path, output.stdout))
        }

        let output = Command::new("docker").args(&["rm", "-f", &cid]).output().unwrap();
        if !output.status.success() {
            error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            panic!()
        }

        f_ok(BuildResult { output: compile_output.into(), outputs })
    }
}
