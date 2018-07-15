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

use compiler;
use config::CONFIG;
use dist::cache::TcCache;
use mock_command::exit_status;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::sync::{Mutex};
use std::time::Instant;

use errors::*;

pub mod build;
mod cache;
pub mod http;
#[cfg(test)]
mod test;

// TODO: Clone by assuming immutable/no GC for now
// TODO: make fields non-public?
// TODO: remove docker_img
// TODO: make archive_id validate that it's just a bunch of hex chars
#[derive(Debug, Hash, Eq, PartialEq)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub docker_img: String,
    pub archive_id: String,
}

#[derive(Hash, Eq, PartialEq)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobId(u64);
impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for JobId {
    type Err = <u64 as FromStr>::Err;
    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        u64::from_str(s).map(JobId)
    }
}
#[derive(Hash, Eq, PartialEq)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerId(SocketAddr);
impl ServerId {
    fn addr(&self) -> SocketAddr {
        self.0
    }
}

const MAX_PER_CORE_LOAD: f64 = 10f64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub cwd: String,
}
// TODO: TryFrom
impl CompileCommand {
    pub fn try_from_compiler(command: compiler::CompileCommand) -> Option<Self> {
        let compiler::CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = command;
        Some(Self {
            executable: executable.into_os_string().into_string().ok()?,
            arguments: arguments.into_iter().map(|arg| arg.into_string().ok()).collect::<Option<_>>()?,
            env_vars: env_vars.into_iter()
                .map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .collect::<Option<_>>()?,
            cwd: cwd.into_os_string().into_string().ok()?,
        })
    }
}

// process::Output is not serialize
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

// TODO: standardise on compressed or not for inputs and toolchain

// TODO: make fields not public

// AllocJob

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobAlloc {
    job_id: JobId,
    server_id: ServerId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AllocJobResult {
    Success { job_alloc: JobAlloc, need_toolchain: bool },
    Fail { msg: String },
}

// AssignJob

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignJobResult {
    need_toolchain: bool,
}

// JobStatus

pub enum JobStatus {
    Pending,
    Started,
    Complete,
}
#[derive(Clone)]
pub struct UpdateJobStatusResult;

// HeartbeatServer

#[derive(Clone)]
pub struct HeartbeatServerResult;

// RunJob

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RunJobResult {
    JobNotFound,
    Complete(JobComplete),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobComplete {
    pub output: ProcessOutput,
    pub outputs: Vec<(String, Vec<u8>)>,
}

// Status

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResult {
    num_servers: usize,
}

// SubmitToolchain

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SubmitToolchainResult {
    Success,
    JobNotFound,
    CannotCache,
}

///////////////////

// BuildResult

pub struct BuildResult {
    output: ProcessOutput,
    outputs: Vec<(String, Vec<u8>)>,
}

///////////////////

// TODO: it's unfortunate all these are public, but in order to describe the trait
// bound on the instance (e.g. scheduler) we pass to the actual communication (e.g.
// http implementation) they need to be public, which has knock-on effects for private
// structs

pub struct ToolchainReader<'a>(Box<Read + 'a>);
impl<'a> Read for ToolchainReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read(buf) }
}

pub struct InputsReader<'a>(Box<Read + Send + 'a>);
impl<'a> Read for InputsReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read(buf) }
}

pub trait SchedulerOutgoing {
    // To Server
    fn do_assign_job(&self, server_id: ServerId, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult>;
}

pub trait ServerOutgoing {
    // To Scheduler
    fn do_update_job_status(&self, job_id: JobId, status: JobStatus) -> Result<UpdateJobStatusResult>;
}

pub trait SchedulerIncoming: Send + Sync {
    // From Client
    fn handle_alloc_job(&self, requester: &SchedulerOutgoing, tc: Toolchain) -> Result<AllocJobResult>;
    // From Server
    fn handle_heartbeat_server(&self, server_id: ServerId, num_cpus: usize) -> Result<HeartbeatServerResult>;
    // From anyone
    fn handle_status(&self) -> Result<StatusResult>;
}

pub trait ServerIncoming: Send + Sync {
    // From Scheduler
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult>;
    // From Client
    fn handle_submit_toolchain(&self, requester: &ServerOutgoing, job_id: JobId, tc_rdr: ToolchainReader) -> Result<SubmitToolchainResult>;
    // From Client
    fn handle_run_job(&self, requester: &ServerOutgoing, job_id: JobId, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader) -> Result<RunJobResult>;
}

pub trait BuilderIncoming: Send + Sync {
    // From Server
    // TODO: outputs should be a vec of some pre-sanitised AbsPath type
    fn run_build(&self, toolchain: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, cache: &Mutex<TcCache>) -> Result<BuildResult>;
}

/////////

pub trait Client {
    // To Scheduler
    fn do_alloc_job(&self, tc: Toolchain) -> SFuture<AllocJobResult>;
    // To Server
    fn do_submit_toolchain(&self, job_alloc: JobAlloc, tc: Toolchain) -> SFuture<SubmitToolchainResult>;
    // To Server
    // TODO: ideally Box<FnOnce or FnBox
    fn do_run_job(&self, job_alloc: JobAlloc, command: CompileCommand, outputs: Vec<PathBuf>, write_inputs: Box<FnMut(&mut Write)>) -> SFuture<RunJobResult>;

    fn put_toolchain_cache(&self, weak_key: &str, create: &mut FnMut(fs::File)) -> Result<String>;
}

/////////

pub struct NoopClient;

impl Client for NoopClient {
    fn do_alloc_job(&self, _tc: Toolchain) -> SFuture<AllocJobResult> {
        f_ok(AllocJobResult::Fail { msg: "Using NoopClient".to_string() })
    }
    fn do_submit_toolchain(&self, _job_alloc: JobAlloc, _tc: Toolchain) -> SFuture<SubmitToolchainResult> {
        panic!("NoopClient");
    }
    fn do_run_job(&self, _job_alloc: JobAlloc, _command: CompileCommand, _outputs: Vec<PathBuf>, _write_inputs: Box<FnMut(&mut Write)>) -> SFuture<RunJobResult> {
        panic!("NoopClient");
    }

    fn put_toolchain_cache(&self, _weak_key: &str, _create: &mut FnMut(fs::File)) -> Result<String> {
        panic!("NoopClient");
    }
}

//enum JobState {
//    AllocRequested(AllocJobRequest),
//    AllocSuccess(ServerId, AllocJobRequest, AllocJobResult),
//    JobStarted(ServerId, AllocJobRequest, AllocJobResult),
//    JobCompleted(ServerId, AllocJobRequest, AllocJobResult),
//    // Interrupted by some error in distributed sccache
//    // or maybe a failure to allocate. Nothing to do with the
//    // compilation itself.
//    JobFailed(ServerId, AllocJobRequest, AllocJobResult),
//}

pub struct Scheduler {
    job_count: Mutex<u64>,
    //jobs: HashMap<JobId, JobState>,

    // Acts as a ring buffer of most recently completed jobs
    finished_jobs: VecDeque<JobStatus>,

    servers: Mutex<HashMap<ServerId, ServerDetails>>,
}

struct ServerDetails {
    jobs_assigned: usize,
    last_seen: Instant,
    num_cpus: usize,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            job_count: Mutex::new(0),
            //jobs: HashMap::new(),
            finished_jobs: VecDeque::new(),
            servers: Mutex::new(HashMap::new()),
        }
    }
}

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(&self, requester: &SchedulerOutgoing, tc: Toolchain) -> Result<AllocJobResult> {
        // TODO: prune old servers
        let server_id = {
            let servers = self.servers.lock().unwrap();
            let mut best = None;
            let mut best_load: f64 = MAX_PER_CORE_LOAD;
            for (id, details) in servers.iter() {
                let load = details.jobs_assigned as f64 / details.num_cpus as f64;
                if load < best_load {
                    best = Some(id);
                    best_load = load;
                    if load == 0f64 {
                        break
                    }
                }
            }
            if let Some(id) = best {
                *id
            } else {
                let msg = format!("Insufficient capacity: {} available servers", servers.len());
                return Ok(AllocJobResult::Fail { msg })
            }
        };
        let job_id = {
            let mut job_count = self.job_count.lock().unwrap();
            let job_id = JobId(*job_count);
            *job_count += 1;
            job_id
        };
        let AssignJobResult { need_toolchain } = requester.do_assign_job(server_id, job_id, tc).unwrap();
        let job_alloc = JobAlloc { job_id, server_id };
        Ok(AllocJobResult::Success { job_alloc, need_toolchain })
    }
    fn handle_status(&self) -> Result<StatusResult> {
        Ok(StatusResult {
            num_servers: self.servers.lock().unwrap().len(),
        })
    }

    fn handle_heartbeat_server(&self, server_id: ServerId, num_cpus: usize) -> Result<HeartbeatServerResult> {
        if num_cpus == 0 {
            return Err("invalid heartbeat num_cpus".into())
        }
        self.servers.lock().unwrap().entry(server_id)
            .and_modify(|details| details.last_seen = Instant::now())
            .or_insert_with(|| {
                info!("Registered new server {:?}", server_id);
                ServerDetails { jobs_assigned: 0, num_cpus, last_seen: Instant::now() }
            });
        Ok(HeartbeatServerResult)
    }
}

pub struct Server {
    builder: Box<BuilderIncoming>,
    cache: Mutex<TcCache>,
    job_toolchains: Mutex<HashMap<JobId, Toolchain>>,
}

impl Server {
    pub fn new(builder: Box<BuilderIncoming>) -> Server {
        Server {
            builder,
            cache: Mutex::new(TcCache::new(&CONFIG.dist.cache_dir.join("server")).unwrap()),
            job_toolchains: Mutex::new(HashMap::new()),
        }
    }
}

impl ServerIncoming for Server {
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_key(&tc.archive_id);
        assert!(self.job_toolchains.lock().unwrap().insert(job_id, tc).is_none());
        if !need_toolchain {
            // TODO: can start prepping the container now
        }
        Ok(AssignJobResult { need_toolchain })
    }
    fn handle_submit_toolchain(&self, requester: &ServerOutgoing, job_id: JobId, tc_rdr: ToolchainReader) -> Result<SubmitToolchainResult> {
        requester.do_update_job_status(job_id, JobStatus::Started).unwrap();
        // TODO: need to lock the toolchain until the container has started
        // TODO: can start prepping container
        let tc = match self.job_toolchains.lock().unwrap().get(&job_id).cloned() {
            Some(tc) => tc,
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        let mut cache = self.cache.lock().unwrap();
        // TODO: this returns before reading all the data, is that valid?
        if cache.contains_key(&tc.archive_id) {
            return Ok(SubmitToolchainResult::Success)
        }
        Ok(cache.insert_with(&tc.archive_id, |mut file| io::copy(&mut {tc_rdr}, &mut file).map(|_| ()))
            .map(|_| SubmitToolchainResult::Success)
            .unwrap_or(SubmitToolchainResult::CannotCache))
    }
    fn handle_run_job(&self, requester: &ServerOutgoing, job_id: JobId, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader) -> Result<RunJobResult> {
        let tc = match self.job_toolchains.lock().unwrap().remove(&job_id) {
            Some(tc) => tc,
            None => return Ok(RunJobResult::JobNotFound),
        };
        let res = self.builder.run_build(tc, command, outputs, inputs_rdr, &self.cache).unwrap();
        requester.do_update_job_status(job_id, JobStatus::Complete).unwrap();
        Ok(RunJobResult::Complete(JobComplete { output: res.output, outputs: res.outputs }))
    }
}
