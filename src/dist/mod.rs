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

#![allow(non_camel_case_types)]

use compiler;
use config::CONFIG;
use dist::cache::TcCache;
use lru_disk_cache::Error as LruError;
use mock_command::exit_status;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use errors::*;

mod cache;
pub mod http;
#[cfg(test)]
mod test;

// TODO: Clone by assuming immutable/no GC for now
// TODO: make fields non-public?
#[derive(Debug, Hash, Eq, PartialEq)]
#[derive(Clone, Serialize, Deserialize)]
pub struct Toolchain {
    pub docker_img: String,
    pub archive_id: String,
}

#[derive(Hash, Eq, PartialEq)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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
pub struct ServerId(SocketAddr);
impl ServerId {
    fn addr(&self) -> SocketAddr {
        self.0
    }
}

const MAX_PER_CORE_LOAD: f64 = 10f64;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
pub struct JobAlloc {
    job_id: JobId,
    server_id: ServerId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum AllocJobResult {
    Success { job_alloc: JobAlloc, need_toolchain: bool },
    Fail { msg: String },
}

// AssignJob

#[derive(Clone, Serialize, Deserialize)]
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
#[serde(tag = "status")]
pub enum RunJobResult {
    JobNotFound,
    Complete(JobComplete),
}
#[derive(Clone, Serialize, Deserialize)]
pub struct JobComplete {
    pub output: ProcessOutput,
    pub outputs: Vec<(String, Vec<u8>)>,
}

// Status

#[derive(Clone, Serialize, Deserialize)]
pub struct StatusResult {
    num_servers: usize,
}

// SubmitToolchain

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
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

pub struct InputsReader<'a>(Box<Read + 'a>);
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
    fn run_build(&self, toolchain: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, cache: Arc<Mutex<TcCache>>) -> Result<BuildResult>;
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

    servers: Arc<Mutex<HashMap<ServerId, ServerDetails>>>,
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
            servers: Arc::new(Mutex::new(HashMap::new())),
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
    cache: Arc<Mutex<TcCache>>,
    job_toolchains: Mutex<HashMap<JobId, Toolchain>>,
}

impl Server {
    pub fn new(builder: Box<BuilderIncoming>) -> Server {
        Server {
            builder,
            cache: Arc::new(Mutex::new(TcCache::new(&CONFIG.dist.cache_dir.join("server")).unwrap())),
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
        let res = self.builder.run_build(tc, command, outputs, inputs_rdr, self.cache.clone()).unwrap();
        requester.do_update_job_status(job_id, JobStatus::Complete).unwrap();
        Ok(RunJobResult::Complete(JobComplete { output: res.output, outputs: res.outputs }))
    }
}

pub struct Builder {
    image_map: Arc<Mutex<HashMap<Toolchain, String>>>,
    container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
}

fn check_output(output: &Output) {
    if !output.status.success() {
        error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
}

impl Builder {
    pub fn new() -> Builder {
        Self::cleanup();
        Builder {
            image_map: Arc::new(Mutex::new(HashMap::new())),
            container_lists: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup() {
        info!("Performing initial Docker cleanup");

        let containers = {
            let output = Command::new("docker").args(&["ps", "-a", "--format", "{{.ID}} {{.Image}}"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        if containers != "" {
            let mut containers_to_rm = vec![];
            for line in containers.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let container_id = iter.next().unwrap();
                let image_name = iter.next().unwrap();
                if iter.next() != None { panic!() }
                if image_name.starts_with("sccache-builder-") {
                    containers_to_rm.push(container_id)
                }
            }
            if !containers_to_rm.is_empty() {
                let output = Command::new("docker").args(&["rm", "-f"]).args(containers_to_rm).output().unwrap();
                check_output(&output)
            }
        }

        let images = {
            let output = Command::new("docker").args(&["images", "--format", "{{.ID}} {{.Repository}}"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        if images != "" {
            let mut images_to_rm = vec![];
            for line in images.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let image_id = iter.next().unwrap();
                let image_name = iter.next().unwrap();
                if iter.next() != None { panic!() }
                if image_name.starts_with("sccache-builder-") {
                    images_to_rm.push(image_id)
                }
            }
            if !images_to_rm.is_empty() {
                let output = Command::new("docker").args(&["rmi"]).args(images_to_rm).output().unwrap();
                check_output(&output)
            }
        }

        info!("Completed initial Docker cleanup");
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Docker image along
    // the way)
    fn get_container(image_map: &Mutex<HashMap<Toolchain, String>>, container_lists: &Mutex<HashMap<Toolchain, Vec<String>>>, tc: &Toolchain, cache: Arc<Mutex<TcCache>>) -> String {
        let container = {
            let mut map = container_lists.lock().unwrap();
            map.entry(tc.clone()).or_insert_with(Vec::new).pop()
        };
        match container {
            Some(cid) => cid,
            None => {
                // TODO: can improve parallelism (of creating multiple images at a time) by using another
                // (more fine-grained) mutex around the entry value and checking if its empty a second time
                let image = {
                    let mut map = image_map.lock().unwrap();
                    map.entry(tc.clone()).or_insert_with(|| {
                        info!("Creating Docker image for {:?} (may block requests)", tc);
                        Self::make_image(tc, cache)
                    }).clone()
                };
                Self::start_container(&image)
            },
        }
    }

    fn finish_container(container_lists: &Mutex<HashMap<Toolchain, Vec<String>>>, tc: &Toolchain, cid: String) {
        // Clean up any running processes
        let output = Command::new("docker").args(&["exec", &cid, "/busybox", "kill", "-9", "-1"]).output().unwrap();
        check_output(&output);

        // Check the diff and clean up the FS
        fn dodiff(cid: &str) -> String {
            let output = Command::new("docker").args(&["diff", cid]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        }
        let diff = dodiff(&cid);
        if diff != "" {
            let mut shoulddelete = false;
            let mut lastpath = None;
            for line in diff.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let changetype = iter.next().unwrap();
                let changepath = iter.next().unwrap();
                if iter.next() != None { panic!() }
                // TODO: If files are created in this dir, it gets marked as modified.
                // A similar thing applies to /root or /build etc
                if changepath == "/tmp" {
                    continue
                }
                if changetype != "A" {
                    warn!("Deleting container {}: path {} had a non-A changetype of {}", &cid, changepath, changetype);
                    shoulddelete = true;
                    break
                }
                // Docker diff paths are in alphabetical order and we do `rm -rf`, so we might be able to skip
                // calling Docker more than necessary (since it's slow)
                if let Some(lastpath) = lastpath {
                    if Path::new(changepath).starts_with(lastpath) {
                        continue
                    }
                }
                lastpath = Some(changepath.clone());
                let output = Command::new("docker").args(&["exec", &cid, "/busybox", "rm", "-rf", changepath]).output().unwrap();
                check_output(&output);
            }

            let newdiff = dodiff(&cid);
            // See note about changepath == "/tmp" above
            if !shoulddelete && newdiff != "" && newdiff != "C /tmp" {
                warn!("Deleted files, but container still has a diff: {:?}", newdiff);
                shoulddelete = true
            }

            if shoulddelete {
                let output = Command::new("docker").args(&["rm", "-f", &cid]).output().unwrap();
                check_output(&output);
                return
            }
        }

        // Good as new, add it back to the container list
        trace!("Reclaimed container");
        container_lists.lock().unwrap().get_mut(&tc).unwrap().push(cid);
    }

    fn make_image(tc: &Toolchain, cache: Arc<Mutex<TcCache>>) -> String {
        let cid = {
            let output = Command::new("docker").args(&["create", &tc.docker_img, "/busybox", "true"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };

        let mut toolchain_cache = cache.lock().unwrap();
        let toolchain_reader = match toolchain_cache.get(&tc.archive_id) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => panic!("expected toolchain, but not available"),
            Err(e) => panic!("{}", e),
        };

        trace!("Copying in toolchain");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut {toolchain_reader}, &mut process.stdin.take().unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        check_output(&output);

        let imagename = format!("sccache-builder-{}", &tc.archive_id);
        let output = Command::new("docker").args(&["commit", &cid, &imagename]).output().unwrap();
        check_output(&output);

        let output = Command::new("docker").args(&["rm", "-f", &cid]).output().unwrap();
        check_output(&output);

        imagename
    }

    fn start_container(image: &str) -> String {
        // Make sure sh doesn't exec the final command, since we need it to do
        // init duties (reaping zombies). Also, because we kill -9 -1, that kills
        // the sleep (it's not a builtin) so it needs to be a loop.
        let output = Command::new("docker")
            .args(&["run", "-d", image, "/busybox", "sh", "-c", "while true; do /busybox sleep 365d && /busybox true; done"]).output().unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned()
    }

    fn perform_build(compile_command: CompileCommand, inputs_rdr: InputsReader, output_paths: Vec<String>, cid: &str) -> BuildResult {
        let cwd = PathBuf::from(compile_command.cwd);

        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        trace!("copying in build dir");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut {inputs_rdr}, &mut process.stdin.take().unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        check_output(&output);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", cid, "/busybox", "mkdir", "-p"]).arg(&cwd);
        for path in output_paths.iter() {
            cmd.arg(cwd.join(Path::new(path).parent().unwrap()));
        }
        let output = cmd.output().unwrap();
        check_output(&output);

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in compile_command.env_vars {
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = format!("cd \"$1\" && shift && exec \"$@\"");
        cmd.args(&[cid, "/busybox", "sh", "-c", &shell_cmd]);
        cmd.arg(&compile_command.executable);
        cmd.arg(&cwd);
        cmd.arg(compile_command.executable);
        cmd.args(compile_command.arguments);
        let compile_output = cmd.output().unwrap();
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let dockerpath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker").args(&["exec", cid, "/busybox", "cat"]).arg(dockerpath).output().unwrap();
            if output.status.success() {
                outputs.push((path, output.stdout))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        BuildResult { output: compile_output.into(), outputs }
    }
}

impl BuilderIncoming for Builder {
    // From Server
    fn run_build(&self, tc: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, cache: Arc<Mutex<TcCache>>) -> Result<BuildResult> {
        let image_map = self.image_map.clone();
        let container_lists = self.container_lists.clone();

        debug!("Finding container");
        let cid = Self::get_container(&image_map, &container_lists, &tc, cache);
        debug!("Performing build with container {}", cid);
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid);
        debug!("Finishing with container {}", cid);
        Self::finish_container(&container_lists, &tc, cid);
        debug!("Returning result");
        Ok(res)
    }
}
