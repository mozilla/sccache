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
use std::fmt;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::ffi::OsString;
use std::path::Path;
use std::process;
use std::str::FromStr;
#[cfg(feature = "dist-server")]
use std::sync::Mutex;

use errors::*;

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
mod cache;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub mod http;
#[cfg(test)]
mod test;

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
pub use dist::cache::TcCache;

// TODO: paths (particularly outputs, which are accessed by an unsandboxed program)
// should be some pre-sanitised AbsPath type

pub use self::path_transform::PathTransformer;

#[cfg(feature = "dist-client")]
pub mod pkg;
#[cfg(not(feature = "dist-client"))]
mod pkg {
    pub trait ToolchainPackager {}
    pub trait InputsPackager {}
}

#[cfg(target_os = "windows")]
mod path_transform {
    use std::collections::HashMap;
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::str;

    pub struct PathTransformer {
        dist_to_local_path: HashMap<String, PathBuf>,
    }

    impl PathTransformer {
        pub fn new() -> Self {
            PathTransformer {
                dist_to_local_path: HashMap::new(),
            }
        }
        pub fn to_dist_assert_abs(&mut self, p: &Path) -> Option<String> {
            if !p.is_absolute() { panic!("non absolute path {:?}", p) }
            self.to_dist(p)
        }
        pub fn to_dist(&mut self, p: &Path) -> Option<String> {
            let mut components = p.components();

            let maybe_dist_prefix = if p.is_absolute() {
                let prefix = components.next().unwrap();
                let dist_prefix = match prefix {
                    Component::Prefix(pc) => {
                        match pc.kind() {
                            // Transforming these to the same place means these may flip-flop
                            // in the tracking map, but they're equivalent so not really an
                            // issue
                            Prefix::Disk(diskchar) |
                            Prefix::VerbatimDisk(diskchar) => {
                                assert!(diskchar.is_ascii_alphabetic());
                                format!("disk-{}", str::from_utf8(&[diskchar]).unwrap())
                            },
                            Prefix::Verbatim(_) |
                            Prefix::VerbatimUNC(_, _) |
                            Prefix::DeviceNS(_) |
                            Prefix::UNC(_, _) => return None,
                        }
                    },
                    _ => panic!("unrecognised start to path {:?}", p),
                };

                let root = components.next().unwrap();
                if root != Component::RootDir { panic!("unexpected non-root component in {:?}", p) }

                Some(dist_prefix)
            } else {
                None
            };

            let mut dist_suffix = String::new();
            for component in components {
                let part = match component {
                    Component::Prefix(_) |
                    Component::RootDir => panic!("unexpected part in path {:?}", p),
                    Component::Normal(osstr) => osstr.to_str()?,
                    // TODO: should be forbidden
                    Component::CurDir => ".",
                    Component::ParentDir => "..",
                };
                if !dist_suffix.is_empty() {
                    dist_suffix.push('/')
                }
                dist_suffix.push_str(part)
            }

            let dist_path = if let Some(dist_prefix) = maybe_dist_prefix {
                format!("/prefix/{}/{}", dist_prefix, dist_suffix)
            } else {
                dist_suffix
            };
            self.dist_to_local_path.insert(dist_path.clone(), p.to_owned());
            Some(dist_path)
        }
        pub fn to_local(&self, p: &str) -> PathBuf {
            self.dist_to_local_path.get(p).unwrap().clone()
        }
    }
}

#[cfg(unix)]
mod path_transform {
    use std::path::{Path, PathBuf};

    pub struct PathTransformer;

    impl PathTransformer {
        pub fn new() -> Self { PathTransformer }
        pub fn to_dist_assert_abs(&mut self, p: &Path) -> Option<String> {
            if !p.is_absolute() { panic!("non absolute path {:?}", p) }
            self.to_dist(p)
        }
        pub fn to_dist(&mut self, p: &Path) -> Option<String> {
            p.as_os_str().to_str().map(Into::into)
        }
        pub fn to_local(&self, p: &str) -> PathBuf {
            PathBuf::from(p)
        }
    }
}

pub fn osstrings_to_strings(osstrings: &[OsString]) -> Option<Vec<String>> {
    osstrings.into_iter().map(|arg| arg.clone().into_string().ok()).collect::<Option<_>>()
}
pub fn osstring_tuples_to_strings(osstring_tuples: &[(OsString, OsString)]) -> Option<Vec<(String, String)>> {
    osstring_tuples.into_iter()
        .map(|(k, v)| Some((k.clone().into_string().ok()?, v.clone().into_string().ok()?)))
        .collect::<Option<_>>()
}

// TODO: TryFrom
pub fn try_compile_command_to_dist(command: compiler::CompileCommand) -> Option<CompileCommand> {
    let compiler::CompileCommand {
        executable,
        arguments,
        env_vars,
        cwd,
    } = command;
    Some(CompileCommand {
        executable: executable.into_os_string().into_string().ok()?,
        arguments: arguments.into_iter().map(|arg| arg.into_string().ok()).collect::<Option<_>>()?,
        env_vars: env_vars.into_iter()
            .map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect::<Option<_>>()?,
        cwd: cwd.into_os_string().into_string().ok()?,
    })
}

// TODO: Clone by assuming immutable/no GC for now
// TODO: make fields non-public?
// TODO: make archive_id validate that it's just a bunch of hex chars
#[derive(Debug, Hash, Eq, PartialEq)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub archive_id: String,
}

#[derive(Hash, Eq, PartialEq)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobId(pub u64);
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
pub struct ServerId(pub SocketAddr);
impl ServerId {
    pub fn addr(&self) -> SocketAddr {
        self.0
    }
}

#[derive(Hash, Eq, PartialEq)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum JobState {
    Pending,
    Ready,
    Started,
    Complete,
}
impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::JobState::*;
        match *self {
            Pending => "pending",
            Ready => "ready",
            Started => "started",
            Complete => "complete",
        }.fmt(f)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub cwd: String,
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
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;
#[cfg(unix)]
fn exit_status(code: i32) -> process::ExitStatus {
    process::ExitStatus::from_raw(code)
}
#[cfg(windows)]
fn exit_status(code: i32) -> process::ExitStatus {
    // TODO: this is probably a subideal conversion
    process::ExitStatus::from_raw(code as u32)
}
impl From<ProcessOutput> for process::Output {
    fn from(o: ProcessOutput) -> Self {
        // TODO: handle signals, i.e. None code
        process::Output { status: exit_status(o.code.unwrap()), stdout: o.stdout, stderr: o.stderr }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputData(Vec<u8>, u64);
impl OutputData {
    #[cfg(feature = "dist-server")]
    pub fn from_reader<R: Read>(r: R) -> Self {
        use flate2::Compression;
        use flate2::read::ZlibEncoder as ZlibReadEncoder;
        let mut compressor = ZlibReadEncoder::new(r, Compression::fast());
        let mut res = vec![];
        io::copy(&mut compressor, &mut res).unwrap();
        OutputData(res, compressor.total_in())
    }
    pub fn lens(&self) -> OutputDataLens {
        OutputDataLens { actual: self.1, compressed: self.0.len() as u64 }
    }
    #[cfg(feature = "dist-client")]
    pub fn into_reader(self) -> impl Read {
        use flate2::read::ZlibDecoder as ZlibReadDecoder;
        let decompressor = ZlibReadDecoder::new(io::Cursor::new(self.0));
        decompressor
    }
}
pub struct OutputDataLens {
    pub actual: u64,
    pub compressed: u64,
}
impl fmt::Display for OutputDataLens {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Size: {}->{}", self.actual, self.compressed)
    }
}

// TODO: standardise on compressed or not for inputs and toolchain

// TODO: make fields not public

// AllocJob

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobAlloc {
    pub auth: String,
    pub job_id: JobId,
    pub server_id: ServerId,
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
    pub need_toolchain: bool,
}

// JobState

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UpdateJobStateResult {
    Success,
    Fail { msg: String },
}

// HeartbeatServer

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatServerResult {
    pub is_new: bool,
}

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
    pub outputs: Vec<(String, OutputData)>,
}

// Status

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResult {
    pub num_servers: usize,
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
    pub output: ProcessOutput,
    pub outputs: Vec<(String, OutputData)>,
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

#[cfg(feature = "dist-server")]
type ExtResult<T, E> = ::std::result::Result<T, E>;

#[cfg(feature = "dist-server")]
pub trait SchedulerOutgoing {
    // To Server
    fn do_assign_job(&self, server_id: ServerId, job_id: JobId, tc: Toolchain, auth: String) -> Result<AssignJobResult>;
}

#[cfg(feature = "dist-server")]
pub trait ServerOutgoing {
    // To Scheduler
    fn do_update_job_state(&self, job_id: JobId, state: JobState) -> Result<UpdateJobStateResult>;
}

#[cfg(feature = "dist-server")]
pub trait SchedulerIncoming: Send + Sync {
    type Error: ::std::error::Error;
    // From Client
    fn handle_alloc_job(&self, requester: &SchedulerOutgoing, tc: Toolchain) -> ExtResult<AllocJobResult, Self::Error>;
    // From Server
    fn handle_heartbeat_server(&self, server_id: ServerId, num_cpus: usize, generate_job_auth: Box<Fn(JobId) -> String + Send>) -> ExtResult<HeartbeatServerResult, Self::Error>;
    // From Server
    fn handle_update_job_state(&self, job_id: JobId, server_id: ServerId, job_state: JobState) -> ExtResult<UpdateJobStateResult, Self::Error>;
    // From anyone
    fn handle_status(&self) -> ExtResult<StatusResult, Self::Error>;
}

#[cfg(feature = "dist-server")]
pub trait ServerIncoming: Send + Sync {
    type Error: ::std::error::Error;
    // From Scheduler
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> ExtResult<AssignJobResult, Self::Error>;
    // From Client
    fn handle_submit_toolchain(&self, requester: &ServerOutgoing, job_id: JobId, tc_rdr: ToolchainReader) -> ExtResult<SubmitToolchainResult, Self::Error>;
    // From Client
    fn handle_run_job(&self, requester: &ServerOutgoing, job_id: JobId, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader) -> ExtResult<RunJobResult, Self::Error>;
}

#[cfg(feature = "dist-server")]
pub trait BuilderIncoming: Send + Sync {
    type Error: ::std::error::Error;
    // From Server
    fn run_build(&self, toolchain: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, cache: &Mutex<TcCache>) -> ExtResult<BuildResult, Self::Error>;
}

/////////

pub trait Client {
    // To Scheduler
    fn do_alloc_job(&self, tc: Toolchain) -> SFuture<AllocJobResult>;
    // To Server
    fn do_submit_toolchain(&self, job_alloc: JobAlloc, tc: Toolchain) -> SFuture<SubmitToolchainResult>;
    // To Server
    fn do_run_job(&self, job_alloc: JobAlloc, command: CompileCommand, outputs: Vec<String>, inputs_packager: Box<pkg::InputsPackager>) -> SFuture<RunJobResult>;
    fn put_toolchain(&self, compiler_path: &Path, weak_key: &str, toolchain_packager: Box<pkg::ToolchainPackager>) -> Result<(Toolchain, Option<String>)>;
    fn may_dist(&self) -> bool;
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
    fn do_run_job(&self, _job_alloc: JobAlloc, _command: CompileCommand, _outputs: Vec<String>, _inputs_packager: Box<pkg::InputsPackager>) -> SFuture<RunJobResult> {
        panic!("NoopClient");
    }

    fn put_toolchain(&self, _compiler_path: &Path, _weak_key: &str, _toolchain_packager: Box<pkg::ToolchainPackager>) -> Result<(Toolchain, Option<String>)> {
        bail!("NoopClient");
    }
    fn may_dist(&self) -> bool {
        false
    }
}
