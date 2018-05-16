#![allow(non_camel_case_types)]

use bytes::IntoBuf;
use compiler::CompileCommand;
use directories::ProjectDirs;
use dist::cache::{CacheOwner, TcCache};
use lru_disk_cache::Error as LruError;
use futures::{Future, Sink, Stream, future};
use futures_cpupool::CpuPool;
use mock_command::exit_status;
use serde_json;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use tokio_core;
use tokio_core::net::TcpStream;
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::length_delimited::{self, Framed};

use errors::*;

use config::ORGANIZATION;
const APP_NAME: &str = "sccache-dist";

mod cache;
#[cfg(test)]
#[macro_use]
mod test;

// TODO: Clone by assuming immutable/no GC for now
// TODO: make fields non-public?
#[derive(Debug, Hash, Eq, PartialEq)]
#[derive(Clone, Serialize, Deserialize)]
pub struct Toolchain {
    pub docker_img: String,
    pub archive_id: String,
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

#[derive(Hash, Eq, PartialEq)]
#[derive(Clone, Copy, Serialize, Deserialize)]
struct JobId(u64);
pub struct ServerId(u64);

const SCHEDULER_SERVERS_PORT: u16 = 10500;
const SCHEDULER_CLIENTS_PORT: u16 = 10501;
const SERVER_CLIENTS_PORT: u16 = 10502;

const CONCURRENT_CLIENT_REQS: usize = 50;
const CONCURRENT_REQS: usize = 20;

struct Cfg;

impl Cfg {
    fn scheduler_addr() -> IpAddr {
        env::var("SCCACHE_SCHEDULER_ADDR")
            .as_ref().map(String::as_str)
            .unwrap_or("127.0.0.1")
            .parse()
            .unwrap()
    }

    fn scheduler_listen_client_addr() -> SocketAddr {
        let ip_addr = "0.0.0.0".parse().unwrap();
        SocketAddr::new(ip_addr, SCHEDULER_CLIENTS_PORT)
    }
    fn client_connect_scheduler_addr() -> SocketAddr {
        SocketAddr::new(Self::scheduler_addr(), SCHEDULER_CLIENTS_PORT)
    }

    fn scheduler_listen_server_addr() -> SocketAddr {
        let ip_addr = "0.0.0.0".parse().unwrap();
        SocketAddr::new(ip_addr, SCHEDULER_SERVERS_PORT)
    }
    fn server_connect_scheduler_addr() -> SocketAddr {
        SocketAddr::new(Self::scheduler_addr(), SCHEDULER_SERVERS_PORT)
    }

    fn server_listen_client_addr() -> SocketAddr {
        let ip_addr = "0.0.0.0".parse().unwrap();
        SocketAddr::new(ip_addr, SERVER_CLIENTS_PORT)
    }
}

// TODO: make these fields not public

// TODO: any OsString or PathBuf shouldn't be sent across the wire
// from Windows

#[derive(Clone, Serialize, Deserialize)]
pub struct JobRequest {
    pub command: CompileCommand,
    pub inputs_archive: Vec<u8>,
    pub outputs: Vec<PathBuf>,
    pub toolchain: Toolchain,
    // TODO: should be sent as part of a separate request, not in here
    pub toolchain_data: Option<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub enum JobResult {
    Complete(JobComplete),
    NeedToolchain,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct JobComplete {
    pub output: ProcessOutput,
    pub outputs: Vec<(PathBuf, Vec<u8>)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JobAllocRequest {
    pub toolchain: Toolchain,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct JobAllocResult {
    job_id: JobId,
    addr: SocketAddr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AllocAssignment {
    job_id: JobId,
}

pub struct BuildRequest(JobRequest, Arc<Mutex<TcCache>>);
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
    fn do_allocation_assign(&self, ServerId, AllocAssignment) -> SFuture<()>;
}

trait DaemonClientHandler {
}
pub trait DaemonClientRequester: Send + Sync {
    // To Scheduler
    fn do_allocation_request(&self, JobAllocRequest) -> SFuture<JobAllocResult>;
    // To DaemonServer
    fn do_compile_request(&self, JobAllocResult, JobRequest) -> SFuture<JobResult>;

    fn get_toolchain_cache(&self, key: &str) -> Vec<u8>;
    // TODO: It's more correct to have a FnBox or Box<FnOnce> here
    fn put_toolchain_cache(&self, weak_key: &str, create: &mut FnMut(fs::File)) -> String;
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
pub trait BuilderHandler: Send + Sync {
    // From DaemonServer
    fn handle_compile_request(&self, BuildRequest) -> SFuture<BuildResult>;
}

enum JobStatus {
    AllocRequested(JobAllocRequest),
    AllocSuccess(ServerId, JobAllocRequest, JobAllocResult),
    JobStarted(ServerId, JobAllocRequest, JobAllocResult),
    JobCompleted(ServerId, JobAllocRequest, JobAllocResult),
    // Interrupted by some error in distributed sccache
    // or maybe a failure to allocate. Nothing to do with the
    // compilation itself.
    JobFailed(ServerId, JobAllocRequest, JobAllocResult),
}

fn large_delimited<T, B>(inner: T) -> Framed<T, B> where T: AsyncRead + AsyncWrite, B: IntoBuf {
    length_delimited::Builder::new()
        .max_frame_length(1*1024*1024*1024) // 1GiB
        .new_framed(inner)
}

pub struct SccacheScheduler {
    job_count: Cell<u64>,
    jobs: HashMap<JobId, JobStatus>,

    // Acts as a ring buffer of most recently completed jobs
    finished_jobs: VecDeque<JobStatus>,

    servers: Arc<Mutex<Vec<(
        SocketAddr,
        Option<WriteBincode<ReadBincode<Framed<TcpStream>, ()>, AllocAssignment>>,
    )>>>,
}

impl SccacheScheduler {
    pub fn new() -> Self {
        SccacheScheduler {
            job_count: Cell::new(0),
            jobs: HashMap::new(),
            finished_jobs: VecDeque::new(),
            servers: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn start(self) -> ! {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let handle = core.handle();

        {
            let mut servers = self.servers.lock().unwrap();
            assert!(servers.is_empty());

            let sched_addr = Cfg::scheduler_listen_server_addr();
            info!("Scheduler listening for servers on {}", sched_addr);
            let listener = TcpListener::bind(sched_addr).unwrap();
            let conn = listener.accept().unwrap().0;
            let addr = conn.peer_addr().unwrap();
            info!("Accepted server connection from {}", addr);
            let conn = TcpStream::from_stream(conn, &handle).unwrap();
            let conn = WriteBincode::new(ReadBincode::new(Framed::new(conn)));

            servers.push((addr, Some(conn)));
            assert!(servers.len() == 1);
        }

        let addr = Cfg::scheduler_listen_client_addr();
        info!("Scheduler listening for clients on {}", addr);
        let listener = tokio_core::net::TcpListener::bind(&addr, &handle).unwrap();
        core.run(
            listener.incoming()
                .from_err()
                .map(|(conn, addr)| {
                    trace!("Accepted connection from {}", addr);
                    let conn = WriteBincode::new(ReadBincode::new(Framed::new(conn)));
                    conn.into_future()
                        .map_err(|(e, _conn)| format!("{}", e).into()) // Mismatched bincode versions, so format
                        .and_then(|(req, conn)| { trace!("received request"); self.handle_allocation_request(req.unwrap()).map(|res| (res, conn)) })
                        .and_then(|(res, conn)| { trace!("sending result"); conn.send(res).map_err(Into::into) })
                })
                .buffer_unordered(CONCURRENT_REQS)
                .map(|_conn| ())
                .or_else(|err| -> ::std::result::Result<(), ()> { // Recover
                    error!("Encountered error while serving request: {}", err);
                    Ok(())
                })
                .for_each(|()| Ok(()))
        ).unwrap();

        panic!()
    }
}

impl SchedulerHandler for SccacheScheduler {
    fn handle_allocation_request(&self, req: JobAllocRequest) -> SFuture<JobAllocResult> {
        let (server_id, ip_addr) = {
            let servers = self.servers.lock().unwrap();
            assert!(servers.len() == 1);
            let ip_addr = servers[0].0.ip();
            (ServerId(0), ip_addr)
        };
        let job_id = JobId(self.job_count.get());
        self.job_count.set(self.job_count.get() + 1);
        let res = JobAllocResult { addr: SocketAddr::new(ip_addr, SERVER_CLIENTS_PORT), job_id };
        Box::new(self.do_allocation_assign(server_id, AllocAssignment { job_id }).map(|()| res))
    }
}
impl SchedulerRequester for SccacheScheduler {
    fn do_allocation_assign(&self, server_id: ServerId, req: AllocAssignment) -> SFuture<()> {
        let servers = self.servers.clone();
        let conn = servers.lock().unwrap()[server_id.0 as usize].1.take().unwrap();
        Box::new(
            conn
                .send(req)
                .map(move |conn| {
                    let mut servers = servers.lock().unwrap();
                    servers[server_id.0 as usize].1 = Some(conn)
                })
                .from_err()
        )
    }
}

// TODO: possibly shouldn't be public
pub struct SccacheDaemonClient {
    client_config_dir: PathBuf,
    cache: Mutex<TcCache>,
    // Local machine mapping from 'weak' hashes to strong toolchain hashes
    weak_map: Mutex<HashMap<String, String>>,
    pool: CpuPool,
}

impl SccacheDaemonClient {
    pub fn new() -> Self {
        let client_config_dir = env::var_os("SCCACHE_CLIENT_CONFIG_DIR")
            .map(|p| PathBuf::from(p))
            .unwrap_or_else(|| {
                let dirs = ProjectDirs::from("", ORGANIZATION, APP_NAME);
                dirs.cache_dir().join("client")
            });
        fs::create_dir_all(&client_config_dir).unwrap();

        let weak_map_path = client_config_dir.join("weak_map.json");
        if !weak_map_path.exists() {
            fs::File::create(&weak_map_path).unwrap().write_all(b"{}").unwrap()
        }
        let weak_map = serde_json::from_reader(fs::File::open(weak_map_path).unwrap()).unwrap();

        SccacheDaemonClient {
            client_config_dir,
            cache: Mutex::new(TcCache::new(CacheOwner::Client).unwrap()),
            // TODO: shouldn't clear on restart, but also should have some
            // form of pruning
            weak_map: Mutex::new(weak_map),
            pool: CpuPool::new(CONCURRENT_CLIENT_REQS),
        }
    }

    fn weak_to_strong(&self, weak_key: &str) -> Option<String> {
        self.weak_map.lock().unwrap().get(weak_key).map(String::to_owned)
    }
    fn record_weak(&self, weak_key: String, key: String) {
        let mut weak_map = self.weak_map.lock().unwrap();
        weak_map.insert(weak_key, key);
        let weak_map_path = self.client_config_dir.join("weak_map.json");
        serde_json::to_writer(fs::File::create(weak_map_path).unwrap(), &*weak_map).unwrap()
    }
}

impl DaemonClientHandler for SccacheDaemonClient {
}
impl DaemonClientRequester for SccacheDaemonClient {
    fn do_allocation_request(&self, req: JobAllocRequest) -> SFuture<JobAllocResult> {
        Box::new(self.pool.spawn(future::lazy(move || {
            let mut core = tokio_core::reactor::Core::new().unwrap();
            let handle = core.handle();
            core.run(
                TcpStream::connect(&Cfg::client_connect_scheduler_addr(), &handle)
                    .map(|conn| WriteBincode::new(ReadBincode::new(Framed::new(conn))))
                    .and_then(|conn| conn.send(req))
                    .from_err()
                    .and_then(|conn| conn.into_future()
                        .map_err(|(e, _conn)| format!("{}", e).into())) // Mismatched bincode versions, so format
                    .map(|(res, _conn)| res.unwrap())
            )
        })))
    }
    fn do_compile_request(&self, ja_res: JobAllocResult, req: JobRequest) -> SFuture<JobResult> {
        Box::new(self.pool.spawn(future::lazy(move || {
            let mut core = tokio_core::reactor::Core::new().unwrap();
            let handle = core.handle();
            core.run(
                TcpStream::connect(&ja_res.addr, &handle)
                    .map(|conn| WriteBincode::new(ReadBincode::new(large_delimited(conn))))
                    .and_then(|conn| conn.send(req))
                    .from_err()
                    .and_then(|conn| conn.into_future()
                        .map_err(|(e, _conn)| format!("{}", e).into())) // Mismatched bincode versions, so format
                    .map(|(res, _conn)| res.unwrap())
            )
        })))
    }

    fn get_toolchain_cache(&self, key: &str) -> Vec<u8> {
        let mut ret = vec![];
        self.cache.lock().unwrap().get(key).unwrap().read_to_end(&mut ret).unwrap();
        ret
    }
    fn put_toolchain_cache(&self, weak_key: &str, create: &mut FnMut(fs::File)) -> String {
        if let Some(strong_key) = self.weak_to_strong(weak_key) {
            debug!("Using cached toolchain {} -> {}", weak_key, strong_key);
            return strong_key
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("/tmp/toolchain_cache.tar");
        match file {
            Ok(f) => create(f),
            Err(e) => panic!("{}", e),
        }
        // TODO: after, if still exists, remove it
        let strong_key = self.cache.lock().unwrap().insert_file("/tmp/toolchain_cache.tar").unwrap();
        self.record_weak(weak_key.to_owned(), strong_key.clone());
        strong_key
    }
}

pub struct SccacheDaemonServer {
    builder: Box<BuilderHandler>,
    cache: Arc<Mutex<TcCache>>,
    sched_addr: SocketAddr,
}

impl SccacheDaemonServer {
    pub fn new(builder: Box<BuilderHandler>) -> SccacheDaemonServer {
        SccacheDaemonServer {
            builder,
            cache: Arc::new(Mutex::new(TcCache::new(CacheOwner::Server).unwrap())),
            sched_addr: Cfg::server_connect_scheduler_addr(),
        }
    }

    pub fn start(self) -> ! {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let handle = core.handle();
        info!("Daemon server connecting to scheduler at {}", self.sched_addr);
        let sched_conn: ReadBincode<Framed<_>, AllocAssignment> = core.run(
            TcpStream::connect(&self.sched_addr, &handle)
                .map(|conn| ReadBincode::new(Framed::new(conn)))
        ).unwrap();
        let self1 = Arc::new(self);
        let self2 = self1.clone();

        core.handle().spawn(
            sched_conn
                .map_err(|e| format!("{}", e).into()) // Mismatched bincode versions, so format
                .and_then(move |req| {
                    trace!("Received request from scheduler");
                    self1.handle_allocation_assign(req)
                })
                .for_each(|()| Ok(()))
                .map_err(|e| panic!(e))
        );

        let addr = Cfg::server_listen_client_addr();
        let listener = tokio_core::net::TcpListener::bind(&addr, &core.handle()).unwrap();
        core.run(
            listener.incoming()
                .from_err()
                .map(|(conn, addr)| {
                    trace!("Accepted connection from {}", addr);
                    let conn = WriteBincode::new(ReadBincode::new(large_delimited(conn)));
                    conn.into_future()
                        .map_err(|(e, _conn)| format!("{}", e).into()) // Mismatched bincode versions, so format
                        .and_then(|(req, conn)| { trace!("received request"); self2.handle_compile_request(req.unwrap()).map(|res| (res, conn)) })
                        .and_then(|(res, conn)| { trace!("sending result"); conn.send(res).map_err(Into::into) })
                })
                .buffer_unordered(CONCURRENT_REQS)
                .map(|_conn| ())
                .or_else(|err| -> ::std::result::Result<(), ()> { // Recover
                    error!("Encountered error while serving request: {}", err);
                    Ok(())
                })
                .for_each(|()| Ok(()))
        ).unwrap();

        panic!()
    }
}

impl DaemonServerHandler for SccacheDaemonServer {
    fn handle_allocation_assign(&self, alloc: AllocAssignment) -> SFuture<()> {
        // TODO: track ID of incoming job so scheduler is kept up-do-date
        f_ok(())
    }
    fn handle_compile_request(&self, req: JobRequest) -> SFuture<JobResult> {
        if let Some(toolchain_data) = req.toolchain_data.as_ref() {
            self.cache.lock().unwrap().insert_with(&req.toolchain.archive_id, |mut file| {
                file.write_all(&toolchain_data)
            }).unwrap()
        }
        if !self.cache.lock().unwrap().contains_key(&req.toolchain.archive_id) {
            return f_ok(JobResult::NeedToolchain)
        }
        Box::new(self.builder.handle_compile_request(BuildRequest(req, self.cache.clone()))
            .map(|res| JobResult::Complete(JobComplete { output: res.output, outputs: res.outputs })))
    }
}
impl DaemonServerRequester for SccacheDaemonServer {
}

pub struct SccacheBuilder {
    image_map: Arc<Mutex<HashMap<Toolchain, String>>>,
    container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
    pool: CpuPool,
}

fn check_output(output: &Output) {
    if !output.status.success() {
        error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
}

impl SccacheBuilder {
    pub fn new() -> SccacheBuilder {
        Self::cleanup();
        SccacheBuilder {
            image_map: Arc::new(Mutex::new(HashMap::new())),
            container_lists: Arc::new(Mutex::new(HashMap::new())),
            // TODO: maybe pass this in from global pool? Maybe not
            pool: CpuPool::new(CONCURRENT_REQS),
        }
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup() {
        info!("Performing initial Docker cleanup");

        let containers = {
            let output = Command::new("docker").args(&["ps", "--format", "{{.ID}} {{.Image}}"]).output().unwrap();
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
            if !shoulddelete && newdiff != "" {
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

    fn perform_build(compile_command: CompileCommand, inputs_archive: Vec<u8>, output_paths: Vec<PathBuf>, cid: &str) -> BuildResult {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        trace!("copying in build dir");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut inputs_archive.as_slice(), &mut process.stdin.take().unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        check_output(&output);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", cid, "/busybox", "mkdir", "-p"]).arg(&compile_command.cwd);
        for path in output_paths.iter() {
            cmd.arg(compile_command.cwd.join(path.parent().unwrap()));
        }
        let output = cmd.output().unwrap();
        check_output(&output);

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in compile_command.env_vars {
            let mut env = k;
            env.push("=");
            env.push(v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = format!("cd \"$1\" && shift && exec \"$@\"");
        cmd.args(&[cid, "/busybox", "sh", "-c", &shell_cmd]);
        cmd.arg(&compile_command.executable);
        cmd.arg(&compile_command.cwd);
        cmd.arg(compile_command.executable);
        cmd.args(compile_command.arguments);
        let compile_output = cmd.output().unwrap();
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let path = compile_command.cwd.join(path); // Resolve in case it's relative
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker").args(&["exec", cid, "/busybox", "cat"]).arg(&path).output().unwrap();
            if output.status.success() {
                outputs.push((path, output.stdout))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        BuildResult { output: compile_output.into(), outputs }
    }
}

impl BuilderHandler for SccacheBuilder {
    // From DaemonServer
    fn handle_compile_request(&self, req: BuildRequest) -> SFuture<BuildResult> {
        let image_map = self.image_map.clone();
        let container_lists = self.container_lists.clone();
        Box::new(self.pool.spawn_fn(move || -> Result<_> {
            let BuildRequest(job_req, cache) = req;
            let command = job_req.command;

            debug!("Finding container");
            let cid = Self::get_container(&image_map, &container_lists, &job_req.toolchain, cache);
            debug!("Performing build with container {}", cid);
            let res = Self::perform_build(command, job_req.inputs_archive, job_req.outputs, &cid);
            debug!("Finishing with container {}", cid);
            Self::finish_container(&container_lists, &job_req.toolchain, cid);
            debug!("Returning result");
            Ok(res)
        }))
    }
}
