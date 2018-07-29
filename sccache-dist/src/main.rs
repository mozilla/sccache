#[macro_use]
extern crate clap;
extern crate crossbeam_utils;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate flate2;
extern crate libmount;
#[macro_use]
extern crate log;
extern crate lru_disk_cache;
extern crate nix;
extern crate sccache_dist as dist;
extern crate tar;

use clap::{App, Arg, SubCommand};
use dist::{
    CompileCommand, InputsReader, JobId, JobAlloc, JobStatus, JobComplete, ServerId, Toolchain, ToolchainReader,
    AllocJobResult, AssignJobResult, HeartbeatServerResult, RunJobResult, StatusResult, SubmitToolchainResult,
    BuilderIncoming, SchedulerIncoming, SchedulerOutgoing, ServerIncoming, ServerOutgoing,
    TcCache,
};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use errors::*;

mod errors {
    #![allow(renamed_and_removed_lints)]
    use std::boxed::Box;
    use std::io;

    use dist;
    use lru_disk_cache;

    error_chain! {
        foreign_links {
            Io(io::Error);
            Lru(lru_disk_cache::Error);
        }

        links {
            Dist(dist::Error, dist::ErrorKind);
        }
    }
}

mod build;

enum Command {
    Scheduler,
    Server {
        builder: BuilderType,
        cache_dir: PathBuf,
        toolchain_cache_size: u64,
        scheduler_addr: IpAddr,
    },
}

enum BuilderType {
    Docker,
    Overlay {
        build_dir: PathBuf,
        bwrap_path: PathBuf,
    },
}

enum Void {}

fn main() {
    init_logging();
    std::process::exit(match parse() {
        Ok(cmd) => {
            match run(cmd) {
                Ok(s) => s,
                Err(e) =>  {
                    let stderr = &mut std::io::stderr();
                    writeln!(stderr, "error: {}", e).unwrap();

                    for e in e.iter().skip(1) {
                        writeln!(stderr, "caused by: {}", e).unwrap();
                    }
                    2
                }
            }
        }
        Err(e) => {
            println!("sccache: {}", e);
            get_app().print_help().unwrap();
            println!("");
            1
        }
    });
}

arg_enum!{
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    pub enum ArgBuilderType {
        docker,
        overlay,
    }
}
pub fn get_app<'a, 'b>() -> App<'a, 'b> {
    App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand(SubCommand::with_name("scheduler"))
        .subcommand(SubCommand::with_name("server")
            .arg(Arg::from_usage("--builder <BUILDER> 'Builder to use'")
                .possible_values(&ArgBuilderType::variants())
                // TODO: for some reason these don't get called out in specific help if they're omitted
                .requires_if("overlay", "overlay-build-dir")
                .requires_if("overlay", "overlay-bwrap-path")
            )
            .arg(Arg::from_usage("--overlay-build-dir [DIR] 'Directory for overlay to perform builds in (recreated on startup)'"))
            .arg(Arg::from_usage("--overlay-bwrap-path [PATH] 'Path to the bubblewrap binary'"))
            .arg(Arg::from_usage("--cache-dir <DIR> 'Directory to use as a cache for toolchains etc'"))
            .arg(Arg::from_usage("--toolchain-cache-size <SIZE> 'Amount of space to reserve for the toolchain cache'"))
            .arg(Arg::from_usage("--scheduler-addr <IP> 'IP address of the scheduler'"))
        )
}

fn parse() -> Result<Command> {
    let matches = get_app().get_matches();
    Ok(match matches.subcommand() {
        ("scheduler", Some(_matches)) => {
            Command::Scheduler
        },
        ("server", Some(matches)) => {
            let builder = value_t_or_exit!(matches.value_of("builder"), ArgBuilderType);
            let builder = match builder {
                ArgBuilderType::docker => BuilderType::Docker,
                ArgBuilderType::overlay => BuilderType::Overlay {
                    build_dir: matches.value_of("overlay-build-dir").unwrap().into(),
                    bwrap_path: matches.value_of("overlay-bwrap-path").unwrap().into(),
                },
            };
            let cache_dir = matches.value_of("cache-dir").unwrap().into();
            let toolchain_cache_size = value_t_or_exit!(matches.value_of("toolchain-cache-size"), u64);
            let scheduler_addr = value_t_or_exit!(matches.value_of("scheduler-addr"), IpAddr);
            Command::Server { builder, cache_dir, toolchain_cache_size, scheduler_addr }
        },
        _ => bail!("no subcommand specified"),
    })
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Scheduler => {
            let scheduler = Scheduler::new();
            let http_scheduler = dist::http::Scheduler::new(scheduler);
            let _: Void = http_scheduler.start();
        },
        Command::Server { builder, cache_dir, toolchain_cache_size, scheduler_addr } => {
            let builder: Box<dist::BuilderIncoming<Error=Error>> = match builder {
                BuilderType::Docker => Box::new(build::DockerBuilder::new()),
                BuilderType::Overlay { ref bwrap_path, ref build_dir } =>
                    Box::new(build::OverlayBuilder::new(bwrap_path, build_dir)?)
            };
            let server = Server::new(builder, &cache_dir, toolchain_cache_size);
            let http_server = dist::http::Server::new(scheduler_addr, server);
            let _: Void = http_server.start();
        },
    }
}

fn init_logging() {
    if env::var("RUST_LOG").is_ok() {
        match env_logger::init() {
            Ok(_) => (),
            Err(e) => panic!(format!("Failed to initalize logging: {:?}", e)),
        }
    }
}

const MAX_PER_CORE_LOAD: f64 = 10f64;

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
    type Error = Error;
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
        let AssignJobResult { need_toolchain } = requester.do_assign_job(server_id, job_id, tc).chain_err(|| "assign job failed")?;
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
    builder: Box<BuilderIncoming<Error=Error>>,
    cache: Mutex<TcCache>,
    job_toolchains: Mutex<HashMap<JobId, Toolchain>>,
}

impl Server {
    pub fn new(builder: Box<BuilderIncoming<Error=Error>>, cache_dir: &Path, toolchain_cache_size: u64) -> Server {
        Server {
            builder,
            cache: Mutex::new(TcCache::new(&cache_dir.join("tc"), toolchain_cache_size).unwrap()),
            job_toolchains: Mutex::new(HashMap::new()),
        }
    }
}

impl ServerIncoming for Server {
    type Error = Error;
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_key(&tc.archive_id);
        assert!(self.job_toolchains.lock().unwrap().insert(job_id, tc).is_none());
        if !need_toolchain {
            // TODO: can start prepping the container now
        }
        Ok(AssignJobResult { need_toolchain })
    }
    fn handle_submit_toolchain(&self, requester: &ServerOutgoing, job_id: JobId, tc_rdr: ToolchainReader) -> Result<SubmitToolchainResult> {
        requester.do_update_job_status(job_id, JobStatus::Started).chain_err(|| "update job status failed")?;
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
        let res = self.builder.run_build(tc, command, outputs, inputs_rdr, &self.cache).chain_err(|| "run build failed")?;
        requester.do_update_job_status(job_id, JobStatus::Complete).chain_err(|| "update job status failed")?;
        Ok(RunJobResult::Complete(JobComplete { output: res.output, outputs: res.outputs }))
    }
}
