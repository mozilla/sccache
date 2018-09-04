extern crate arraydeque;
extern crate base64;
#[macro_use]
extern crate clap;
extern crate crossbeam_utils;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate flate2;
extern crate jsonwebtoken as jwt;
extern crate libmount;
#[macro_use]
extern crate log;
extern crate lru_disk_cache;
extern crate nix;
extern crate rand;
extern crate sccache;
#[macro_use]
extern crate serde_derive;
extern crate tar;

use arraydeque::ArrayDeque;
use clap::{App, Arg, SubCommand};
use rand::RngCore;
use sccache::config::INSECURE_DIST_CLIENT_TOKEN;
use sccache::dist::{
    self,
    CompileCommand, InputsReader, JobId, JobAlloc, JobState, JobComplete, ServerId, Toolchain, ToolchainReader,
    AllocJobResult, AssignJobResult, HeartbeatServerResult, RunJobResult, StatusResult, SubmitToolchainResult, UpdateJobStateResult,
    BuilderIncoming, SchedulerIncoming, SchedulerOutgoing, ServerIncoming, ServerOutgoing,
    TcCache,
};
use std::collections::{btree_map, BTreeMap, HashMap};
use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use errors::*;

mod errors {
    #![allow(renamed_and_removed_lints)]
    use std::boxed::Box;
    use std::io;

    use base64;
    use jwt;
    use lru_disk_cache;
    use sccache;

    error_chain! {
        foreign_links {
            Base64(base64::DecodeError);
            Io(io::Error);
            Jwt(jwt::errors::Error);
            Lru(lru_disk_cache::Error);
        }

        links {
            Sccache(sccache::errors::Error, sccache::errors::ErrorKind);
        }
    }
}

mod scheduler_config {
    use sccache;
    use std::path::Path;

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ClientAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "token")]
        Token { token: String },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ServerAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "jwt_hs256")]
        JwtHS256 { secret_key: String },
        #[serde(rename = "token")]
        Token { token: String },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub client_auth: ClientAuth,
        pub server_auth: ServerAuth,
    }

    pub fn from_path(conf_path: &Path) -> Option<Config> {
        sccache::config::try_read_config_file(&conf_path)
    }
}

mod server_config {
    use sccache;
    use std::net::{IpAddr, SocketAddr};
    use std::path::{Path, PathBuf};

    const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;
    fn default_toolchain_cache_size() -> u64 { TEN_GIGS }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum BuilderType {
        #[serde(rename = "docker")]
        Docker,
        #[serde(rename = "overlay")]
        Overlay { build_dir: PathBuf, bwrap_path: PathBuf },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum SchedulerAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "jwt_token")]
        JwtToken { token: String },
        #[serde(rename = "token")]
        Token { token: String },
    }

    #[derive(Debug)]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub builder: BuilderType,
        pub cache_dir: PathBuf,
        pub public_addr: SocketAddr,
        pub scheduler_addr: IpAddr,
        pub scheduler_auth: SchedulerAuth,
        #[serde(default = "default_toolchain_cache_size")]
        pub toolchain_cache_size: u64,
    }

    pub fn from_path(conf_path: &Path) -> Option<Config> {
        sccache::config::try_read_config_file(&conf_path)
    }
}

mod build;

pub const INSECURE_DIST_SERVER_TOKEN: &str = "dangerously_insecure_server";

enum Command {
    Auth(AuthSubcommand),
    Scheduler(scheduler_config::Config),
    Server(server_config::Config),
}

enum AuthSubcommand {
    Base64 { num_bytes: usize },
    JwtHS256ServerToken { secret_key: String, server_id: ServerId },
}

enum Void {}

// Only supported on x86_64 Linux machines
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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

pub fn get_app<'a, 'b>() -> App<'a, 'b> {
    App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand(SubCommand::with_name("auth")
            .subcommand(SubCommand::with_name("generate-jwt-hs256-key"))
            .subcommand(SubCommand::with_name("generate-jwt-hs256-server-token")
                .arg(Arg::from_usage("--server <SERVER_ADDR> 'Generate a key for the specified server'"))
                .arg(Arg::from_usage("--secret-key [KEY] 'Use specified key to create the token'").required_unless("config"))
                .arg(Arg::from_usage("--config [PATH] 'Use the key from the scheduler config file'").required_unless("secret-key"))
            )
            .subcommand(SubCommand::with_name("generate-shared-token")
                .arg(Arg::from_usage("--bits [BITS] 'Use the specified number of bits of randomness'").default_value("256"))
            )
        )
        .subcommand(SubCommand::with_name("scheduler")
            .arg(Arg::from_usage("--config <PATH> 'Use the scheduler config file at PATH'"))
        )
        .subcommand(SubCommand::with_name("server")
            .arg(Arg::from_usage("--config <PATH> 'Use the server config file at PATH'"))
        )
}

fn parse() -> Result<Command> {
    let matches = get_app().get_matches();
    Ok(match matches.subcommand() {
        ("auth", Some(matches)) => {
            Command::Auth(match matches.subcommand() {
                ("generate-jwt-hs256-key", Some(_matches)) => {
                    // Size based on https://briansmith.org/rustdoc/ring/hmac/fn.recommended_key_len.html
                    AuthSubcommand::Base64 { num_bytes: 256 / 8 }
                },
                ("generate-jwt-hs256-server-token", Some(matches)) => {
                    let server_id = ServerId(value_t_or_exit!(matches, "server", SocketAddr));
                    let secret_key = if let Some(config_path) = matches.value_of("config").map(Path::new) {
                        if let Some(config) = scheduler_config::from_path(config_path) {
                            match config.server_auth {
                                scheduler_config::ServerAuth::JwtHS256 { secret_key } => secret_key,
                                scheduler_config::ServerAuth::Insecure |
                                scheduler_config::ServerAuth::Token { token: _ } => bail!("Scheduler not configured with JWT HS256"),
                            }
                        } else {
                            bail!("Could not load config")
                        }
                    } else {
                        matches.value_of("secret-key").unwrap().to_owned()
                    };
                    AuthSubcommand::JwtHS256ServerToken { secret_key, server_id }
                },
                ("generate-shared-token", Some(matches)) => {
                    let bits = value_t_or_exit!(matches, "bits", usize);
                    if bits % 8 != 0 || bits < 64 || bits > 4096 {
                        bail!("Number of bits must be divisible by 8, greater than 64 and less than 4096")
                    }
                    AuthSubcommand::Base64 { num_bytes: bits / 8 }
                },
                _ => bail!("No subcommand of auth specified"),
            })
        }
        ("scheduler", Some(matches)) => {
            let config_path = Path::new(matches.value_of("config").unwrap());
            if let Some(config) = scheduler_config::from_path(config_path) {
                Command::Scheduler(config)
            } else {
                bail!("Could not load config")
            }
        },
        ("server", Some(matches)) => {
            let config_path = Path::new(matches.value_of("config").unwrap());
            if let Some(config) = server_config::from_path(config_path) {
                Command::Server(config)
            } else {
                bail!("Could not load config")
            }
        },
        _ => bail!("No subcommand specified"),
    })
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, |c| c == ' ');
    let server_addr = split.next().and_then(|addr| addr.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(ServerId(server_addr)),
        Some(_) |
        None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerJwt {
    server_id: ServerId,
}
fn create_jwt_server_token(server_id: ServerId, header: &jwt::Header, key: &[u8]) -> String {
    jwt::encode(&header, &ServerJwt { server_id }, key).unwrap()
}
fn dangerous_unsafe_extract_jwt_server_token(server_token: &str) -> Option<ServerId> {
    jwt::dangerous_unsafe_decode::<ServerJwt>(&server_token)
        .map(|res| res.claims.server_id)
        .ok()
}
fn check_jwt_server_token(server_token: &str, key: &[u8], validation: &jwt::Validation) -> Option<ServerId> {
    jwt::decode::<ServerJwt>(server_token, key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            let mut rng = rand::OsRng::new().unwrap();
            rng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD));
            Ok(0)
        },
        Command::Auth(AuthSubcommand::JwtHS256ServerToken { secret_key, server_id }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = base64::decode_config(&secret_key, base64::URL_SAFE_NO_PAD)?;
            println!("{}", create_jwt_server_token(server_id, &header, &secret_key));
            Ok(0)
        },

        Command::Scheduler(scheduler_config::Config { client_auth, server_auth }) => {
            let check_client_auth: Box<Fn(&str) -> bool + Send + Sync> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(move |s| s == INSECURE_DIST_CLIENT_TOKEN),
                scheduler_config::ClientAuth::Token { token } => Box::new(move |s| s == token),
            };

            let check_server_auth: Box<Fn(&str) -> Option<ServerId> + Send + Sync> = match server_auth {
                scheduler_config::ServerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE server authentication");
                    let token = INSECURE_DIST_SERVER_TOKEN;
                    Box::new(move |server_token| check_server_token(server_token, &token))
                },
                scheduler_config::ServerAuth::Token { token } => {
                    Box::new(move |server_token| check_server_token(server_token, &token))
                },
                scheduler_config::ServerAuth::JwtHS256 { secret_key } => {
                    let secret_key = base64::decode_config(&secret_key, base64::URL_SAFE_NO_PAD).chain_err(|| "Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let validation = jwt::Validation::new(jwt::Algorithm::HS256);
                    Box::new(move |server_token| check_jwt_server_token(server_token, &secret_key, &validation))
                }
            };

            let scheduler = Scheduler::new();
            let http_scheduler = dist::http::Scheduler::new(scheduler, check_client_auth, check_server_auth);
            let _: Void = http_scheduler.start();
        },

        Command::Server(server_config::Config { builder, cache_dir, public_addr, scheduler_addr, scheduler_auth, toolchain_cache_size }) => {
            let builder: Box<dist::BuilderIncoming<Error=Error>> = match builder {
                server_config::BuilderType::Docker => Box::new(build::DockerBuilder::new()),
                server_config::BuilderType::Overlay { bwrap_path, build_dir } =>
                    Box::new(build::OverlayBuilder::new(bwrap_path, build_dir).chain_err(|| "Overlay builder failed to start")?)
            };

            let server_id = ServerId(public_addr);
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, &INSECURE_DIST_SERVER_TOKEN)
                },
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                },
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId = dangerous_unsafe_extract_jwt_server_token(&token).chain_err(|| "Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!("JWT server id ({:?}) did not match configured server id ({:?})", token_server_id, server_id)
                    }
                    token
                }
            };

            let server = Server::new(builder, &cache_dir, toolchain_cache_size);
            let http_server = dist::http::Server::new(scheduler_addr, scheduler_auth, server);
            let _: Void = http_server.start();
        },
    }
}

fn init_logging() {
    if env::var("RUST_LOG").is_ok() {
        match env_logger::try_init() {
            Ok(_) => (),
            Err(e) => panic!(format!("Failed to initalize logging: {:?}", e)),
        }
    }
}

const MAX_PER_CORE_LOAD: f64 = 10f64;

#[derive(Copy, Clone)]
struct JobDetail {
    server_id: ServerId,
    state: JobState,
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    job_count: AtomicUsize,

    // Circular buffer of most recently completed jobs
    finished_jobs: Mutex<ArrayDeque<[(JobId, JobDetail); 1024], arraydeque::Wrapping>>,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,

    servers: Mutex<HashMap<ServerId, ServerDetails>>,
}

struct ServerDetails {
    jobs_assigned: usize,
    last_seen: Instant,
    num_cpus: usize,
    generate_job_auth: Box<Fn(JobId) -> String + Send>,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            job_count: AtomicUsize::new(0),
            jobs: Mutex::new(BTreeMap::new()),
            finished_jobs: Mutex::new(ArrayDeque::new()),
            servers: Mutex::new(HashMap::new()),
        }
    }
}

impl SchedulerIncoming for Scheduler {
    type Error = Error;
    fn handle_alloc_job(&self, requester: &SchedulerOutgoing, tc: Toolchain) -> Result<AllocJobResult> {
        // TODO: prune old servers
        let (job_id, server_id, auth) = {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();
            let mut servers = self.servers.lock().unwrap();

            let mut best = None;
            let mut best_load: f64 = MAX_PER_CORE_LOAD;
            let num_servers = servers.len();
            for (&server_id, details) in servers.iter_mut() {
                let load = details.jobs_assigned as f64 / details.num_cpus as f64;
                if load < best_load {
                    best = Some((server_id, details));
                    best_load = load;
                    if load == 0f64 {
                        break
                    }
                }
            }
            if let Some((server_id, server_details)) = best {
                let job_count = self.job_count.fetch_add(1, Ordering::SeqCst) as u64;
                let job_id = JobId(job_count);
                server_details.jobs_assigned += 1;

                info!("Job {} created and assigned to server {:?}", job_id, server_id);
                assert!(jobs.insert(job_id, JobDetail { server_id, state: JobState::Pending }).is_none());
                let auth = (server_details.generate_job_auth)(job_id);
                (job_id, server_id, auth)
            } else {
                let msg = format!("Insufficient capacity across {} available servers", num_servers);
                return Ok(AllocJobResult::Fail { msg })
            }
        };
        let AssignJobResult { need_toolchain } = requester.do_assign_job(server_id, job_id, tc, auth.clone()).chain_err(|| "assign job failed")?;
        if !need_toolchain {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();

            jobs.get_mut(&job_id).unwrap().state = JobState::Ready
        }
        let job_alloc = JobAlloc { auth, job_id, server_id };
        Ok(AllocJobResult::Success { job_alloc, need_toolchain })
    }

    fn handle_heartbeat_server(&self, server_id: ServerId, num_cpus: usize, generate_job_auth: Box<Fn(JobId) -> String + Send>) -> Result<HeartbeatServerResult> {
        if num_cpus == 0 {
            bail!("Invalid number of CPUs (0) specified in heartbeat")
        }

        // LOCKS
        let mut servers = self.servers.lock().unwrap();

        let mut is_new = false;
        servers.entry(server_id)
            .and_modify(|details| details.last_seen = Instant::now())
            .or_insert_with(|| {
                info!("Registered new server {:?}", server_id);
                is_new = true;
                ServerDetails { jobs_assigned: 0, num_cpus, generate_job_auth, last_seen: Instant::now() }
            });
        Ok(HeartbeatServerResult { is_new })
    }

    fn handle_update_job_state(&self, job_id: JobId, server_id: ServerId, job_state: JobState) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut finished_jobs = self.finished_jobs.lock().unwrap();
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            // TODO: nll should mean not needing to copy this out
            let job_detail = *entry.get();
            if job_detail.server_id != server_id {
                bail!("Job id {} is not registed on server {:?}", job_id, server_id)
            }
            match (job_detail.state, job_state) {
                (JobState::Pending, JobState::Ready) |
                (JobState::Ready,   JobState::Started) => {
                    entry.get_mut().state = job_state
                },
                (JobState::Started, JobState::Complete) => {
                    let (job_id, job_entry) = entry.remove_entry();
                    finished_jobs.push_back((job_id, job_entry));
                    servers.get_mut(&server_id).unwrap().jobs_assigned -= 1
                },
                (from, to) => {
                    bail!("Invalid job state transition from {} to {}", from, to)
                },
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else {
            bail!("Unknown job")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<StatusResult> {
        let servers = self.servers.lock().unwrap();

        Ok(StatusResult {
            num_servers: servers.len(),
        })
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
        let need_toolchain = !self.cache.lock().unwrap().contains_toolchain(&tc);
        assert!(self.job_toolchains.lock().unwrap().insert(job_id, tc).is_none());
        if !need_toolchain {
            // TODO: can start prepping the container now
        }
        Ok(AssignJobResult { need_toolchain })
    }
    fn handle_submit_toolchain(&self, requester: &ServerOutgoing, job_id: JobId, tc_rdr: ToolchainReader) -> Result<SubmitToolchainResult> {
        requester.do_update_job_state(job_id, JobState::Ready).chain_err(|| "Updating job state failed")?;
        // TODO: need to lock the toolchain until the container has started
        // TODO: can start prepping container
        let tc = match self.job_toolchains.lock().unwrap().get(&job_id).cloned() {
            Some(tc) => tc,
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        let mut cache = self.cache.lock().unwrap();
        // TODO: this returns before reading all the data, is that valid?
        if cache.contains_toolchain(&tc) {
            return Ok(SubmitToolchainResult::Success)
        }
        Ok(cache.insert_with(&tc, |mut file| io::copy(&mut {tc_rdr}, &mut file).map(|_| ()))
            .map(|_| SubmitToolchainResult::Success)
            .unwrap_or(SubmitToolchainResult::CannotCache))
    }
    fn handle_run_job(&self, requester: &ServerOutgoing, job_id: JobId, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader) -> Result<RunJobResult> {
        requester.do_update_job_state(job_id, JobState::Started).chain_err(|| "Updating job state failed")?;
        let tc = match self.job_toolchains.lock().unwrap().remove(&job_id) {
            Some(tc) => tc,
            None => return Ok(RunJobResult::JobNotFound),
        };
        let res = self.builder.run_build(tc, command, outputs, inputs_rdr, &self.cache).chain_err(|| "run build failed")?;
        requester.do_update_job_state(job_id, JobState::Complete).chain_err(|| "Updating job state failed")?;
        Ok(RunJobResult::Complete(JobComplete { output: res.output, outputs: res.outputs }))
    }
}
