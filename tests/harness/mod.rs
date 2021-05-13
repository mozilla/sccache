#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use sccache::config::HTTPUrl;
use sccache::dist::{self, SchedulerStatusResult, ServerId};
use sccache::server::ServerInfo;
#[cfg(feature = "dist-server")]
use std::env;
use std::fs;
use std::io::Write;
use std::net::{self, IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str;
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;
#[cfg(feature = "dist-server")]
use nix::{
    sys::{
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus},
    },
    unistd::{ForkResult, Pid},
};
use predicates::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[cfg(feature = "dist-server")]
macro_rules! matches {
    ($expression:expr, $($pattern:tt)+) => {
        match $expression {
            $($pattern)+ => true,
            _ => false
        }
    }
}

const CONTAINER_NAME_PREFIX: &str = "sccache_dist_test";
const DIST_IMAGE: &str = "sccache_dist_test_image";
const DIST_DOCKERFILE: &str = include_str!("Dockerfile.sccache-dist");
const DIST_IMAGE_BWRAP_PATH: &str = "/bwrap";
const MAX_STARTUP_WAIT: Duration = Duration::from_secs(5);

const DIST_SERVER_TOKEN: &str = "THIS IS THE TEST TOKEN";

const CONFIGS_CONTAINER_PATH: &str = "/sccache-bits";
const BUILD_DIR_CONTAINER_PATH: &str = "/sccache-bits/build-dir";
const SCHEDULER_PORT: u16 = 10500;
const SERVER_PORT: u16 = 12345; // arbitrary

const TC_CACHE_SIZE: u64 = 1024 * 1024 * 1024; // 1 gig

pub fn start_local_daemon(cfg_path: &Path, cached_cfg_path: &Path) {
    // Don't run this with run() because on Windows `wait_with_output`
    // will hang because the internal server process is not detached.
    sccache_command()
        .arg("--start-server")
        .env("SCCACHE_CONF", cfg_path)
        .env("SCCACHE_CACHED_CONF", cached_cfg_path)
        .status()
        .unwrap()
        .success();
}
pub fn stop_local_daemon() {
    trace!("sccache --stop-server");
    drop(
        sccache_command()
            .arg("--stop-server")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

pub fn get_stats<F: 'static + Fn(ServerInfo)>(f: F) {
    sccache_command()
        .args(&["--show-stats", "--stats-format=json"])
        .assert()
        .success()
        .stdout(predicate::function(move |output: &[u8]| {
            let s = str::from_utf8(output).expect("Output not UTF-8");
            f(serde_json::from_str(s).expect("Failed to parse JSON stats"));
            true
        }));
}

#[allow(unused)]
pub fn zero_stats() {
    trace!("sccache --zero-stats");
    drop(
        sccache_command()
            .arg("--zero-stats")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

pub fn write_json_cfg<T: Serialize>(path: &Path, filename: &str, contents: &T) {
    let p = path.join(filename);
    let mut f = fs::File::create(&p).unwrap();
    f.write_all(&serde_json::to_vec(contents).unwrap()).unwrap();
}

pub fn write_source(path: &Path, filename: &str, contents: &str) {
    let p = path.join(filename);
    let mut f = fs::File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

// Override any environment variables that could adversely affect test execution.
pub fn sccache_command() -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("sccache"));
    cmd.env("SCCACHE_CONF", "nonexistent_conf_path")
        .env("SCCACHE_CACHED_CONF", "nonexistent_cached_conf_path");
    cmd
}

#[cfg(feature = "dist-server")]
pub fn sccache_dist_path() -> PathBuf {
    assert_cmd::cargo::cargo_bin("sccache-dist")
}

pub fn sccache_client_cfg(tmpdir: &Path) -> sccache::config::FileConfig {
    let cache_relpath = "client-cache";
    let dist_cache_relpath = "client-dist-cache";
    fs::create_dir(tmpdir.join(cache_relpath)).unwrap();
    fs::create_dir(tmpdir.join(dist_cache_relpath)).unwrap();

    let disk_cache = sccache::config::DiskCacheConfig {
        dir: tmpdir.join(cache_relpath),
        ..Default::default()
    };
    sccache::config::FileConfig {
        cache: sccache::config::CacheConfigs {
            azure: None,
            disk: Some(disk_cache),
            gcs: None,
            memcached: None,
            redis: None,
            s3: None,
        },
        dist: sccache::config::DistConfig {
            auth: Default::default(), // dangerously_insecure
            scheduler_url: None,
            cache_dir: tmpdir.join(dist_cache_relpath),
            toolchains: vec![],
            toolchain_cache_size: TC_CACHE_SIZE,
            rewrite_includes_only: false, // TODO
        },
    }
}
#[cfg(feature = "dist-server")]
fn sccache_scheduler_cfg() -> sccache::config::scheduler::Config {
    sccache::config::scheduler::Config {
        public_addr: SocketAddr::from(([0, 0, 0, 0], SCHEDULER_PORT)),
        client_auth: sccache::config::scheduler::ClientAuth::Insecure,
        server_auth: sccache::config::scheduler::ServerAuth::Token {
            token: DIST_SERVER_TOKEN.to_owned(),
        },
    }
}
#[cfg(feature = "dist-server")]
fn sccache_server_cfg(
    tmpdir: &Path,
    scheduler_url: HTTPUrl,
    server_ip: IpAddr,
) -> sccache::config::server::Config {
    let relpath = "server-cache";
    fs::create_dir(tmpdir.join(relpath)).unwrap();

    sccache::config::server::Config {
        builder: sccache::config::server::BuilderType::Overlay {
            build_dir: BUILD_DIR_CONTAINER_PATH.into(),
            bwrap_path: DIST_IMAGE_BWRAP_PATH.into(),
        },
        cache_dir: Path::new(CONFIGS_CONTAINER_PATH).join(relpath),
        public_addr: SocketAddr::new(server_ip, SERVER_PORT),
        scheduler_url,
        scheduler_auth: sccache::config::server::SchedulerAuth::Token {
            token: DIST_SERVER_TOKEN.to_owned(),
        },
        toolchain_cache_size: TC_CACHE_SIZE,
    }
}

// TODO: this is copied from the sccache-dist binary - it's not clear where would be a better place to put the
// code so that it can be included here
#[cfg(feature = "dist-server")]
fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}

#[cfg(feature = "dist-server")]
pub enum ServerHandle {
    Container { cid: String, url: HTTPUrl },
    Process { pid: Pid, url: HTTPUrl },
}

#[cfg(feature = "dist-server")]
pub struct DistSystem {
    sccache_dist: PathBuf,
    tmpdir: PathBuf,

    scheduler_name: Option<String>,
    server_names: Vec<String>,
    server_pids: Vec<Pid>,
}

#[cfg(feature = "dist-server")]
impl DistSystem {
    pub fn new(sccache_dist: &Path, tmpdir: &Path) -> Self {
        // Make sure the docker image is available, building it if necessary
        let mut child = Command::new("docker")
            .args(&["build", "-q", "-t", DIST_IMAGE, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(DIST_DOCKERFILE.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        check_output(&output);

        let tmpdir = tmpdir.join("distsystem");
        fs::create_dir(&tmpdir).unwrap();

        Self {
            sccache_dist: sccache_dist.to_owned(),
            tmpdir,

            scheduler_name: None,
            server_names: vec![],
            server_pids: vec![],
        }
    }

    pub fn add_scheduler(&mut self) {
        let scheduler_cfg_relpath = "scheduler-cfg.json";
        let scheduler_cfg_path = self.tmpdir.join(scheduler_cfg_relpath);
        let scheduler_cfg_container_path =
            Path::new(CONFIGS_CONTAINER_PATH).join(scheduler_cfg_relpath);
        let scheduler_cfg = sccache_scheduler_cfg();
        fs::File::create(&scheduler_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&scheduler_cfg).unwrap())
            .unwrap();

        // Create the scheduler
        let scheduler_name = make_container_name("scheduler");
        let output = Command::new("docker")
            .args(&[
                "run",
                "--name",
                &scheduler_name,
                "-e",
                "SCCACHE_NO_DAEMON=1",
                "-e",
                "RUST_LOG=sccache=trace",
                "-e",
                "RUST_BACKTRACE=1",
                "-v",
                &format!("{}:/sccache-dist", self.sccache_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}",
                    self.tmpdir.to_str().unwrap(),
                    CONFIGS_CONTAINER_PATH
                ),
                "-d",
                DIST_IMAGE,
                "bash",
                "-c",
                &format!(
                    r#"
                    set -o errexit &&
                    exec /sccache-dist scheduler --config {cfg}
                "#,
                    cfg = scheduler_cfg_container_path.to_str().unwrap()
                ),
            ])
            .output()
            .unwrap();
        self.scheduler_name = Some(scheduler_name);

        check_output(&output);

        let scheduler_url = self.scheduler_url();
        wait_for_http(scheduler_url, Duration::from_millis(100), MAX_STARTUP_WAIT);
        wait_for(
            || {
                let status = self.scheduler_status();
                if matches!(
                    self.scheduler_status(),
                    SchedulerStatusResult {
                        num_servers: 0,
                        num_cpus: _,
                        in_progress: 0
                    }
                ) {
                    Ok(())
                } else {
                    Err(format!("{:?}", status))
                }
            },
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        );
    }

    pub fn add_server(&mut self) -> ServerHandle {
        let server_cfg_relpath = format!("server-cfg-{}.json", self.server_names.len());
        let server_cfg_path = self.tmpdir.join(&server_cfg_relpath);
        let server_cfg_container_path = Path::new(CONFIGS_CONTAINER_PATH).join(server_cfg_relpath);

        let server_name = make_container_name("server");
        let output = Command::new("docker")
            .args(&[
                "run",
                // Important for the bubblewrap builder
                "--privileged",
                "--name",
                &server_name,
                "-e",
                "RUST_LOG=sccache=trace",
                "-e",
                "RUST_BACKTRACE=1",
                "-v",
                &format!("{}:/sccache-dist", self.sccache_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}",
                    self.tmpdir.to_str().unwrap(),
                    CONFIGS_CONTAINER_PATH
                ),
                "-d",
                DIST_IMAGE,
                "bash",
                "-c",
                &format!(
                    r#"
                    set -o errexit &&
                    while [ ! -f {cfg}.ready ]; do sleep 0.1; done &&
                    exec /sccache-dist server --config {cfg}
                "#,
                    cfg = server_cfg_container_path.to_str().unwrap()
                ),
            ])
            .output()
            .unwrap();
        self.server_names.push(server_name.clone());

        check_output(&output);

        let server_ip = self.container_ip(&server_name);
        let server_cfg = sccache_server_cfg(&self.tmpdir, self.scheduler_url(), server_ip);
        fs::File::create(&server_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&server_cfg).unwrap())
            .unwrap();
        fs::File::create(format!("{}.ready", server_cfg_path.to_str().unwrap())).unwrap();

        let url = HTTPUrl::from_url(
            reqwest::Url::parse(&format!("https://{}:{}", server_ip, SERVER_PORT)).unwrap(),
        );
        let handle = ServerHandle::Container {
            cid: server_name,
            url,
        };
        self.wait_server_ready(&handle);
        handle
    }

    pub fn add_custom_server<S: dist::ServerIncoming + 'static>(
        &mut self,
        handler: S,
    ) -> ServerHandle {
        let server_addr = {
            let ip = self.host_interface_ip();
            let listener = net::TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
            listener.local_addr().unwrap()
        };
        let token = create_server_token(ServerId::new(server_addr), DIST_SERVER_TOKEN);
        let server =
            dist::http::Server::new(server_addr, self.scheduler_url().to_url(), token, handler)
                .unwrap();
        let pid = match unsafe { nix::unistd::fork() }.unwrap() {
            ForkResult::Parent { child } => {
                self.server_pids.push(child);
                child
            }
            ForkResult::Child => {
                env::set_var("RUST_LOG", "sccache=trace");
                env_logger::try_init().unwrap();
                void::unreachable(server.start().unwrap())
            }
        };

        let url =
            HTTPUrl::from_url(reqwest::Url::parse(&format!("https://{}", server_addr)).unwrap());
        let handle = ServerHandle::Process { pid, url };
        self.wait_server_ready(&handle);
        handle
    }

    pub fn restart_server(&mut self, handle: &ServerHandle) {
        match handle {
            ServerHandle::Container { cid, url: _ } => {
                let output = Command::new("docker")
                    .args(&["restart", cid])
                    .output()
                    .unwrap();
                check_output(&output);
            }
            ServerHandle::Process { pid: _, url: _ } => {
                // TODO: pretty easy, just no need yet
                panic!("restart not yet implemented for pids")
            }
        }
        self.wait_server_ready(handle)
    }

    pub fn wait_server_ready(&mut self, handle: &ServerHandle) {
        let url = match handle {
            ServerHandle::Container { cid: _, url } | ServerHandle::Process { pid: _, url } => {
                url.clone()
            }
        };
        wait_for_http(url, Duration::from_millis(100), MAX_STARTUP_WAIT);
        wait_for(
            || {
                let status = self.scheduler_status();
                if matches!(
                    self.scheduler_status(),
                    SchedulerStatusResult {
                        num_servers: 1,
                        num_cpus: _,
                        in_progress: 0
                    }
                ) {
                    Ok(())
                } else {
                    Err(format!("{:?}", status))
                }
            },
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        );
    }

    pub fn scheduler_url(&self) -> HTTPUrl {
        let ip = self.container_ip(self.scheduler_name.as_ref().unwrap());
        let url = format!("http://{}:{}", ip, SCHEDULER_PORT);
        HTTPUrl::from_url(reqwest::Url::parse(&url).unwrap())
    }

    fn scheduler_status(&self) -> SchedulerStatusResult {
        let res = reqwest::get(dist::http::urls::scheduler_status(
            &self.scheduler_url().to_url(),
        ))
        .unwrap();
        assert!(res.status().is_success());
        bincode::deserialize_from(res).unwrap()
    }

    fn container_ip(&self, name: &str) -> IpAddr {
        let output = Command::new("docker")
            .args(&[
                "inspect",
                "--format",
                "{{ .NetworkSettings.IPAddress }}",
                name,
            ])
            .output()
            .unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned().parse().unwrap()
    }

    // The interface that the host sees on the docker network (typically 'docker0')
    fn host_interface_ip(&self) -> IpAddr {
        let output = Command::new("docker")
            .args(&[
                "inspect",
                "--format",
                "{{ .NetworkSettings.Gateway }}",
                self.scheduler_name.as_ref().unwrap(),
            ])
            .output()
            .unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned().parse().unwrap()
    }
}

// If you want containers to hang around (e.g. for debugging), commend out the "rm -f" lines
#[cfg(feature = "dist-server")]
impl Drop for DistSystem {
    fn drop(&mut self) {
        let mut did_err = false;

        // Panicking halfway through drop would either abort (if it's a double panic) or leave us with
        // resources that aren't yet cleaned up. Instead, do as much as possible then decide what to do
        // at the end - panic (if not already doing so) or let the panic continue
        macro_rules! droperr {
            ($e:expr) => {
                match $e {
                    Ok(()) => (),
                    Err(e) => {
                        did_err = true;
                        eprintln!("Error with {}: {}", stringify!($e), e)
                    }
                }
            };
        }

        let mut logs = vec![];
        let mut outputs = vec![];
        let mut exits = vec![];

        if let Some(scheduler_name) = self.scheduler_name.as_ref() {
            droperr!(Command::new("docker")
                .args(&["logs", scheduler_name])
                .output()
                .map(|o| logs.push((scheduler_name, o))));
            droperr!(Command::new("docker")
                .args(&["kill", scheduler_name])
                .output()
                .map(|o| outputs.push((scheduler_name, o))));
            droperr!(Command::new("docker")
                .args(&["rm", "-f", scheduler_name])
                .output()
                .map(|o| outputs.push((scheduler_name, o))));
        }
        for server_name in self.server_names.iter() {
            droperr!(Command::new("docker")
                .args(&["logs", server_name])
                .output()
                .map(|o| logs.push((server_name, o))));
            droperr!(Command::new("docker")
                .args(&["kill", server_name])
                .output()
                .map(|o| outputs.push((server_name, o))));
            droperr!(Command::new("docker")
                .args(&["rm", "-f", server_name])
                .output()
                .map(|o| outputs.push((server_name, o))));
        }
        for &pid in self.server_pids.iter() {
            droperr!(nix::sys::signal::kill(pid, Signal::SIGINT));
            thread::sleep(Duration::from_millis(100));
            let mut killagain = true; // Default to trying to kill again, e.g. if there was an error waiting on the pid
            droperr!(
                nix::sys::wait::waitpid(pid, Some(WaitPidFlag::WNOHANG)).map(|ws| {
                    if ws != WaitStatus::StillAlive {
                        killagain = false;
                        exits.push(ws)
                    }
                })
            );
            if killagain {
                eprintln!("SIGINT didn't kill process, trying SIGKILL");
                droperr!(nix::sys::signal::kill(pid, Signal::SIGKILL));
                droperr!(nix::sys::wait::waitpid(pid, Some(WaitPidFlag::WNOHANG))
                    .map_err(|e| e.to_string())
                    .and_then(|ws| if ws == WaitStatus::StillAlive {
                        Err("process alive after sigkill".to_owned())
                    } else {
                        exits.push(ws);
                        Ok(())
                    }));
            }
        }

        for (
            container,
            Output {
                status,
                stdout,
                stderr,
            },
        ) in logs
        {
            println!(
                "LOGS == ({}) ==\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                status,
                container,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        for (
            container,
            Output {
                status,
                stdout,
                stderr,
            },
        ) in outputs
        {
            println!(
                "OUTPUTS == ({}) ==\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                status,
                container,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        for exit in exits {
            println!("EXIT: {:?}", exit)
        }

        if did_err && !thread::panicking() {
            panic!("Encountered failures during dist system teardown")
        }
    }
}

fn make_container_name(tag: &str) -> String {
    format!(
        "{}_{}_{}",
        CONTAINER_NAME_PREFIX,
        tag,
        Uuid::new_v4().to_hyphenated_ref()
    )
}

fn check_output(output: &Output) {
    if !output.status.success() {
        println!("{}\n\n[BEGIN STDOUT]\n===========\n{}\n===========\n[FIN STDOUT]\n\n[BEGIN STDERR]\n===========\n{}\n===========\n[FIN STDERR]\n\n",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
}

#[cfg(feature = "dist-server")]
fn wait_for_http(url: HTTPUrl, interval: Duration, max_wait: Duration) {
    // TODO: after upgrading to reqwest >= 0.9, use 'danger_accept_invalid_certs' and stick with that rather than tcp
    wait_for(
        || {
            //match reqwest::get(url.to_url()) {
            match net::TcpStream::connect(url.to_url()) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        },
        interval,
        max_wait,
    )
}

fn wait_for<F: Fn() -> Result<(), String>>(f: F, interval: Duration, max_wait: Duration) {
    let start = Instant::now();
    let mut lasterr;
    loop {
        match f() {
            Ok(()) => return,
            Err(e) => lasterr = e,
        }
        if start.elapsed() > max_wait {
            break;
        }
        thread::sleep(interval)
    }
    panic!("wait timed out, last error result: {}", lasterr)
}
