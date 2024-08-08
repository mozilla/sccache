use fs_err as fs;
use log::trace;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use sccache::config::HTTPUrl;
use sccache::dist::{self, SchedulerStatusResult, ServerId};
use sccache::server::ServerInfo;
use std::env;
use std::fs::remove_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str::{self, FromStr};
use std::thread;
use std::time::Duration;
use tokio::net;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde::Serialize;
#[cfg(feature = "dist-server")]
use tokio::task::{AbortHandle, JoinHandle};
use uuid::Uuid;

const CONTAINER_NAME_PREFIX: &str = "sccache_dist_test";
const DIST_IMAGE: &str = "sccache_dist_test_image";
const DIST_DOCKERFILE: &str = include_str!("Dockerfile.sccache-dist");
const DIST_IMAGE_BWRAP_PATH: &str = "/usr/bin/bwrap";
const MAX_STARTUP_WAIT: Duration = Duration::from_secs(5);
const DIST_CACHE_RELPATH: &str = "client-dist-cache";

const DIST_SERVER_TOKEN: &str = "THIS IS THE TEST TOKEN";

const CONFIGS_CONTAINER_PATH: &str = "/sccache-bits";
const BUILD_DIR_CONTAINER_PATH: &str = "/sccache-bits/build-dir";
const SCHEDULER_PORT: u16 = 10500;
const SERVER_PORT: u16 = 12345; // arbitrary

const TC_CACHE_SIZE: u64 = 1024 * 1024 * 1024; // 1 gig

pub fn start_local_daemon(cfg_path: &Path, cached_cfg_path: &Path) {
    // Don't run this with run() because on Windows `wait_with_output`
    // will hang because the internal server process is not detached.
    if !sccache_command()
        .arg("--start-server")
        // Uncomment following lines to debug locally.
        // .env("SCCACHE_LOG", "sccache=trace")
        // .env("RUST_LOG_STYLE", "never")
        // .env(
        //     "SCCACHE_ERROR_LOG",
        //     env::temp_dir().join("sccache_local_daemon.txt"),
        // )
        .env("SCCACHE_CONF", cfg_path)
        .env("SCCACHE_CACHED_CONF", cached_cfg_path)
        .status()
        .unwrap()
        .success()
    {
        panic!("Failed to start local daemon");
    }
}

pub fn stop_local_daemon() -> bool {
    trace!("sccache --stop-server");
    sccache_command()
        .arg("--stop-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub fn clear_cache_local_daemon(tmpdir: &Path) -> bool {
    trace!("clear local cache daemon");
    let client_build_dir = tmpdir.join(DIST_CACHE_RELPATH);
    assert!(client_build_dir.exists());
    remove_dir_all(client_build_dir).is_ok()
}

pub fn get_stats<F: 'static + Fn(ServerInfo)>(f: F) {
    sccache_command()
        .args(["--show-stats", "--stats-format=json"])
        .assert()
        .success()
        .stdout(predicate::function(move |output: &[u8]| {
            let s = str::from_utf8(output).expect("Output not UTF-8");
            let stats = serde_json::from_str(s).expect("Failed to parse JSON stats");
            eprintln!("get server stats: {stats:?}");
            f(stats);
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
    let mut f = fs::File::create(p).unwrap();
    f.write_all(&serde_json::to_vec(contents).unwrap()).unwrap();
}

pub fn write_source(path: &Path, filename: &str, contents: &str) {
    let p = path.join(filename);
    let mut f = fs::File::create(p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

pub fn init_cargo(path: &Path, cargo_name: &str) -> PathBuf {
    let cargo_path = path.join(cargo_name);
    let source_path = "src";
    fs::create_dir_all(cargo_path.join(source_path)).unwrap();
    cargo_path
}

// Prune any environment variables that could adversely affect test execution.
pub fn prune_command(mut cmd: Command) -> Command {
    use sccache::util::OsStrExt;

    for (var, _) in env::vars_os() {
        if var.starts_with("SCCACHE_") {
            cmd.env_remove(var);
        }
    }
    cmd
}

pub fn sccache_command() -> Command {
    prune_command(Command::new(env!("CARGO_BIN_EXE_sccache")))
}

pub fn cargo_command() -> Command {
    prune_command(Command::new("cargo"))
}

#[cfg(feature = "dist-server")]
pub fn sccache_dist_path() -> PathBuf {
    env!("CARGO_BIN_EXE_sccache-dist").into()
}

pub fn sccache_client_cfg(
    tmpdir: &Path,
    preprocessor_cache_mode: bool,
) -> sccache::config::FileConfig {
    let cache_relpath = "client-cache";
    let dist_cache_relpath = DIST_CACHE_RELPATH;
    fs::create_dir(tmpdir.join(cache_relpath)).unwrap();
    fs::create_dir(tmpdir.join(dist_cache_relpath)).unwrap();

    let disk_cache = sccache::config::DiskCacheConfig {
        dir: tmpdir.join(cache_relpath),
        preprocessor_cache_mode: sccache::config::PreprocessorCacheModeConfig {
            use_preprocessor_cache_mode: preprocessor_cache_mode,
            ..Default::default()
        },
        ..Default::default()
    };
    sccache::config::FileConfig {
        cache: sccache::config::CacheConfigs {
            azure: None,
            disk: Some(disk_cache),
            gcs: None,
            gha: None,
            memcached: None,
            redis: None,
            s3: None,
            webdav: None,
            oss: None,
            cos: None,
            multilevel: None,
        },
        dist: sccache::config::DistConfig {
            auth: Default::default(), // dangerously_insecure
            scheduler_url: None,
            cache_dir: tmpdir.join(dist_cache_relpath),
            toolchains: vec![],
            toolchain_cache_size: TC_CACHE_SIZE,
            rewrite_includes_only: false, // TODO
        },
        server_startup_timeout_ms: None,
        basedirs: vec![],
        client_side_mode: false,
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
        bind_address: Some(SocketAddr::from(([0, 0, 0, 0], SERVER_PORT))),
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
#[allow(dead_code)]
pub enum ServerHandle {
    Container {
        cid: String,
        url: HTTPUrl,
    },
    AsyncTask {
        handle: JoinHandle<()>,
        url: HTTPUrl,
    },
}

#[cfg(feature = "dist-server")]
pub struct DistSystem {
    sccache_dist: PathBuf,
    tmpdir: PathBuf,

    scheduler_name: Option<String>,
    server_names: Vec<String>,
    server_handles: Vec<AbortHandle>,
    client: reqwest::Client,
}

#[cfg(feature = "dist-server")]
impl DistSystem {
    pub fn new(sccache_dist: &Path, tmpdir: &Path) -> Self {
        // Make sure the docker image is available, building it if necessary.
        // Retry up to 3 times to handle transient apt-get failures in CI.
        let mut last_output = None;
        for attempt in 1..=3 {
            let mut child = Command::new("docker")
                .args(["build", "-q", "-t", DIST_IMAGE, "-"])
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
            if output.status.success() {
                last_output = Some(output);
                break;
            }
            eprintln!(
                "docker build attempt {}/3 failed (exit {}), retrying...",
                attempt, output.status
            );
            last_output = Some(output);
            std::thread::sleep(Duration::from_secs(5 * attempt as u64));
        }
        check_output(&last_output.unwrap());

        let tmpdir = tmpdir.join("distsystem");
        fs::create_dir(&tmpdir).unwrap();

        let client = dist_http_client_builder().build().unwrap();

        Self {
            sccache_dist: sccache_dist.to_owned(),
            tmpdir,

            scheduler_name: None,
            server_names: vec![],
            server_handles: vec![],
            client,
        }
    }

    pub async fn add_scheduler(&mut self) {
        let scheduler_cfg_relpath = "scheduler-cfg.json";
        let scheduler_cfg_path = self.tmpdir.join(scheduler_cfg_relpath);
        let scheduler_cfg_container_path =
            Path::new(CONFIGS_CONTAINER_PATH).join(scheduler_cfg_relpath);
        let scheduler_cfg = sccache_scheduler_cfg();
        fs::File::create(scheduler_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&scheduler_cfg).unwrap())
            .unwrap();

        // Create the scheduler
        let scheduler_name = make_container_name("scheduler");
        let output = Command::new("docker")
            .args([
                "run",
                "--name",
                &scheduler_name,
                "-e",
                "SCCACHE_NO_DAEMON=1",
                "-e",
                "SCCACHE_LOG=debug",
                "-e",
                "RUST_BACKTRACE=1",
                "--network",
                "host",
                "-v",
                &format!("{}:/sccache-dist:z", self.sccache_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}:z",
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
        wait_for_http(
            &self.client,
            scheduler_url,
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        )
        .await;

        wait_for(
            || async {
                let status = self.scheduler_status().await;
                if matches!(
                    status,
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
        )
        .await;
    }

    pub async fn add_server(&mut self) -> ServerHandle {
        let server_cfg_relpath = format!("server-cfg-{}.json", self.server_names.len());
        let server_cfg_path = self.tmpdir.join(&server_cfg_relpath);
        let server_cfg_container_path = Path::new(CONFIGS_CONTAINER_PATH).join(server_cfg_relpath);

        let server_name = make_container_name("server");
        let output = Command::new("docker")
            .args([
                "run",
                // Important for the bubblewrap builder
                "--privileged",
                "--name",
                &server_name,
                "-e",
                "SCCACHE_LOG=debug",
                "-e",
                "RUST_BACKTRACE=1",
                "--network",
                "host",
                "-v",
                &format!("{}:/sccache-dist:z", self.sccache_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}:z",
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

        let server_ip = IpAddr::from_str("127.0.0.1").unwrap();
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
        self.wait_server_ready(&handle).await;
        handle
    }

    pub async fn add_custom_server<S: dist::ServerIncoming + 'static>(
        &mut self,
        handler: S,
    ) -> ServerHandle {
        let server_addr = {
            let ip = IpAddr::from_str("127.0.0.1").unwrap();
            let listener = net::TcpListener::bind(SocketAddr::from((ip, 0)))
                .await
                .unwrap();
            listener.local_addr().unwrap()
        };
        let token = create_server_token(ServerId::new(server_addr), DIST_SERVER_TOKEN);
        let server = dist::http::Server::new(
            server_addr,
            Some(SocketAddr::from(([0, 0, 0, 0], server_addr.port()))),
            self.scheduler_url().to_url(),
            token,
            handler,
        )
        .unwrap();
        let handle = tokio::spawn(async move {
            server.start().await.unwrap();
            unreachable!();
        });
        self.server_handles.push(handle.abort_handle());

        let url =
            HTTPUrl::from_url(reqwest::Url::parse(&format!("https://{}", server_addr)).unwrap());
        let handle = ServerHandle::AsyncTask { handle, url };
        self.wait_server_ready(&handle).await;
        handle
    }

    pub async fn restart_server(&mut self, handle: &ServerHandle) {
        match handle {
            ServerHandle::Container { cid, url: _ } => {
                let output = Command::new("docker")
                    .args(["restart", cid])
                    .output()
                    .unwrap();
                check_output(&output);
            }
            ServerHandle::AsyncTask { handle: _, url: _ } => {
                // TODO: pretty easy, just no need yet
                panic!("restart not yet implemented for async servers")
            }
        }
        self.wait_server_ready(handle).await;
    }
    pub fn count_toolchains_on_server(&mut self, handle: &ServerHandle) -> usize {
        match handle {
            ServerHandle::Container { cid, url: _ } => {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        "-t",
                        cid,
                        "ls",
                        "-1",
                        &format!("{BUILD_DIR_CONTAINER_PATH}/toolchains"),
                    ])
                    .output()
                    .unwrap();
                check_output(&output);
                println!("{output:?}");
                let str_output = String::from_utf8_lossy(&output.stdout);
                str_output.lines().filter(|&part| !part.is_empty()).count()
            }
            ServerHandle::AsyncTask { .. } => {
                panic!("toolchain counting not implemented for async servers")
            }
        }
    }

    pub async fn wait_server_ready(&mut self, handle: &ServerHandle) {
        let url = match handle {
            ServerHandle::Container { cid: _, url }
            | ServerHandle::AsyncTask { handle: _, url } => url.clone(),
        };
        wait_for_http(
            &self.client,
            url,
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        )
        .await;

        wait_for(
            || async {
                let status = self.scheduler_status().await;
                if matches!(
                    status,
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
        )
        .await;
    }

    pub fn scheduler_url(&self) -> HTTPUrl {
        let url = format!("http://127.0.0.1:{}", SCHEDULER_PORT);
        HTTPUrl::from_url(reqwest::Url::parse(&url).unwrap())
    }

    async fn scheduler_status(&self) -> SchedulerStatusResult {
        let url = dist::http::urls::scheduler_status(&self.scheduler_url().to_url());
        let res = self.client.get(url).send().await.unwrap();
        assert!(res.status().is_success());
        let bytes = res.bytes().await.unwrap();
        bincode::deserialize_from(bytes.as_ref()).unwrap()
    }
}

// If you want containers to hang around (e.g. for debugging), comment out the "rm -f" lines
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

        if let Some(scheduler_name) = self.scheduler_name.as_ref() {
            droperr!(
                Command::new("docker")
                    .args(["logs", scheduler_name])
                    .output()
                    .map(|o| logs.push((scheduler_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["kill", scheduler_name])
                    .output()
                    .map(|o| outputs.push((scheduler_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["rm", "-f", scheduler_name])
                    .output()
                    .map(|o| outputs.push((scheduler_name, o)))
            );
        }
        for server_name in self.server_names.iter() {
            droperr!(
                Command::new("docker")
                    .args(["logs", server_name])
                    .output()
                    .map(|o| logs.push((server_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["kill", server_name])
                    .output()
                    .map(|o| outputs.push((server_name, o)))
            );
            droperr!(
                Command::new("docker")
                    .args(["rm", "-f", server_name])
                    .output()
                    .map(|o| outputs.push((server_name, o)))
            );
        }
        for handle in &self.server_handles {
            handle.abort();
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
        Uuid::new_v4().hyphenated()
    )
}

fn check_output(output: &Output) {
    if !output.status.success() {
        println!(
            "{}\n\n[BEGIN STDOUT]\n===========\n{}\n===========\n[FIN STDOUT]\n\n[BEGIN STDERR]\n===========\n{}\n===========\n[FIN STDERR]\n\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        panic!()
    }
}

#[cfg(feature = "dist-server")]
fn dist_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .danger_accept_invalid_certs(true)
        .tls_sni(false)
}

#[cfg(feature = "dist-server")]
async fn wait_for_http(
    client: &reqwest::Client,
    url: HTTPUrl,
    interval: Duration,
    max_wait: Duration,
) {
    let url = url.to_url();
    wait_for(
        || async {
            tokio::time::timeout(interval, client.get(url.clone()).send())
                .await
                .map_err(|e| e.to_string())?
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
        interval,
        max_wait,
    )
    .await;
}

#[cfg(feature = "dist-server")]
async fn wait_for<F, Fut>(f: F, interval: Duration, max_wait: Duration)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut last_error = None;
    let wait = async {
        loop {
            match f().await {
                Ok(()) => return,
                Err(e) => last_error = Some(e),
            }
            tokio::time::sleep(interval).await;
        }
    };
    if tokio::time::timeout(max_wait, wait).await.is_err() {
        panic!("wait timed out, last error result: {:?}", last_error);
    }
}
