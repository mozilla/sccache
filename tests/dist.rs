#![cfg(all(feature = "dist-client", feature = "dist-server"))]

extern crate assert_cmd;
extern crate log;
extern crate sccache;
extern crate serde_json;

use crate::harness::{
    cargo_command, clear_cache_local_daemon, get_stats, init_cargo, sccache_command,
    start_local_daemon, stop_local_daemon, write_json_cfg, write_source,
};
use assert_cmd::prelude::*;
use sccache::config::HTTPUrl;
use sccache::dist::{
    AllocJobResult, AssignJobResult, CompileCommand, HeartbeatServerResult, InputsReader,
    JobAuthorizer, JobId, JobState, RunJobResult, SchedulerIncoming, SchedulerOutgoing,
    SchedulerStatusResult, ServerId, ServerIncoming, ServerNonce, ServerOutgoing,
    SubmitToolchainResult, Toolchain, ToolchainReader, UpdateJobStateResult,
};
use std::ffi::OsStr;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Output;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use sccache::errors::*;

mod harness;

fn basic_compile(tmpdir: &Path, sccache_cfg_path: &Path, sccache_cached_cfg_path: &Path) {
    let envs: Vec<(_, &OsStr)> = vec![
        ("RUST_BACKTRACE", "1".as_ref()),
        ("SCCACHE_LOG", "debug".as_ref()),
        ("SCCACHE_CONF", sccache_cfg_path.as_ref()),
        ("SCCACHE_CACHED_CONF", sccache_cached_cfg_path.as_ref()),
    ];
    let source_file = "x.c";
    let obj_file = "x.o";
    write_source(
        tmpdir,
        source_file,
        "#if !defined(SCCACHE_TEST_DEFINE)\n#error SCCACHE_TEST_DEFINE is not defined\n#endif\nint x() { return 5; }",
    );
    sccache_command()
        .args([
            std::env::var("CC")
                .unwrap_or_else(|_| "gcc".to_string())
                .as_str(),
            "-c",
            "-DSCCACHE_TEST_DEFINE",
        ])
        .arg(tmpdir.join(source_file))
        .arg("-o")
        .arg(tmpdir.join(obj_file))
        .envs(envs)
        .assert()
        .success();
}

fn rust_compile(tmpdir: &Path, sccache_cfg_path: &Path, sccache_cached_cfg_path: &Path) -> Output {
    let sccache_path = env!("CARGO_BIN_EXE_sccache");
    let envs: Vec<(_, &OsStr)> = vec![
        ("RUSTC_WRAPPER", sccache_path.as_ref()),
        ("CARGO_TARGET_DIR", "target".as_ref()),
        ("RUST_BACKTRACE", "1".as_ref()),
        ("SCCACHE_LOG", "debug".as_ref()),
        ("SCCACHE_CONF", sccache_cfg_path.as_ref()),
        ("SCCACHE_CACHED_CONF", sccache_cached_cfg_path.as_ref()),
    ];
    let cargo_name = "sccache-dist-test";
    let cargo_path = init_cargo(tmpdir, cargo_name);

    let manifest_file = "Cargo.toml";
    let source_file = "src/main.rs";

    write_source(
        &cargo_path,
        manifest_file,
        r#"[package]
        name = "sccache-dist-test"
        version = "0.1.0"
        edition = "2021"
        [dependencies]
        # Pinned: the point of this test is that distributed compilation works,
        # not that it keeps up with whatever libc published most recently.
        libc = "=0.2.169""#,
    );
    write_source(
        &cargo_path,
        source_file,
        r#"fn main() {
        println!("Hello, world!");
}"#,
    );

    cargo_command()
        .current_dir(cargo_path)
        .args(["build", "--release"])
        .envs(envs)
        .output()
        .unwrap()
}

pub fn dist_test_sccache_client_cfg(
    tmpdir: &Path,
    scheduler_url: HTTPUrl,
) -> sccache::config::FileConfig {
    let mut sccache_cfg = harness::sccache_client_cfg(tmpdir, false);
    sccache_cfg.cache.disk.as_mut().unwrap().size = 0;
    sccache_cfg.dist.scheduler_url = Some(scheduler_url);
    sccache_cfg
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_basic() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_server();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

// A compile error on the build server reached the client as "Compiler killed by signal 1" with exit
// code 254 instead of the compiler's exit code.
#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_failed_compile() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_server();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);

    // An error the compiler finds, not the preprocessor: preprocessing runs locally, so an
    // `#error` would fail before anything is sent to the build server.
    write_source(
        tmpdir,
        "fail.c",
        "int x() { return sccache_dist_test_undeclared; }",
    );
    let output = sccache_command()
        .args([
            std::env::var("CC")
                .unwrap_or_else(|_| "gcc".to_string())
                .as_str(),
            "-c",
        ])
        .arg(tmpdir.join("fail.c"))
        .arg("-o")
        .arg(tmpdir.join("fail.o"))
        .envs(vec![
            ("RUST_BACKTRACE", OsStr::new("1")),
            ("SCCACHE_CONF", sccache_cfg_path.as_os_str()),
            ("SCCACHE_CACHED_CONF", sccache_cached_cfg_path.as_os_str()),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(!stdout.contains("killed by signal"), "stdout: {stdout}");
    assert!(
        stderr.contains("sccache_dist_test_undeclared"),
        "stderr: {stderr}"
    );

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_fails);
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_restartedserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let server_handle = system.add_server();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    system.restart_server(&server_handle);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(2, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(2, info.stats.compile_requests);
        assert_eq!(2, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(2, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_nobuilder() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(0, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

struct FailingServer;
impl ServerIncoming for FailingServer {
    fn handle_assign_job(&self, _job_id: JobId, _tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = false;
        let state = JobState::Ready;
        Ok(AssignJobResult {
            need_toolchain,
            state,
        })
    }
    fn handle_submit_toolchain(
        &self,
        _requester: &dyn ServerOutgoing,
        _job_id: JobId,
        _tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        panic!("should not have submitted toolchain")
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        _command: CompileCommand,
        _outputs: Vec<String>,
        _inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        requester
            .do_update_job_state(job_id, JobState::Started)
            .context("Updating job state failed")?;
        bail!("internal build failure")
    }
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_failingserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_custom_server(FailingServer);

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(0, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_cargo_build() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    rust_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path)
        .assert()
        .success();
    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(8, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_cargo_makeflags() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server();

    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    let compile_output = rust_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    assert!(
        !String::from_utf8_lossy(&compile_output.stderr)
            .contains("warning: failed to connect to jobserver from environment variable")
    );

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(8, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_preprocesspr_cache_bug_2173() {
    // Bug 2173: preprocessor cache hit but main cache miss - because using the preprocessor cache
    // means not doing regular preprocessing, there was no preprocessed translation unit to send
    // out for distributed compilation, so an empty u8 array was compiled - which "worked", but
    // the object file *was* the result of compiling an empty file.
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server();

    let mut sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let disk_cache = sccache_cfg.cache.disk.as_mut().unwrap();
    disk_cache
        .preprocessor_cache_mode
        .use_preprocessor_cache_mode = true;
    disk_cache.size = 10_000_000; // enough for one tiny object file
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);

    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);
    let obj_file = "x.o";
    let obj_path = tmpdir.join(obj_file);
    let data_a = std::fs::read(&obj_path).unwrap();

    let cache_path = sccache_cfg.cache.disk.unwrap().dir;

    // Don't touch the preprocessor cache - and check that it exists
    assert!(
        cache_path.join("preprocessor").is_dir(),
        "The preprocessor cache should exist"
    );

    // Delete the main cache to ensure a cache miss - potential dirs are "0".."f".
    let main_cache_dirs = "0123456789abcdef";
    let delete_count = main_cache_dirs.chars().fold(0, |res, dir| {
        res + (std::fs::remove_dir_all(cache_path.join(String::from(dir))).is_ok() as u32)
    });
    assert_eq!(delete_count, 1, "Did the disk cache format change?");

    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    // Check that this gave the same result (i.e. that it didn't compile a completely empty file).
    // It would be nice to check directly that the object file contains the symbol for the x() function
    // from basic_compile(), but that seems pretty involved and this happens to work...
    let data_b = std::fs::read(&obj_path).unwrap();

    assert_eq!(data_a, data_b);
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_toolchain() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = harness::sccache_dist_path();

    let mut system = harness::DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let server_handle = system.add_server();
    let sccache_cfg = dist_test_sccache_client_cfg(tmpdir, system.scheduler_url());
    let sccache_cfg_path = tmpdir.join("sccache-cfg.json");
    write_json_cfg(tmpdir, "sccache-cfg.json", &sccache_cfg);
    let sccache_cached_cfg_path = tmpdir.join("sccache-cached-cfg");
    stop_local_daemon();
    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    stop_local_daemon();
    clear_cache_local_daemon(tmpdir);

    start_local_daemon(&sccache_cfg_path, &sccache_cached_cfg_path);
    basic_compile(tmpdir, &sccache_cfg_path, &sccache_cached_cfg_path);

    assert_eq!(system.count_toolchains_on_server(&server_handle), 1);

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

struct RecordingScheduler {
    heartbeats: Arc<Mutex<Vec<ServerId>>>,
    accepted: mpsc::Sender<ServerId>,
}

impl SchedulerIncoming for RecordingScheduler {
    fn handle_alloc_job(
        &self,
        _requester: &dyn SchedulerOutgoing,
        _tc: Toolchain,
    ) -> Result<AllocJobResult> {
        panic!("should not have allocated a job")
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        _server_nonce: ServerNonce,
        _num_cpus: usize,
        _job_authorizer: Box<dyn JobAuthorizer>,
    ) -> Result<HeartbeatServerResult> {
        self.heartbeats.lock().unwrap().push(server_id);
        let _ = self.accepted.send(server_id);
        Ok(HeartbeatServerResult { is_new: true })
    }

    fn handle_update_job_state(
        &self,
        _job_id: JobId,
        _server_id: ServerId,
        _job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        Ok(SchedulerStatusResult {
            num_servers: self.heartbeats.lock().unwrap().len(),
            num_cpus: 1,
            in_progress: 0,
        })
    }
}

struct AcceptAnyClient;

impl sccache::dist::http::ClientAuthCheck for AcceptAnyClient {
    fn check(
        &self,
        _token: &str,
    ) -> std::result::Result<(), sccache::dist::http::ClientVisibleMsg> {
        Ok(())
    }
}

struct NullServer;

impl ServerIncoming for NullServer {
    fn handle_assign_job(&self, _job_id: JobId, _tc: Toolchain) -> Result<AssignJobResult> {
        panic!("should not have assigned a job")
    }

    fn handle_submit_toolchain(
        &self,
        _requester: &dyn ServerOutgoing,
        _job_id: JobId,
        _tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        panic!("should not have submitted a toolchain")
    }

    fn handle_run_job(
        &self,
        _requester: &dyn ServerOutgoing,
        _job_id: JobId,
        _command: CompileCommand,
        _outputs: Vec<String>,
        _inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        panic!("should not have run a job")
    }
}

fn wait_until<F: Fn() -> bool>(what: &str, f: F) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

const TEST_SERVER_TOKEN: &str = "test server token";

struct TestScheduler {
    addr: SocketAddr,
    auth_attempts: Arc<Mutex<Vec<ServerId>>>,
    heartbeats: Arc<Mutex<Vec<ServerId>>>,
    accepted: mpsc::Receiver<ServerId>,
}

fn start_test_scheduler(check_server_ip: bool) -> TestScheduler {
    let addr: SocketAddr = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };

    let auth_attempts = Arc::new(Mutex::new(Vec::new()));
    let heartbeats = Arc::new(Mutex::new(Vec::new()));
    let (accepted, accepted_rx) = mpsc::channel();
    let scheduler = sccache::dist::http::Scheduler::new(
        addr,
        RecordingScheduler {
            heartbeats: heartbeats.clone(),
            accepted,
        },
        Box::new(AcceptAnyClient),
        {
            let auth_attempts = auth_attempts.clone();
            Box::new(move |token| {
                let mut split = token.splitn(2, ' ');
                let addr = split.next().and_then(|addr| addr.parse().ok())?;
                match split.next() {
                    Some(token) if token == TEST_SERVER_TOKEN => {
                        let server_id = ServerId::new(addr);
                        auth_attempts.lock().unwrap().push(server_id);
                        Some(server_id)
                    }
                    _ => None,
                }
            })
        },
        check_server_ip,
    );
    std::thread::spawn(move || scheduler.start().expect("scheduler failed to start"));

    wait_until("scheduler to listen", || TcpStream::connect(addr).is_ok());
    TestScheduler {
        addr,
        auth_attempts,
        heartbeats,
        accepted: accepted_rx,
    }
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_check_server_ip_disabled_accepts_mismatched_ip() {
    // The server advertises an address that is not the one it connects from.
    let public_addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let scheduler = start_test_scheduler(false);

    let server = sccache::dist::http::Server::new(
        public_addr,
        Some("127.0.0.1:0".parse().unwrap()),
        reqwest::Url::parse(&format!("http://{}", scheduler.addr)).unwrap(),
        format!("{public_addr} {TEST_SERVER_TOKEN}"),
        NullServer,
    )
    .unwrap();
    std::thread::spawn(move || server.start().expect("server failed to start"));

    wait_until("server heartbeat attempt", || {
        !scheduler.auth_attempts.lock().unwrap().is_empty()
    });
    assert_eq!(
        scheduler.auth_attempts.lock().unwrap().as_slice(),
        &[ServerId::new(public_addr)]
    );
    // Sanity check that the advertised IP really differs from the connection's source IP.
    assert_ne!(public_addr.ip(), scheduler.addr.ip());

    let accepted = scheduler
        .accepted
        .recv_timeout(Duration::from_secs(5))
        .expect("scheduler rejected a heartbeat from a mismatched IP");
    assert_eq!(accepted, ServerId::new(public_addr));
    assert_eq!(
        scheduler.heartbeats.lock().unwrap().as_slice(),
        &[ServerId::new(public_addr)]
    );
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_check_server_ip_enabled_rejects_mismatched_ip() {
    // The server advertises an address that is not the one it connects from.
    let public_addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let scheduler = start_test_scheduler(true);

    let server = sccache::dist::http::Server::new(
        public_addr,
        Some("127.0.0.1:0".parse().unwrap()),
        reqwest::Url::parse(&format!("http://{}", scheduler.addr)).unwrap(),
        format!("{public_addr} {TEST_SERVER_TOKEN}"),
        NullServer,
    )
    .unwrap();
    std::thread::spawn(move || server.start().expect("server failed to start"));

    wait_until("server heartbeat attempt", || {
        !scheduler.auth_attempts.lock().unwrap().is_empty()
    });
    assert_eq!(
        scheduler.auth_attempts.lock().unwrap().as_slice(),
        &[ServerId::new(public_addr)]
    );
    // Sanity check that the advertised IP really differs from the connection's source IP.
    assert_ne!(public_addr.ip(), scheduler.addr.ip());

    assert!(
        scheduler
            .accepted
            .recv_timeout(Duration::from_secs(1))
            .is_err(),
        "scheduler accepted a heartbeat from a mismatched IP"
    );
    assert!(scheduler.heartbeats.lock().unwrap().is_empty());
}
