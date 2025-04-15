#![cfg(all(feature = "dist-client", feature = "dist-server"))]

extern crate assert_cmd;
#[macro_use]
extern crate log;
extern crate sccache;
extern crate serde_json;

use crate::harness::{
    client::{sccache_client_cfg, SccacheClient},
    dist::{cargo_command, sccache_dist_path, DistSystem},
    init_cargo, write_source,
};
use assert_cmd::prelude::*;
use sccache::config::HTTPUrl;
use sccache::dist::{
    AssignJobResult, CompileCommand, InputsReader, JobId, JobState, RunJobResult, ServerIncoming,
    ServerOutgoing, SubmitToolchainResult, Toolchain, ToolchainReader,
};
use std::path::Path;
use std::process::Output;

use sccache::errors::*;

mod harness;

fn basic_compile(client: &SccacheClient, tmpdir: &Path) {
    let source_file = "x.c";
    let obj_file = "x.o";
    write_source(tmpdir, source_file, "#if !defined(SCCACHE_TEST_DEFINE)\n#error SCCACHE_TEST_DEFINE is not defined\n#endif\nint x() { return 5; }");
    client
        .cmd()
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
        .env("RUST_BACKTRACE", "1")
        .env("SCCACHE_RECACHE", "1")
        .assert()
        .success();
}

fn rust_compile(client: &SccacheClient, tmpdir: &Path) -> Output {
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
        libc = "0.2.169""#,
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
        .envs(
            client
                .cmd()
                .get_envs()
                .map(|(k, v)| (k, v.unwrap_or_default())),
        )
        .env("RUSTC_WRAPPER", &client.path)
        .env("CARGO_TARGET_DIR", "target")
        .env("RUST_BACKTRACE", "1")
        .env("SCCACHE_RECACHE", "1")
        .output()
        .unwrap()
}

pub fn dist_test_sccache_client_cfg(
    tmpdir: &Path,
    scheduler_url: HTTPUrl,
) -> sccache::config::FileConfig {
    let mut sccache_cfg = sccache_client_cfg(tmpdir, false);
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
    let sccache_dist = sccache_dist_path();

    let mut system = DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_server();

    let client = system.new_client(&dist_test_sccache_client_cfg(
        tmpdir,
        system.scheduler_url(),
    ));

    basic_compile(&client, tmpdir);

    let stats = client.stats().unwrap();

    assert_eq!(1, stats.dist_compiles.values().sum::<usize>());
    assert_eq!(0, stats.dist_errors);
    assert_eq!(1, stats.compile_requests);
    assert_eq!(1, stats.requests_executed);
    assert_eq!(0, stats.cache_hits.all());
    assert_eq!(1, stats.cache_misses.all());
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_restartedserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = sccache_dist_path();

    let mut system = DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let server_handle = system.add_server();

    let client = system.new_client(&dist_test_sccache_client_cfg(
        tmpdir,
        system.scheduler_url(),
    ));

    basic_compile(&client, tmpdir);

    system.restart_server(&server_handle);

    basic_compile(&client, tmpdir);

    let stats = client.stats().unwrap();

    assert_eq!(2, stats.dist_compiles.values().sum::<usize>());
    assert_eq!(0, stats.dist_errors);
    assert_eq!(2, stats.compile_requests);
    assert_eq!(2, stats.requests_executed);
    assert_eq!(0, stats.cache_hits.all());
    assert_eq!(2, stats.cache_misses.all());
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_nobuilder() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = sccache_dist_path();

    let mut system = DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();

    let client = system.new_client(&dist_test_sccache_client_cfg(
        tmpdir,
        system.scheduler_url(),
    ));

    basic_compile(&client, tmpdir);

    let stats = client.stats().unwrap();

    assert_eq!(0, stats.dist_compiles.values().sum::<usize>());
    assert_eq!(1, stats.dist_errors);
    assert_eq!(1, stats.compile_requests);
    assert_eq!(1, stats.requests_executed);
    assert_eq!(0, stats.cache_hits.all());
    assert_eq!(1, stats.cache_misses.all());
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
    let sccache_dist = sccache_dist_path();

    let mut system = DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    system.add_custom_server(FailingServer);

    let client = system.new_client(&dist_test_sccache_client_cfg(
        tmpdir,
        system.scheduler_url(),
    ));

    basic_compile(&client, tmpdir);

    let stats = client.stats().unwrap();

    assert_eq!(0, stats.dist_compiles.values().sum::<usize>());
    assert_eq!(1, stats.dist_errors);
    assert_eq!(1, stats.compile_requests);
    assert_eq!(1, stats.requests_executed);
    assert_eq!(0, stats.cache_hits.all());
    assert_eq!(1, stats.cache_misses.all());
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
fn test_dist_cargo_build() {
    let tmpdir = tempfile::Builder::new()
        .prefix("sccache_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let sccache_dist = sccache_dist_path();

    let mut system = DistSystem::new(&sccache_dist, tmpdir);
    system.add_scheduler();
    let _server_handle = system.add_server();

    let client = system.new_client(&dist_test_sccache_client_cfg(
        tmpdir,
        system.scheduler_url(),
    ));

    let compile_output = rust_compile(&client, tmpdir);

    // Ensure sccache ignores inherited jobservers in CARGO_MAKEFLAGS
    assert!(!String::from_utf8_lossy(&compile_output.stderr)
        .contains("warning: failed to connect to jobserver from environment variable"));

    // Assert compilation succeeded
    compile_output.assert().success();

    let stats = client.stats().unwrap();

    assert_eq!(1, stats.dist_compiles.values().sum::<usize>());
    assert_eq!(0, stats.dist_errors);
    // check >= 5 because cargo >=1.82 does additional requests with -vV
    assert!(stats.compile_requests >= 5);
    assert_eq!(1, stats.requests_executed);
    assert_eq!(0, stats.cache_hits.all());
    assert_eq!(1, stats.cache_misses.all());
}
