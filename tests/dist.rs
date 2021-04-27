#![cfg(all(feature = "dist-client", feature = "dist-server"))]

extern crate assert_cmd;
#[macro_use]
extern crate log;
extern crate cachepot;
extern crate serde_json;

use crate::harness::{
    get_stats, cachepot_command, start_local_daemon, stop_local_daemon, write_json_cfg, write_source,
};
use assert_cmd::prelude::*;
use cachepot::config::HTTPUrl;
use cachepot::dist::{
    AssignJobResult, CompileCommand, InputsReader, JobId, JobState, RunJobResult, ServerIncoming,
    ServerOutgoing, SubmitToolchainResult, Toolchain, ToolchainReader,
};
use serial_test::serial;
use std::ffi::OsStr;
use std::path::Path;

use cachepot::errors::*;

mod harness;

fn basic_compile(tmpdir: &Path, cachepot_cfg_path: &Path, cachepot_cached_cfg_path: &Path) {
    let envs: Vec<(_, &OsStr)> = vec![
        ("RUST_BACKTRACE", "1".as_ref()),
        ("RUST_LOG", "cachepot=trace".as_ref()),
        ("CACHEPOT_CONF", cachepot_cfg_path.as_ref()),
        ("CACHEPOT_CACHED_CONF", cachepot_cached_cfg_path.as_ref()),
    ];
    let source_file = "x.c";
    let obj_file = "x.o";
    write_source(tmpdir, source_file, "#if !defined(CACHEPOT_TEST_DEFINE)\n#error CACHEPOT_TEST_DEFINE is not defined\n#endif\nint x() { return 5; }");
    cachepot_command()
        .arg(std::env::var("CC").unwrap_or_else(|_| "gcc".to_string()))
        .args(&["-c", "-DCACHEPOT_TEST_DEFINE"])
        .arg(tmpdir.join(source_file))
        .arg("-o")
        .arg(tmpdir.join(obj_file))
        .envs(envs)
        .assert()
        .success();
}

pub fn dist_test_cachepot_client_cfg(
    tmpdir: &Path,
    scheduler_url: HTTPUrl,
) -> cachepot::config::FileConfig {
    let mut cachepot_cfg = harness::cachepot_client_cfg(tmpdir);
    cachepot_cfg.cache.disk.as_mut().unwrap().size = 0;
    cachepot_cfg.dist.scheduler_url = Some(scheduler_url);
    cachepot_cfg
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
#[serial]
fn test_dist_basic() {
    let tmpdir = tempfile::Builder::new()
        .prefix("cachepot_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let cachepot_dist = harness::cachepot_dist_path();

    let mut system = harness::DistSystem::new(&cachepot_dist, tmpdir);
    system.add_scheduler();
    system.add_server();

    let cachepot_cfg = dist_test_cachepot_client_cfg(tmpdir, system.scheduler_url());
    let cachepot_cfg_path = tmpdir.join("cachepot-cfg.json");
    write_json_cfg(tmpdir, "cachepot-cfg.json", &cachepot_cfg);
    let cachepot_cached_cfg_path = tmpdir.join("cachepot-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&cachepot_cfg_path, &cachepot_cached_cfg_path);
    basic_compile(tmpdir, &cachepot_cfg_path, &cachepot_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(1, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(0, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}

#[test]
#[cfg_attr(not(feature = "dist-tests"), ignore)]
#[serial]
fn test_dist_restartedserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("cachepot_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let cachepot_dist = harness::cachepot_dist_path();

    let mut system = harness::DistSystem::new(&cachepot_dist, tmpdir);
    system.add_scheduler();
    let server_handle = system.add_server();

    let cachepot_cfg = dist_test_cachepot_client_cfg(tmpdir, system.scheduler_url());
    let cachepot_cfg_path = tmpdir.join("cachepot-cfg.json");
    write_json_cfg(tmpdir, "cachepot-cfg.json", &cachepot_cfg);
    let cachepot_cached_cfg_path = tmpdir.join("cachepot-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&cachepot_cfg_path, &cachepot_cached_cfg_path);
    basic_compile(tmpdir, &cachepot_cfg_path, &cachepot_cached_cfg_path);

    system.restart_server(&server_handle);
    basic_compile(tmpdir, &cachepot_cfg_path, &cachepot_cached_cfg_path);

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
#[serial]
fn test_dist_nobuilder() {
    let tmpdir = tempfile::Builder::new()
        .prefix("cachepot_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let cachepot_dist = harness::cachepot_dist_path();

    let mut system = harness::DistSystem::new(&cachepot_dist, tmpdir);
    system.add_scheduler();

    let cachepot_cfg = dist_test_cachepot_client_cfg(tmpdir, system.scheduler_url());
    let cachepot_cfg_path = tmpdir.join("cachepot-cfg.json");
    write_json_cfg(tmpdir, "cachepot-cfg.json", &cachepot_cfg);
    let cachepot_cached_cfg_path = tmpdir.join("cachepot-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&cachepot_cfg_path, &cachepot_cached_cfg_path);
    basic_compile(tmpdir, &cachepot_cfg_path, &cachepot_cached_cfg_path);

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
#[serial]
fn test_dist_failingserver() {
    let tmpdir = tempfile::Builder::new()
        .prefix("cachepot_dist_test")
        .tempdir()
        .unwrap();
    let tmpdir = tmpdir.path();
    let cachepot_dist = harness::cachepot_dist_path();

    let mut system = harness::DistSystem::new(&cachepot_dist, tmpdir);
    system.add_scheduler();
    system.add_custom_server(FailingServer);

    let cachepot_cfg = dist_test_cachepot_client_cfg(tmpdir, system.scheduler_url());
    let cachepot_cfg_path = tmpdir.join("cachepot-cfg.json");
    write_json_cfg(tmpdir, "cachepot-cfg.json", &cachepot_cfg);
    let cachepot_cached_cfg_path = tmpdir.join("cachepot-cached-cfg");

    stop_local_daemon();
    start_local_daemon(&cachepot_cfg_path, &cachepot_cached_cfg_path);
    basic_compile(tmpdir, &cachepot_cfg_path, &cachepot_cached_cfg_path);

    get_stats(|info| {
        assert_eq!(0, info.stats.dist_compiles.values().sum::<usize>());
        assert_eq!(1, info.stats.dist_errors);
        assert_eq!(1, info.stats.compile_requests);
        assert_eq!(1, info.stats.requests_executed);
        assert_eq!(0, info.stats.cache_hits.all());
        assert_eq!(1, info.stats.cache_misses.all());
    });
}
