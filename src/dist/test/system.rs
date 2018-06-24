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

use config::{self, HIDDEN_FILE_CONFIG_DATA_VAR, FileConfig};
use dist::{
    DistBuilderHandler,
    BuildResult,
};
use compiler::CompileResult;
use env_logger;
use std::env;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use tempdir::TempDir;
use test::system::{find_compilers, run_sccache_command_test};
use test::utils::{find_sccache_binary};
use uuid::Uuid;

use super::super::*;

const IMAGE: &str = "aidanhs/ubuntu-docker:18.04-17.03.2-ce";
const CONTAINER_NAME_PREFIX: &str = "sccache_dist_test";

struct DistSystem {
    scheduler_name: String,
    server_names: Vec<String>,
}

fn make_container_name(tag: &str) -> String {
    format!("{}_{}_{}", CONTAINER_NAME_PREFIX, tag, Uuid::new_v4().hyphenated())
}

fn check_output(output: &Output) {
    if !output.status.success() {
        error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
}

impl DistSystem {
    fn new_with_scheduler(sccache: &Path, cfg: FileConfig) -> Self {
        let scheduler_name = make_container_name("scheduler");
        let output = Command::new("docker")
            .args(&[
                "run",
                "-e", "SCCACHE_START_SCHEDULER=1",
                "--name", &scheduler_name,
                "-e", "RUST_LOG=sccache=debug",
                "-e", "RUST_BACKTRACE=1",
                "-e", &format!("{}={}", HIDDEN_FILE_CONFIG_DATA_VAR, serde_json::to_string(&cfg).unwrap()),
                "-v", &format!("{}:/sccache", sccache.to_str().unwrap()),
                "-d", "--rm",
                IMAGE,
                "/sccache"
            ]).output().unwrap();
        check_output(&output);

        DistSystem {
            scheduler_name,
            server_names: vec![],
        }
    }

    fn add_server(&mut self, sccache: &Path, cfg: FileConfig) {
        let server_name = make_container_name("server");
        let output = Command::new("docker")
            .args(&[
                "run",
                "-e", "SCCACHE_START_DIST_SERVER=1",
                "--name", &server_name,
                "-e", "RUST_LOG=sccache=debug",
                "-e", "RUST_BACKTRACE=1",
                "-e", &format!("{}={}", HIDDEN_FILE_CONFIG_DATA_VAR, serde_json::to_string(&cfg).unwrap()),
                "-v", &format!("{}:/sccache", sccache.to_str().unwrap()),
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-d", "--rm",
                IMAGE,
                "/sccache"
            ]).output().unwrap();
        check_output(&output);

        self.server_names.push(server_name);
    }

    fn get_scheduler_ip(&self) -> IpAddr {
        let output = Command::new("docker")
            .args(&["inspect", "--format", "{{ .NetworkSettings.IPAddress }}", &self.scheduler_name]).output().unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned().parse().unwrap()
    }
}

impl Drop for DistSystem {
    fn drop(&mut self) {
        let mut logs = vec![];
        let mut outputs = vec![];

        logs.push((&self.scheduler_name, Command::new("docker").args(&["logs", &self.scheduler_name]).output().unwrap()));
        outputs.push(Command::new("docker").args(&["kill", &self.scheduler_name]).output().unwrap());
        for server_name in self.server_names.iter() {
            logs.push((&server_name, Command::new("docker").args(&["logs", &server_name]).output().unwrap()));
            outputs.push(Command::new("docker").args(&["kill", server_name]).output().unwrap());
        }

        for (container, Output { status, stdout, stderr }) in logs {
            println!("====\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                container, String::from_utf8_lossy(&stdout), String::from_utf8_lossy(&stderr));
        }
        for output in outputs {
            // TODO: there's no output from the containers if this fails (because they've died already),
            // I think the only way to fix this is to have a thread appending output to an in-memory log
            check_output(&output)
        }
    }
}

struct FailingBuilder;

impl DistBuilderHandler for FailingBuilder {
    fn handle_compile_request(&self, req: BuildRequest) -> SFuture<BuildResult> {
        f_err("FailingBuilder")
    }
}

fn run_compile(cmd: &[&str], addr: SocketAddr) -> CompileResult {
    panic!()
}

lazy_static! {
    static ref SERVER_MUTEX: Mutex<()> = Mutex::new(());
}

struct EnvSetter;
impl Drop for EnvSetter {
    fn drop(&mut self) {
        env::remove_var(HIDDEN_FILE_CONFIG_DATA_VAR)
    }
}

fn lock_local_server(cfg: FileConfig) -> (MutexGuard<'static, ()>, EnvSetter) {
    // TODO: poisons
    env::set_var(HIDDEN_FILE_CONFIG_DATA_VAR, serde_json::to_string(&cfg).unwrap());
    (SERVER_MUTEX.lock().unwrap(), EnvSetter)
}

//#[test]
//fn failing_builder() {
//    let sched_addr = "127.0.0.1:9000".parse().unwrap();
//    let dserver_addr = "127.0.0.1:9001".parse().unwrap();
//    let dclient_addr = "127.0.0.1:9002".parse().unwrap();
//
//    let sched = SccacheScheduler::new();
//    let dclient = SccacheDaemonClient::new(dclient_addr);
//    let builder = FailingBuilder;
//    let dserver = SccacheDaemonServer::new(dserver_addr, builder);
//
//    let system = standup_system(Box::new(sched), vec![Box::new(dserver)], vec![Box::new(dclient)]);
//    let result = run_compile(&["gcc", "test.c"], dclient_addr);
//
//    // TODO: Assert scheduler state has 0 active jobs and one failed with error job
//    assert!(false);
//    // TODO: Assert job success because daemon client should have fallen back to performing compilation locally
//    assert!(false);
//}

#[test]
fn test_sccache_command() {
    match env_logger::init() {
        Ok(_) => {},
        Err(_) => {},
    }

    let tempdir = TempDir::new("sccache_system_test").unwrap();
    let sccache = find_sccache_binary();
    // TODO: the packager can't handle binaries that aren't called 'gcc' or 'clang'
    //let compilers = find_compilers();
    use test::system::Compiler;
    let compilers = vec![
        Compiler {
            name: "gcc",
            exe: "/usr/bin/gcc".into(),
            env_vars: vec![],
        }
    ];
    if compilers.is_empty() {
        assert!(env::var_os("CI").is_none());
        warn!("No compilers found, skipping test");
        return
    }

    let scheduler_cfg: FileConfig = Default::default();
    let mut system = DistSystem::new_with_scheduler(&sccache, scheduler_cfg);
    let mut server_cfg: FileConfig = Default::default();
    server_cfg.dist.scheduler_addr = Some(system.get_scheduler_ip());
    system.add_server(&sccache, server_cfg);

    let mut client_cfg: FileConfig = Default::default();
    client_cfg.dist.scheduler_addr = Some(system.get_scheduler_ip());
    client_cfg.dist.cache_dir = tempdir.path().join("client_tc_cache");
    let _guard = lock_local_server(client_cfg);
    for compiler in compilers {
        run_sccache_command_test(&sccache, compiler, tempdir.path())
    }
}
