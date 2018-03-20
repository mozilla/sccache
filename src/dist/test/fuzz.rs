use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use super::super::*; // dist/mod.rs
use super::super::super::test::utils;

const BUCKET_NAME: &str = "mybucket";

struct DockerSystem {
}

fn container_ip(cid: &str) -> IpAddr {
    let output = Command::new("docker").args(&["inspect", "-f={{ .NetworkSettings.IPAddress }}", &cid]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout.trim().parse().unwrap()
}

impl DockerSystem {
    fn new() -> Self {
        DockerSystem {}
    }

    fn new_machine(&self) -> Machine {
        let sccache = utils::find_sccache_binary();
        let volume_mount = format!("{}:/sccache", sccache.to_str().unwrap());
        let cid = {
            // This odd construction is to ensure bash stays as the root process - without
            // the &&, bash will just exec since it's the last command in the pipeline.
            let cmd = "sleep infinity && true";
            let args = &["run", "--rm", "-d", "-v", &volume_mount, "aidanhs/commondockenv", "bash", "-c", cmd];
            let output = Command::new("docker").args(args).output().unwrap();
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        let ip_addr = container_ip(&cid);
        Machine {
            cid,
            ip_addr,
        }
    }
    fn new_s3(&self) -> SocketAddr {
        let cid = {
            let args = &["run", "--rm", "-d", "-e=MINIO_ACCESS_KEY=foobar123", "-e=MINIO_SECRET_KEY=foobar123",
                "minio/minio:RELEASE.2018-03-19T19-22-06Z", "server", "--address", ":4572", "/data"];
            let output = Command::new("docker").args(args).output().unwrap();
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        let status = Command::new("docker")
            .args(&["exec", &cid, "sh", "-c", &format!("export AWS_ACCESS_KEY_ID=foobar123 AWS_SECRET_ACCESS_KEY=foobar123 && apk update && apk add py2-pip && pip install awscli && aws --endpoint=http://localhost:4572 s3 mb s3://{}", BUCKET_NAME)])
            .status().unwrap();
        assert!(status.success());
        let ip_addr = container_ip(&cid);
        SocketAddr::new(ip_addr, 4572)
    }

    // Check up on the services in each machine
    fn is_healthy(&self) -> bool {
        panic!()
    }
}

enum CacheLocation {
    S3(SocketAddr, String), // endpoint, bucket
    None,
}

struct Machine {
    cid: String,
    ip_addr: IpAddr,
}

impl Machine {
    fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    fn add_scheduler(&self) -> SocketAddr {
        panic!()
    }
    fn add_daemon_server(&self, sched_addr: SocketAddr) {
        panic!()
    }
    fn add_daemon_client(&self, sched_addr: Option<SocketAddr>, cache_loc: CacheLocation) -> SocketAddr {
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", "-d"]).arg("-e=SCCACHE_SERVER_PORT=9000");
        match cache_loc {
            CacheLocation::S3(endpoint, bucket) => {
                cmd.arg(format!("-e=SCCACHE_ENDPOINT={}", endpoint.to_string()));
                cmd.arg(format!("-e=SCCACHE_BUCKET={}", bucket));
                cmd.arg(format!("-e=AWS_ACCESS_KEY_ID=foobar123"));
                cmd.arg(format!("-e=AWS_SECRET_ACCESS_KEY=foobar123"));
            },
            CacheLocation::None => (),
        };
        cmd.args(&[&self.cid, "/sccache", "--start-server"]);
        let status = cmd.status().unwrap();
        assert!(status.success());
        // TODO: wait for is_healthy
        // TODO: dynamically choose port
        SocketAddr::new(self.ip_addr, 9000)
    }

    fn add_monkey(&self, m: MachineMonkey) {
        match m {
            MachineMonkey::ConnectionDrops => {
                let cid = self.cid.clone();
                thread::spawn(move || {
                    loop {
                        let status = Command::new("docker").args(&["network", "disconnect", "bridge", &cid]).status().unwrap();
                        assert!(status.success());
                        thread::sleep(Duration::from_millis(1000));
                        let status = Command::new("docker").args(&["network", "connect", "bridge", &cid]).status().unwrap();
                        assert!(status.success());
                        thread::sleep(Duration::from_millis(1000));
                    }
                });
            },
        }
    }

    fn invoke_sccache(&self, input: &Path, output: &Path, client_addr: SocketAddr) {
        let input_file = input.file_name().unwrap().to_str().unwrap();
        let output_file = output.file_name().unwrap().to_str().unwrap();
        let status = Command::new("docker").arg("cp")
            .args(&[input.to_str().unwrap(), &format!("{}:{}", self.cid, input_file)]).status().unwrap();
        assert!(status.success());

        let mut cmd = Command::new("docker");
        cmd.arg("exec").arg(format!("-e=SCCACHE_SERVER_PORT={}", client_addr.port()));
        // See compile_cmdline in src/test/system.rs
        cmd.args(&[&self.cid, "/sccache", "gcc", "-c", input_file, "-o", output_file]);
        let status = cmd.status().unwrap();
        assert!(status.success());
        //assert_eq!(true, fs::metadata(&OUTPUT).and_then(|m| Ok(m.len() > 0)).unwrap());
    }
}

enum MachineMonkey {
    ConnectionDrops,
}

fn run_compile(cmd: &[&str], addr: SocketAddr) -> CompileResult {
    panic!()
}

#[test]
fn flaky_connection_to_s3() {
    let sys = DockerSystem::new();

    let s3_addr = sys.new_s3();

    let client_machine = sys.new_machine();
    let cacheloc = CacheLocation::S3(s3_addr, BUCKET_NAME.to_owned());
    let dclient_addr = client_machine.add_daemon_client(None, cacheloc);
    client_machine.add_monkey(MachineMonkey::ConnectionDrops);

    let input = Path::new("src/test/test.c");
    let output = Path::new("src/test/test.o");

    let sccache = utils::find_sccache_binary();
    thread::sleep(Duration::from_millis(1000));
    for i in 0..20 {
        client_machine.invoke_sccache(input, output, dclient_addr);
        thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn unclean_dserver_disconnects() {
    let sys = DockerSystem::new();

    let sched_machine = sys.new_machine();
    let sched_addr = sched_machine.add_scheduler();

    let build_machine = sys.new_machine();
    build_machine.add_daemon_server(sched_addr);

    let client_machine = sys.new_machine();
    let dclient_addr = client_machine.add_daemon_client(Some(sched_addr), CacheLocation::None);

    build_machine.add_monkey(MachineMonkey::ConnectionDrops);

    for i in 0..20 {
        let res = run_compile(&["gcc", "test.c"], dclient_addr);
        // TODO: Assert job success
        assert!(false);
        thread::sleep(Duration::from_millis(500));
    }

    assert!(sys.is_healthy());
}
