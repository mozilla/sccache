use std::time::Duration;
use std::net::SocketAddr;
use std::thread;

use super::super::*;

struct DockerSystem;

impl DockerSystem {
    fn new() -> Self {
        DockerSystem
    }

    fn new_machine(&self) -> Machine {
        panic!()
    }

    // Check up on the services in each machine
    fn is_healthy(&self) -> bool {
        panic!()
    }
}

struct Machine;

impl Machine {
    fn socket_addr() -> SocketAddr {
        panic!()
    }

    fn add_scheduler(&self) -> SocketAddr {
        panic!()
    }
    fn add_daemon_server(&self, sched_addr: SocketAddr) {
        panic!()
    }
    fn add_daemon_client(&self, sched_addr: SocketAddr) -> SocketAddr {
        panic!()
    }

    fn add_monkey(&self, m: MachineMonkey) {
        panic!()
    }
}

enum MachineMonkey {
    ConnectionDrops,
}

fn run_compile(cmd: &[&str], addr: SocketAddr) -> CompileResult {
    panic!()
}

#[test]
fn unclean_dserver_disconnects() {
    let sys = DockerSystem;

    let sched_machine = sys.new_machine();
    let sched_addr = sched_machine.add_scheduler();

    let build_machine = sys.new_machine();
    build_machine.add_daemon_server(sched_addr);

    let client_machine = sys.new_machine();
    let dclient_addr = client_machine.add_daemon_client(sched_addr);

    build_machine.add_monkey(MachineMonkey::ConnectionDrops);

    for i in 0..20 {
        let res = run_compile(&["gcc", "test.c"], dclient_addr);
        // TODO: Assert job success
        assert!(false);
        thread::sleep(Duration::from_millis(500));
    }

    assert!(sys.is_healthy());
}
