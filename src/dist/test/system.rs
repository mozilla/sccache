use std::net::SocketAddr;

use super::super::*;

use futures::future;

struct RunningSystem {
    daemon_clients: Vec<Box<DaemonClient>>
}

fn standup_system(sched: Box<Scheduler>, dservers: Vec<Box<DaemonServer>>, dclients: Vec<Box<DaemonClient>>) -> RunningSystem {
    panic!()
}

struct FailingBuilder;

impl Builder for FailingBuilder {
    fn compile_request(&self, req: BuildRequest) -> Box<Future<Item=BuildResult, Error=()>> {
        Box::new(future::err(()))
    }
}

fn run_compile(cmd: &[&str], addr: SocketAddr) -> CompileResult {
    panic!()
}

#[test]
fn failing_builder() {
    let sched_addr = "127.0.0.1:9000".parse().unwrap();
    let dserver_addr = "127.0.0.1:9001".parse().unwrap();
    let dclient_addr = "127.0.0.1:9002".parse().unwrap();

    let sched = SccacheScheduler::new(sched_addr);
    let dclient = SccacheDaemonClient::new(dclient_addr);
    let builder = FailingBuilder;
    let dserver = SccacheDaemonServer::new(dserver_addr, builder);

    let system = standup_system(Box::new(sched), vec![Box::new(dserver)], vec![Box::new(dclient)]);
    let result = run_compile(&["gcc", "test.c"], dclient_addr);

    // TODO: Assert scheduler state has 0 active jobs and one failed with error job
    assert!(false);
    // TODO: Assert job success because daemon client should have fallen back to performing compilation locally
    assert!(false);
}
