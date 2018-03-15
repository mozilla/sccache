#![allow(non_camel_case_types, unused)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use futures::Future;

#[cfg(test)]
#[macro_use]
mod test;

#[derive(Hash, Eq, PartialEq)]
struct JobId(u64);
struct DaemonId(u64);

struct JobRequest;
struct JobResult;

struct JobAllocRequest;
struct JobAllocResult;

struct AllocAssignment;

struct CompileRequest;
struct CompileResult;

struct BuildRequest;
struct BuildResult;

trait Scheduler {
    // From DaemonClient
    fn allocation_request(&self, JobAllocRequest) -> Box<Future<Item=JobAllocResult, Error=()>>;
}

trait DaemonClient {
    // From Client
    fn compile_request(&self, CompileRequest) -> Box<Future<Item=CompileResult, Error=()>>;
}

trait DaemonServer {
    // From Scheduler
    fn allocation_assign(&self, AllocAssignment) -> Box<Future<Item=(), Error=()>>;
    // From DaemonClient
    fn compile_request(&self, JobRequest) -> Box<Future<Item=JobResult, Error=()>>;
}

trait Builder {
    // From DaemonServer
    fn compile_request(&self, BuildRequest) -> Box<Future<Item=BuildResult, Error=()>>;
}

enum JobStatus {
    AllocRequested(JobAllocRequest),
    AllocSuccess(DaemonId, JobAllocRequest, JobAllocResult),
    JobStarted(DaemonId, JobAllocRequest, JobAllocResult),
    JobCompleted(DaemonId, JobAllocRequest, JobAllocResult),
    // Interrupted by some error in distributed sccache
    // or maybe a failure to allocate. Nothing to do with the
    // compilation itself.
    JobFailed(DaemonId, JobAllocRequest, JobAllocResult),
}

struct SccacheScheduler {
    jobs: HashMap<JobId, JobStatus>,

    // Acts as a ring buffer of most recently completed jobs
    finished_jobs: VecDeque<JobStatus>,
}

impl SccacheScheduler {
    fn new(addr: SocketAddr) -> SccacheScheduler {
        SccacheScheduler { jobs: HashMap::new(), finished_jobs: VecDeque::new() }
    }
}

impl Scheduler for SccacheScheduler {
    fn allocation_request(&self, req: JobAllocRequest) -> Box<Future<Item=JobAllocResult, Error=()>> {
        panic!()
    }
}

struct SccacheDaemonClient;

impl SccacheDaemonClient {
    fn new(addr: SocketAddr) -> SccacheDaemonClient {
        SccacheDaemonClient
    }
}

impl DaemonClient for SccacheDaemonClient {
    // From Client
    fn compile_request(&self, req: CompileRequest) -> Box<Future<Item=CompileResult, Error=()>> {
        panic!()
    }
}

struct SccacheDaemonServer;

impl SccacheDaemonServer {
    fn new<B: Builder>(addr: SocketAddr, builder: B) -> SccacheDaemonServer {
        SccacheDaemonServer
    }
}

impl DaemonServer for SccacheDaemonServer {
    // From Scheduler
    fn allocation_assign(&self, alloc: AllocAssignment) -> Box<Future<Item=(), Error=()>> {
        panic!()
    }
    // From DaemonClient
    fn compile_request(&self, req: JobRequest) -> Box<Future<Item=JobResult, Error=()>> {
        panic!()
    }
}

struct SccacheBuilder;

impl SccacheBuilder {
    fn new() -> SccacheBuilder {
        SccacheBuilder
    }
}

impl Builder for SccacheBuilder {
    // From DaemonServer
    fn compile_request(&self, req: BuildRequest) -> Box<Future<Item=BuildResult, Error=()>> {
        panic!()
    }
}
