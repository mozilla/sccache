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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use futures::Future;
use num_cpus;
use reqwest;
use rouille;
use serde_json;
use std::time::Duration;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use super::cache;
use super::{
    ServerId, JobId, Toolchain, CompileCommand,
    ToolchainReader, InputsReader,

    AllocJobResult, JobAlloc,
    AssignJobResult,
    HeartbeatServerResult,
    RunJobResult,
    StatusResult,
    SubmitToolchainResult,
    UpdateJobStatusResult, JobStatus,

    SchedulerIncoming, SchedulerOutgoing,
    ServerIncoming, ServerOutgoing,
};
use tokio_core;

use errors::*;

const SCHEDULER_PORT: u16 = 10500;
const SERVER_PORT: u16 = 10501;

// TODO: move this into the config module
struct Cfg;

impl Cfg {
    fn scheduler_listen_addr() -> SocketAddr {
        let ip_addr = "0.0.0.0".parse().unwrap();
        SocketAddr::new(ip_addr, SCHEDULER_PORT)
    }
    fn scheduler_connect_addr(scheduler_addr: IpAddr) -> SocketAddr {
        SocketAddr::new(scheduler_addr, SCHEDULER_PORT)
    }

    fn server_listen_addr() -> SocketAddr {
        let ip_addr = "0.0.0.0".parse().unwrap();
        SocketAddr::new(ip_addr, SERVER_PORT)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatServerHttpRequest {
    num_cpus: usize,
    port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocJobHttpRequest {
    pub toolchain: Toolchain,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignJobHttpRequest {
    job_id: JobId,
    toolchain: Toolchain,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunJobHttpRequest {
    job_id: JobId,
    command: CompileCommand,
    outputs: Vec<String>,
}

pub struct Scheduler<S> {
    handler: S,
}

impl<S: SchedulerIncoming + 'static> Scheduler<S> {
    pub fn new(handler: S) -> Self {
        Self { handler }
    }

    pub fn start(self) -> ! {
        let Self { handler } = self;
        let requester = SchedulerRequester { client: reqwest::Client::new() };
        let addr = Cfg::scheduler_listen_addr();

        info!("Scheduler listening for clients on {}", addr);
        let server = rouille::Server::new(addr, move |request| {
            let request_id = request.remote_addr();
            trace!("Req {}: {:?}", request_id, request);
            let response = (|| router!(request,
                (POST) (/api/v1/scheduler/alloc_job) => {
                    let toolchain = try_or_400!(rouille::input::json_input(request));
                    trace!("Req {}: alloc_job: {:?}", request_id, toolchain);

                    let res: AllocJobResult = handler.handle_alloc_job(&requester, toolchain).unwrap();
                    rouille::Response::json(&res)
                },
                (POST) (/api/v1/scheduler/heartbeat_server) => {
                    let heartbeat_server = try_or_400!(rouille::input::json_input(request));
                    trace!("Req {}: alloc_job: {:?}", request_id, heartbeat_server);
                    let HeartbeatServerHttpRequest { num_cpus, port } = heartbeat_server;
                    let server_id = ServerId(SocketAddr::new(request.remote_addr().ip(), port));

                    let HeartbeatServerResult = handler.handle_heartbeat_server(server_id, num_cpus).unwrap();
                    rouille::Response::empty_204()
                },
                (GET) (/api/v1/scheduler/status) => {
                    let res: StatusResult = handler.handle_status().unwrap();
                    rouille::Response::json(&res)
                },
                _ => {
                    warn!("Unknown request {:?}", request);
                    rouille::Response::empty_404()
                },
            )) ();
            trace!("Res {}: {:?}", request_id, response);
            response
        }).unwrap();
        server.run();

        panic!()
    }
}

struct SchedulerRequester {
    client: reqwest::Client,
}

impl SchedulerOutgoing for SchedulerRequester {
    fn do_assign_job(&self, server_id: ServerId, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let url = format!("http://{}/api/v1/distserver/assign_job/{}", server_id.addr(), job_id);
        let mut res = self.client.post(&url)
            .json(&tc)
            .send()
            .unwrap();
        if !res.status().is_success() {
            panic!()
        }
        Ok(res.json().unwrap())
    }
}

pub struct Server<S> {
    scheduler_addr: SocketAddr,
    handler: S,
}

impl<S: ServerIncoming + 'static> Server<S> {
    pub fn new(scheduler_addr: IpAddr, handler: S) -> Self {
        Self {
            scheduler_addr: Cfg::scheduler_connect_addr(scheduler_addr),
            handler,
        }
    }

    pub fn start(self) -> ! {
        let Self { scheduler_addr, handler } = self;
        let requester = ServerRequester { _client: reqwest::Client::new(), _scheduler_addr: scheduler_addr };
        let addr = Cfg::server_listen_addr();

        // TODO: detect if this panics
        thread::spawn(move || {
            let url = format!("http://{}:{}/api/v1/scheduler/heartbeat_server", scheduler_addr.ip(), scheduler_addr.port());
            let req = HeartbeatServerHttpRequest { num_cpus: num_cpus::get(), port: addr.port() };
            let client = reqwest::Client::new();
            loop {
                match client.post(&url).json(&req).send() {
                    Ok(ref res) if res.status().is_success() => (),
                    Ok(res) => error!("Response {} from server when heartbeating {:?}", res.status(), req),
                    Err(e) => error!("Failed to send heartbeat to server: {}", e),
                }
                thread::sleep(Duration::from_secs(30))
            }
        });

        info!("Server listening for clients on {}", addr);
        let server = rouille::Server::new(addr, move |request| {
            let request_id = request.remote_addr();
            trace!("Req {}: {:?}", request_id, request);
            let response = (|| router!(request,
                (POST) (/api/v1/distserver/assign_job/{job_id: JobId}) => {
                    let toolchain = try_or_400!(rouille::input::json_input(request));
                    trace!("Req {}: assign_job: {:?}", request_id, toolchain);

                    let res: AssignJobResult = handler.handle_assign_job(job_id, toolchain).unwrap();
                    rouille::Response::json(&res)
                },
                (POST) (/api/v1/distserver/submit_toolchain/{job_id: JobId}) => {
                    let mut body = request.data().unwrap();
                    let toolchain_rdr = ToolchainReader(Box::new(body));

                    let res: SubmitToolchainResult = handler.handle_submit_toolchain(&requester, job_id, toolchain_rdr).unwrap();
                    rouille::Response::json(&res)
                },
                (POST) (/api/v1/distserver/run_job) => {
                    let mut body = request.data().unwrap();
                    let json_length = body.read_u32::<BigEndian>().unwrap() as u64;

                    let mut json_reader = body.take(json_length);
                    let runjob = serde_json::from_reader(&mut json_reader).unwrap();
                    trace!("Req {}: run_job: {:?}", request_id, runjob);
                    let RunJobHttpRequest { job_id, command, outputs } = runjob;
                    let body = json_reader.into_inner();
                    let inputs_rdr = InputsReader(Box::new(body));
                    let outputs = outputs.into_iter().collect();

                    let res: RunJobResult = handler.handle_run_job(&requester, job_id, command, outputs, inputs_rdr).unwrap();
                    rouille::Response::json(&res)
                },
                _ => {
                    warn!("Unknown request {:?}", request);
                    rouille::Response::empty_404()
                },
            ))();
            trace!("Res {}: {:?}", request_id, response);
            response
        }).unwrap();
        server.run();

        panic!()
    }
}

struct ServerRequester {
    _client: reqwest::Client,
    _scheduler_addr: SocketAddr,
}

impl ServerOutgoing for ServerRequester {
    fn do_update_job_status(&self, _job_id: JobId, _status: JobStatus) -> Result<UpdateJobStatusResult> {
        // TODO
        Ok(UpdateJobStatusResult)
    }
}

pub struct Client {
    scheduler_addr: SocketAddr,
    client: reqwest::unstable::async::Client,
    tc_cache: cache::ClientToolchainCache,
}

impl Client {
    pub fn new(handle: &tokio_core::reactor::Handle, scheduler_addr: IpAddr) -> Self {
        Self {
            scheduler_addr: Cfg::scheduler_connect_addr(scheduler_addr),
            client: reqwest::unstable::async::Client::new(handle),
            tc_cache: cache::ClientToolchainCache::new(),
        }
    }
}

impl super::Client for Client {
    fn do_alloc_job(&self, tc: Toolchain) -> SFuture<AllocJobResult> {
        let url = format!("http://{}/api/v1/scheduler/alloc_job", self.scheduler_addr);
        Box::new(self.client.post(&url).json(&tc).send()
            .and_then(|mut res| {
                if !res.status().is_success() {
                    panic!()
                }
                res.json()
            })
            .map_err(Into::into))
    }
    fn do_submit_toolchain(&self, job_alloc: JobAlloc, tc: Toolchain) -> SFuture<SubmitToolchainResult> {
        let url = format!("http://{}/api/v1/distserver/submit_toolchain/{}", job_alloc.server_id.addr(), job_alloc.job_id);
        if let Some(toolchain_bytes) = self.tc_cache.get_toolchain_cache(&tc.archive_id) {
            Box::new(self.client.post(&url).body(toolchain_bytes).send()
                .and_then(|mut res| {
                    if !res.status().is_success() {
                        panic!()
                    }
                    res.json()
                })
                .map_err(Into::into))
        } else {
            f_err("couldn't find toolchain locally")
        }
    }
    fn do_run_job(&self, job_alloc: JobAlloc, command: CompileCommand, outputs: Vec<PathBuf>, mut write_inputs: Box<FnMut(&mut Write)>) -> SFuture<RunJobResult> {
        let url = format!("http://{}/api/v1/distserver/run_job", job_alloc.server_id.addr());
        let outputs = outputs.into_iter().map(|output| output.into_os_string().into_string().unwrap()).collect();
        let json = serde_json::to_vec(&RunJobHttpRequest { job_id: job_alloc.job_id, command, outputs }).unwrap();
        let json_length = json.len();
        let mut inputs = vec![];
        write_inputs(&mut inputs);

        let mut body = vec![];
        body.write_u32::<BigEndian>(json_length as u32).unwrap();
        body.write(&json).unwrap();
        body.write(&inputs).unwrap();

        Box::new(self.client.post(&url).body(body).send()
            .and_then(|mut res| {
                if !res.status().is_success() {
                    panic!()
                }
                res.json()
            })
            .map_err(Into::into))
    }

    fn put_toolchain_cache(&self, weak_key: &str, create: &mut FnMut(fs::File)) -> Result<String> {
        self.tc_cache.put_toolchain_cache(weak_key, create)
    }
}
