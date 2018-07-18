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

use bincode;
use boxfnonce::BoxFnOnce;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use futures::{Future, Stream};
use num_cpus;
use reqwest;
use rouille;
use serde;
use std;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
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

// Based on rouille::input::json::json_input
#[derive(Debug)]
pub enum RouilleBincodeError {
    BodyAlreadyExtracted,
    WrongContentType,
    ParseError(bincode::Error),
}
impl From<bincode::Error> for RouilleBincodeError {
    fn from(err: bincode::Error) -> RouilleBincodeError {
        RouilleBincodeError::ParseError(err)
    }
}
impl std::error::Error for RouilleBincodeError {
    fn description(&self) -> &str {
        match *self {
            RouilleBincodeError::BodyAlreadyExtracted => {
                "the body of the request was already extracted"
            },
            RouilleBincodeError::WrongContentType => {
                "the request didn't have a binary content type"
            },
            RouilleBincodeError::ParseError(_) => {
                "error while parsing the bincode body"
            },
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            RouilleBincodeError::ParseError(ref e) => Some(e),
            _ => None
        }
    }
}
impl std::fmt::Display for RouilleBincodeError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "{}", std::error::Error::description(self))
    }
}
fn bincode_input<O>(request: &rouille::Request) -> std::result::Result<O, RouilleBincodeError> where O: serde::de::DeserializeOwned {
    if let Some(header) = request.header("Content-Type") {
        if !header.starts_with("application/octet-stream") {
            return Err(RouilleBincodeError::WrongContentType);
        }
    } else {
        return Err(RouilleBincodeError::WrongContentType);
    }

    if let Some(mut b) = request.data() {
        bincode::deserialize_from::<_, O, _>(&mut b, bincode::Infinite).map_err(From::from)
    } else {
        Err(RouilleBincodeError::BodyAlreadyExtracted)
    }
}

// Based on rouille::Response::json
pub fn bincode_response<T>(content: &T) -> rouille::Response where T: serde::Serialize {
    let data = bincode::serialize(content, bincode::Infinite).unwrap();

    rouille::Response {
        status_code: 200,
        headers: vec![("Content-Type".into(), "application/octet-stream".into())],
        data: rouille::ResponseBody::from_data(data),
        upgrade: None,
    }
}

// Based on try_or_400 in rouille
#[derive(Serialize)]
pub struct ErrJson<'a> {
    description: &'a str,
    cause: Option<Box<ErrJson<'a>>>,
}

impl<'a> ErrJson<'a> {
    pub fn from_err<E: ?Sized + std::error::Error>(err: &'a E) -> ErrJson<'a> {
        let cause = err.cause().map(ErrJson::from_err).map(Box::new);
        ErrJson { description: err.description(), cause }
    }
}
macro_rules! try_or_500 {
    ($result:expr) => (
        match $result {
            Ok(r) => r,
            Err(err) => {
                let json = ErrJson::from_err(&err);
                return rouille::Response::json(&json).with_status_code(500)
            },
        }
    );
}

// Note that content-length is necessary due to https://github.com/tiny-http/tiny-http/issues/147
trait ReqwestRequestBuilderExt {
    fn bincode<T: serde::Serialize + ?Sized>(&mut self, bincode: &T) -> Result<&mut Self>;
    fn bytes(&mut self, bytes: Vec<u8>) -> &mut Self;
}
impl ReqwestRequestBuilderExt for reqwest::RequestBuilder {
    fn bincode<T: serde::Serialize + ?Sized>(&mut self, bincode: &T) -> Result<&mut Self> {
        let bytes = bincode::serialize(bincode, bincode::Infinite)?;
        Ok(self.bytes(bytes))
    }
    fn bytes(&mut self, bytes: Vec<u8>) -> &mut Self {
        self.header(reqwest::header::ContentType::octet_stream())
            .header(reqwest::header::ContentLength(bytes.len() as u64))
            .body(bytes)
    }
}
impl ReqwestRequestBuilderExt for reqwest::unstable::async::RequestBuilder {
    fn bincode<T: serde::Serialize + ?Sized>(&mut self, bincode: &T) -> Result<&mut Self> {
        let bytes = bincode::serialize(bincode, bincode::Infinite)?;
        Ok(self.bytes(bytes))
    }
    fn bytes(&mut self, bytes: Vec<u8>) -> &mut Self {
        self.header(reqwest::header::ContentType::octet_stream())
            .header(reqwest::header::ContentLength(bytes.len() as u64))
            .body(bytes)
    }
}

fn bincode_req<T: serde::de::DeserializeOwned + 'static>(req: &mut reqwest::RequestBuilder) -> Result<T> {
    let mut res = req.send()?;
    let status = res.status();
    let mut body = vec![];
    res.copy_to(&mut body).unwrap();
    if !status.is_success() {
        Err(format!("Error {}: {}", status.as_u16(), String::from_utf8_lossy(&body)).into())
    } else {
        bincode::deserialize(&body).map_err(Into::into)
    }
}

fn bincode_req_fut<T: serde::de::DeserializeOwned + 'static>(req: &mut reqwest::unstable::async::RequestBuilder) -> SFuture<T> {
    Box::new(req.send().map_err(Into::into)
        .and_then(|res| {
            let status = res.status();
            res.into_body().concat2()
                .map(move |b| (status, b)).map_err(Into::into)
        })
        .and_then(|(status, body)| {
            if !status.is_success() {
                return f_err(format!("Error {}: {}", status.as_u16(), String::from_utf8_lossy(&body)))
            }
            match bincode::deserialize(&body) {
                Ok(r) => f_ok(r),
                Err(e) => f_err(e),
            }
        }))
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
                    let toolchain = try_or_400!(bincode_input(request));
                    trace!("Req {}: alloc_job: {:?}", request_id, toolchain);

                    let res: AllocJobResult = try_or_500!(handler.handle_alloc_job(&requester, toolchain));
                    bincode_response(&res)
                },
                (POST) (/api/v1/scheduler/heartbeat_server) => {
                    let heartbeat_server = try_or_400!(bincode_input(request));
                    trace!("Req {}: heartbeat_server: {:?}", request_id, heartbeat_server);
                    let HeartbeatServerHttpRequest { num_cpus, port } = heartbeat_server;
                    let server_id = ServerId(SocketAddr::new(request.remote_addr().ip(), port));

                    let HeartbeatServerResult = handler.handle_heartbeat_server(server_id, num_cpus).unwrap();
                    rouille::Response::empty_204()
                },
                (GET) (/api/v1/scheduler/status) => {
                    let res: StatusResult = handler.handle_status().unwrap();
                    bincode_response(&res)
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

        unreachable!()
    }
}

struct SchedulerRequester {
    client: reqwest::Client,
}

impl SchedulerOutgoing for SchedulerRequester {
    fn do_assign_job(&self, server_id: ServerId, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let url = format!("http://{}/api/v1/distserver/assign_job/{}", server_id.addr(), job_id);
        bincode_req(self.client.post(&url).bincode(&tc)?)
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
                match client.post(&url).bincode(&req).unwrap().send() {
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
                    let toolchain = try_or_400!(bincode_input(request));
                    trace!("Req {}: assign_job: {:?}", request_id, toolchain);

                    let res: AssignJobResult = try_or_500!(handler.handle_assign_job(job_id, toolchain));
                    bincode_response(&res)
                },
                (POST) (/api/v1/distserver/submit_toolchain/{job_id: JobId}) => {
                    let mut body = request.data().unwrap();
                    let toolchain_rdr = ToolchainReader(Box::new(body));

                    let res: SubmitToolchainResult = try_or_500!(handler.handle_submit_toolchain(&requester, job_id, toolchain_rdr));
                    bincode_response(&res)
                },
                (POST) (/api/v1/distserver/run_job) => {
                    let mut body = request.data().unwrap();
                    let bincode_length = body.read_u32::<BigEndian>().unwrap() as u64;

                    let mut bincode_reader = body.take(bincode_length);
                    let runjob = bincode::deserialize_from(&mut bincode_reader, bincode::Infinite).unwrap();
                    trace!("Req {}: run_job: {:?}", request_id, runjob);
                    let RunJobHttpRequest { job_id, command, outputs } = runjob;
                    let body = bincode_reader.into_inner();
                    let inputs_rdr = InputsReader(Box::new(body));
                    let outputs = outputs.into_iter().collect();

                    let res: RunJobResult = try_or_500!(handler.handle_run_job(&requester, job_id, command, outputs, inputs_rdr));
                    bincode_response(&res)
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

        unreachable!()
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
    pub fn new(handle: &tokio_core::reactor::Handle, scheduler_addr: IpAddr, cache_dir: &Path, cache_size: u64) -> Self {
        Self {
            scheduler_addr: Cfg::scheduler_connect_addr(scheduler_addr),
            client: reqwest::unstable::async::Client::new(handle),
            tc_cache: cache::ClientToolchainCache::new(cache_dir, cache_size),
        }
    }
}

impl super::Client for Client {
    fn do_alloc_job(&self, tc: Toolchain) -> SFuture<AllocJobResult> {
        let url = format!("http://{}/api/v1/scheduler/alloc_job", self.scheduler_addr);
        Box::new(f_res(self.client.post(&url).bincode(&tc).map(bincode_req_fut)).and_then(|r| r))
    }
    fn do_submit_toolchain(&self, job_alloc: JobAlloc, tc: Toolchain) -> SFuture<SubmitToolchainResult> {
        let url = format!("http://{}/api/v1/distserver/submit_toolchain/{}", job_alloc.server_id.addr(), job_alloc.job_id);
        if let Some(toolchain_bytes) = self.tc_cache.get_toolchain_cache(&tc.archive_id) {
            bincode_req_fut(self.client.post(&url).bytes(toolchain_bytes))
        } else {
            f_err("couldn't find toolchain locally")
        }
    }
    fn do_run_job(&self, job_alloc: JobAlloc, command: CompileCommand, outputs: Vec<PathBuf>, mut write_inputs: Box<FnMut(&mut Write)>) -> SFuture<RunJobResult> {
        let url = format!("http://{}/api/v1/distserver/run_job", job_alloc.server_id.addr());
        let outputs = outputs.into_iter().map(|output| output.into_os_string().into_string().unwrap()).collect();
        let bincode = bincode::serialize(&RunJobHttpRequest { job_id: job_alloc.job_id, command, outputs }, bincode::Infinite).unwrap();
        let bincode_length = bincode.len();
        let mut inputs = vec![];
        write_inputs(&mut inputs);

        let mut body = vec![];
        body.write_u32::<BigEndian>(bincode_length as u32).unwrap();
        body.write(&bincode).unwrap();
        body.write(&inputs).unwrap();

        bincode_req_fut(self.client.post(&url).bytes(body))
    }

    fn put_toolchain_cache(&self, weak_key: &str, create: BoxFnOnce<(fs::File,), io::Result<()>>) -> Result<String> {
        self.tc_cache.put_toolchain_cache(weak_key, create)
    }
    fn may_dist(&self) -> bool {
        true
    }
}
