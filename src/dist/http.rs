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
#![allow(unused)]

#[cfg(feature = "dist-client")]
pub use self::client::Client;
#[cfg(feature = "dist-server")]
pub use self::server::Scheduler;
#[cfg(feature = "dist-server")]
pub use self::server::Server;

//#[allow(unused)]
mod common {
    use bincode;
    use futures::{Future, Stream};
    use reqwest;
    use serde;
    use std::net::{IpAddr, SocketAddr};
    use dist::{JobId, CompileCommand};

    use errors::*;

    const SCHEDULER_PORT: u16 = 10500;
    const SERVER_PORT: u16 = 10501;

    // TODO: move this into the config module
    pub struct Cfg;

    impl Cfg {
        pub fn scheduler_listen_addr() -> SocketAddr {
            let ip_addr = "0.0.0.0".parse().unwrap();
            SocketAddr::new(ip_addr, SCHEDULER_PORT)
        }
        pub fn scheduler_connect_addr(scheduler_addr: IpAddr) -> SocketAddr {
            SocketAddr::new(scheduler_addr, SCHEDULER_PORT)
        }

        pub fn server_listen_addr() -> SocketAddr {
            let ip_addr = "0.0.0.0".parse().unwrap();
            SocketAddr::new(ip_addr, SERVER_PORT)
        }
    }

    // Note that content-length is necessary due to https://github.com/tiny-http/tiny-http/issues/147
    pub trait ReqwestRequestBuilderExt {
        fn bincode<T: serde::Serialize + ?Sized>(&mut self, bincode: &T) -> Result<&mut Self>;
        fn bytes(&mut self, bytes: Vec<u8>) -> &mut Self;
        fn bearer_auth(&mut self, token: String) -> &mut Self;
    }
    impl ReqwestRequestBuilderExt for reqwest::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(&mut self, bincode: &T) -> Result<&mut Self> {
            let bytes = bincode::serialize(bincode)?;
            Ok(self.bytes(bytes))
        }
        fn bytes(&mut self, bytes: Vec<u8>) -> &mut Self {
            self.header(reqwest::header::ContentType::octet_stream())
                .header(reqwest::header::ContentLength(bytes.len() as u64))
                .body(bytes)
        }
        fn bearer_auth(&mut self, token: String) -> &mut Self {
            self.header(reqwest::header::Authorization(reqwest::header::Bearer { token }))
        }
    }
    impl ReqwestRequestBuilderExt for reqwest::unstable::async::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(&mut self, bincode: &T) -> Result<&mut Self> {
            let bytes = bincode::serialize(bincode)?;
            Ok(self.bytes(bytes))
        }
        fn bytes(&mut self, bytes: Vec<u8>) -> &mut Self {
            self.header(reqwest::header::ContentType::octet_stream())
                .header(reqwest::header::ContentLength(bytes.len() as u64))
                .body(bytes)
        }
        fn bearer_auth(&mut self, token: String) -> &mut Self {
            self.header(reqwest::header::Authorization(reqwest::header::Bearer { token }))
        }
    }

    pub fn bincode_req<T: serde::de::DeserializeOwned + 'static>(req: &mut reqwest::RequestBuilder) -> Result<T> {
        let mut res = req.send()?;
        let status = res.status();
        let mut body = vec![];
        res.copy_to(&mut body).unwrap();
        if !status.is_success() {
            Err(format!("Error {} (Headers={:?}): {}", status.as_u16(), res.headers(), String::from_utf8_lossy(&body)).into())
        } else {
            bincode::deserialize(&body).map_err(Into::into)
        }
    }
    pub fn bincode_req_fut<T: serde::de::DeserializeOwned + 'static>(req: &mut reqwest::unstable::async::RequestBuilder) -> SFuture<T> {
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
    #[derive(Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct JobJwt {
        pub job_id: JobId,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatServerHttpRequest {
        pub jwt_key: Vec<u8>,
        pub num_cpus: usize,
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RunJobHttpRequest {
        pub command: CompileCommand,
        pub outputs: Vec<String>,
    }
}

#[cfg(feature = "dist-server")]
mod server {
    use bincode;
    use byteorder::{BigEndian, ReadBytesExt};
    use flate2::read::ZlibDecoder as ZlibReadDecoder;
    use jwt;
    use num_cpus;
    use rand::{self, RngCore};
    use reqwest;
    use rouille;
    use serde;
    use serde_json;
    use std;
    use std::io::Read;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic;
    use std::thread;
    use std::time::Duration;

    use dist::{
        self,

        ServerId, JobId, Toolchain,
        ToolchainReader, InputsReader,

        AllocJobResult,
        AssignJobResult,
        HeartbeatServerResult,
        RunJobResult,
        StatusResult,
        SubmitToolchainResult,
        UpdateJobStateResult, JobState,
    };
    use super::common::{
        Cfg,
        ReqwestRequestBuilderExt,
        bincode_req,

        JobJwt,
        HeartbeatServerHttpRequest,
        RunJobHttpRequest,
    };
    use errors::*;

    const JWT_KEY_LENGTH: usize = 256 / 8;
    lazy_static!{
        static ref JWT_HEADER: jwt::Header = jwt::Header::new(jwt::Algorithm::HS256);
        static ref JWT_VALIDATION: jwt::Validation = jwt::Validation {
            leeway: 0,
            validate_exp: false,
            validate_iat: false,
            validate_nbf: false,
            aud: None,
            iss: None,
            sub: None,
            algorithms: vec![jwt::Algorithm::HS256],
        };
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
            bincode::deserialize_from::<_, O>(&mut b).map_err(From::from)
        } else {
            Err(RouilleBincodeError::BodyAlreadyExtracted)
        }
    }

    // Based on rouille::Response::json
    pub fn bincode_response<T>(content: &T) -> rouille::Response where T: serde::Serialize {
        let data = bincode::serialize(content).unwrap();

        rouille::Response {
            status_code: 200,
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            data: rouille::ResponseBody::from_data(data),
            upgrade: None,
        }
    }

    // Based on try_or_400 in rouille, but with logging
    #[derive(Serialize)]
    pub struct ErrJson<'a> {
        description: &'a str,
        cause: Option<Box<ErrJson<'a>>>,
    }

    impl<'a> ErrJson<'a> {
        fn from_err<E: ?Sized + std::error::Error>(err: &'a E) -> ErrJson<'a> {
            let cause = err.cause().map(ErrJson::from_err).map(Box::new);
            ErrJson { description: err.description(), cause }
        }
        fn into_data(self) -> String {
            serde_json::to_string(&self).unwrap()
        }
    }
    macro_rules! try_or_err_and_log {
        ($reqid:expr, $code:expr, $result:expr) => {
            match $result {
                Ok(r) => r,
                Err(err) => {
                    // TODO: would ideally just use error_chain
                    use std::error::Error;
                    let mut err_msg = err.to_string();
                    let mut maybe_cause = err.cause();
                    while let Some(cause) = maybe_cause {
                        err_msg.push_str(", caused by: ");
                        err_msg.push_str(cause.description());
                        maybe_cause = cause.cause()
                    };

                    warn!("Res {} error: {}", $reqid, err_msg);
                    let json = ErrJson::from_err(&err);
                    return rouille::Response::json(&json).with_status_code($code)
                },
            }
        };
    }
    macro_rules! try_or_400_log {
        ($reqid:expr, $result:expr) => { try_or_err_and_log!($reqid, 400, $result) };
    }
    macro_rules! try_or_500_log {
        ($reqid:expr, $result:expr) => { try_or_err_and_log!($reqid, 500, $result) };
    }
    fn make_401(short_err: &str) -> rouille::Response {
        rouille::Response {
            status_code: 401,
            headers: vec![("WWW-Authenticate".into(), format!("Bearer error=\"{}\"", short_err).into())],
            data: rouille::ResponseBody::empty(),
            upgrade: None,
        }
    }
    fn bearer_http_auth(request: &rouille::Request) -> Option<&str> {
        let header = request.header("Authorization")?;

        let mut split = header.splitn(2, |c| c == ' ');

        let authtype = split.next()?;
        if authtype != "Bearer" {
            return None
        }

        split.next()
    }
    macro_rules! try_jwt_or_401 {
        ($request:ident, $key:expr, $valid_claims:expr) => {{
            let claims: Result<_> = match bearer_http_auth($request) {
                Some(token) => {
                    jwt::decode(&token, $key, &JWT_VALIDATION)
                        .map_err(Into::into)
                        .and_then(|res| {
                            fn identical_t<T>(_: &T, _: &T) {}
                            let valid_claims = $valid_claims;
                            identical_t(&res.claims, &valid_claims);
                            if res.claims == valid_claims { Ok(()) } else { Err("invalid claims".into()) }
                        })
                },
                None => Err("no Authorization header".into()),
            };
            match claims {
                Ok(()) => (),
                Err(err) => {
                    let json = ErrJson::from_err(&err);
                    let mut res = make_401("invalid_jwt");
                    res.data = rouille::ResponseBody::from_data(json.into_data());
                    return res
                },
            }
        }};
    }

    pub struct Scheduler<S> {
        handler: S,
        // Is this client permitted to use the scheduler?
        check_client_auth: Box<Fn(&str) -> bool + Send + Sync>,
        // Do we believe the server is who they appear to be?
        check_server_auth: Box<Fn(&str) -> Option<ServerId> + Send + Sync>,
    }

    impl<S: dist::SchedulerIncoming + 'static> Scheduler<S> {
        pub fn new(handler: S, check_client_auth: Box<Fn(&str) -> bool + Send + Sync>, check_server_auth: Box<Fn(&str) -> Option<ServerId> + Send + Sync>) -> Self {
            Self { handler, check_client_auth, check_server_auth }
        }

        pub fn start(self) -> ! {
            let Self { handler, check_client_auth, check_server_auth } = self;
            let requester = SchedulerRequester { client: reqwest::Client::new() };
            let addr = Cfg::scheduler_listen_addr();

            macro_rules! check_server_auth_or_401 {
                ($request:ident) => {{
                    match bearer_http_auth($request).and_then(&*check_server_auth) {
                        Some(server_id) if server_id.addr().ip() == $request.remote_addr().ip() => server_id,
                        Some(_) => return make_401("invalid_bearer_token_mismatched_address"),
                        None => return make_401("invalid_bearer_token"),
                    }}
                };
            }

            info!("Scheduler listening for clients on {}", addr);
            let request_count = atomic::AtomicUsize::new(0);
            let server = rouille::Server::new(addr, move |request| {
                let req_id = request_count.fetch_add(1, atomic::Ordering::SeqCst);
                trace!("Req {} ({}): {:?}", req_id, request.remote_addr(), request);
                let response = (|| router!(request,
                    (POST) (/api/v1/scheduler/alloc_job) => {
                        if !bearer_http_auth(request).map_or(false, &*check_client_auth) {
                            return make_401("invalid_bearer_token")
                        }
                        let toolchain = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: alloc_job: {:?}", req_id, toolchain);

                        let res: AllocJobResult = try_or_500_log!(req_id, handler.handle_alloc_job(&requester, toolchain));
                        bincode_response(&res)
                    },
                    (POST) (/api/v1/scheduler/heartbeat_server) => {
                        let server_id = check_server_auth_or_401!(request);
                        let heartbeat_server = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: heartbeat_server: {:?}", req_id, heartbeat_server);

                        let HeartbeatServerHttpRequest { num_cpus, jwt_key } = heartbeat_server;
                        let generate_job_auth = Box::new(move |job_id| {
                            let claims = JobJwt { job_id };
                            jwt::encode(&JWT_HEADER, &claims, &jwt_key).unwrap()
                        });
                        let res: HeartbeatServerResult = handler.handle_heartbeat_server(server_id, num_cpus, generate_job_auth).unwrap();
                        bincode_response(&res)
                    },
                    (POST) (/api/v1/scheduler/job_state/{job_id: JobId}) => {
                        let server_id = check_server_auth_or_401!(request);
                        let job_state = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: job state: {:?}", req_id, job_state);

                        let res: UpdateJobStateResult = handler.handle_update_job_state(job_id, server_id, job_state).unwrap();
                        bincode_response(&res)
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
                trace!("Res {}: {:?}", req_id, response);
                response
            }).unwrap();
            server.run();

            unreachable!()
        }
    }

    struct SchedulerRequester {
        client: reqwest::Client,
    }

    impl dist::SchedulerOutgoing for SchedulerRequester {
        fn do_assign_job(&self, server_id: ServerId, job_id: JobId, tc: Toolchain, auth: String) -> Result<AssignJobResult> {
            let url = format!("http://{}/api/v1/distserver/assign_job/{}", server_id.addr(), job_id);
            bincode_req(self.client.post(&url).bearer_auth(auth).bincode(&tc)?)
        }
    }

    pub struct Server<S> {
        scheduler_addr: SocketAddr,
        scheduler_auth: String,
        handler: S,
        jwt_key: Vec<u8>,
    }

    impl<S: dist::ServerIncoming + 'static> Server<S> {
        pub fn new(scheduler_addr: IpAddr, scheduler_auth: String, handler: S) -> Self {
            let mut jwt_key = vec![0; JWT_KEY_LENGTH];
            let mut rng = rand::OsRng::new().unwrap();
            rng.fill_bytes(&mut jwt_key);
            Self {
                scheduler_addr: Cfg::scheduler_connect_addr(scheduler_addr),
                scheduler_auth,
                jwt_key,
                handler,
            }
        }

        pub fn start(self) -> ! {
            let Self { scheduler_addr, scheduler_auth, jwt_key, handler } = self;
            let requester = ServerRequester { client: reqwest::Client::new(), scheduler_addr, scheduler_auth: scheduler_auth.clone() };
            let addr = Cfg::server_listen_addr();

            // TODO: detect if this panics
            let heartbeat_req = HeartbeatServerHttpRequest { num_cpus: num_cpus::get(), jwt_key: jwt_key.clone() };
            thread::spawn(move || {
                let url = format!("http://{}:{}/api/v1/scheduler/heartbeat_server", scheduler_addr.ip(), scheduler_addr.port());
                let client = reqwest::Client::new();
                loop {
                    trace!("Performing heartbeat");
                    match bincode_req(client.post(&url).bearer_auth(scheduler_auth.clone()).bincode(&heartbeat_req).unwrap()) {
                        Ok(HeartbeatServerResult { is_new }) => {
                            trace!("Heartbeat success is_new={}", is_new);
                            // TODO: if is_new, terminate all running jobs
                            thread::sleep(Duration::from_secs(30))
                        },
                        Err(e) => {
                            error!("Failed to send heartbeat to server: {}", e);
                            thread::sleep(Duration::from_secs(10))
                        },
                    }
                }
            });

            info!("Server listening for clients on {}", addr);
            let request_count = atomic::AtomicUsize::new(0);
            let server = rouille::Server::new(addr, move |request| {
                let req_id = request_count.fetch_add(1, atomic::Ordering::SeqCst);
                trace!("Req {} ({}): {:?}", req_id, request.remote_addr(), request);
                let response = (|| router!(request,
                    (POST) (/api/v1/distserver/assign_job/{job_id: JobId}) => {
                        try_jwt_or_401!(request, &jwt_key, JobJwt { job_id });
                        let toolchain = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: assign_job({}): {:?}", req_id, job_id, toolchain);

                        let res: AssignJobResult = try_or_500_log!(req_id, handler.handle_assign_job(job_id, toolchain));
                        bincode_response(&res)
                    },
                    (POST) (/api/v1/distserver/submit_toolchain/{job_id: JobId}) => {
                        try_jwt_or_401!(request, &jwt_key, JobJwt { job_id });
                        trace!("Req {}: submit_toolchain({})", req_id, job_id);

                        let mut body = request.data().unwrap();
                        let toolchain_rdr = ToolchainReader(Box::new(body));
                        let res: SubmitToolchainResult = try_or_500_log!(req_id, handler.handle_submit_toolchain(&requester, job_id, toolchain_rdr));
                        bincode_response(&res)
                    },
                    (POST) (/api/v1/distserver/run_job/{job_id: JobId}) => {
                        try_jwt_or_401!(request, &jwt_key, JobJwt { job_id });

                        let mut body = request.data().unwrap();
                        let bincode_length = body.read_u32::<BigEndian>().unwrap() as u64;

                        let mut bincode_reader = body.take(bincode_length);
                        let runjob = bincode::deserialize_from(&mut bincode_reader).unwrap();
                        trace!("Req {}: run_job({}): {:?}", req_id, job_id, runjob);
                        let RunJobHttpRequest { command, outputs } = runjob;
                        let body = bincode_reader.into_inner();
                        let inputs_rdr = InputsReader(Box::new(ZlibReadDecoder::new(body)));
                        let outputs = outputs.into_iter().collect();

                        let res: RunJobResult = try_or_500_log!(req_id, handler.handle_run_job(&requester, job_id, command, outputs, inputs_rdr));
                        bincode_response(&res)
                    },
                    _ => {
                        warn!("Unknown request {:?}", request);
                        rouille::Response::empty_404()
                    },
                ))();
                trace!("Res {}: {:?}", req_id, response);
                response
            }).unwrap();
            server.run();

            unreachable!()
        }
    }

    struct ServerRequester {
        client: reqwest::Client,
        scheduler_addr: SocketAddr,
        scheduler_auth: String,
    }

    impl dist::ServerOutgoing for ServerRequester {
        fn do_update_job_state(&self, job_id: JobId, state: JobState) -> Result<UpdateJobStateResult> {
            let url = format!("http://{}/api/v1/scheduler/job_state/{}", self.scheduler_addr, job_id);
            bincode_req(self.client.post(&url).bearer_auth(self.scheduler_auth.clone()).bincode(&state)?)
        }
    }
}

#[cfg(feature = "dist-client")]
mod client {
    use bincode;
    use byteorder::{BigEndian, WriteBytesExt};
    use config;
    use dist::pkg::{InputsPackager, ToolchainPackager};
    use flate2::Compression;
    use flate2::write::ZlibEncoder as ZlibWriteEncoder;
    use futures::{Future, Stream};
    use futures_cpupool::CpuPool;
    use reqwest;
    use std::fs;
    use std::io::Write;
    use std::net::{IpAddr, SocketAddr};
    use std::path::Path;
    use std::time::Duration;
    use super::super::cache;
    use tokio_core;

    use dist::{
        self,
        Toolchain, CompileCommand,
        AllocJobResult, JobAlloc, RunJobResult, SubmitToolchainResult,
    };
    use super::common::{
        Cfg,
        ReqwestRequestBuilderExt,
        bincode_req,
        bincode_req_fut,

        RunJobHttpRequest,
    };
    use errors::*;

    const REQUEST_TIMEOUT_SECS: u64 = 600;

    pub struct Client {
        auth: &'static config::DistAuth,
        scheduler_addr: SocketAddr,
        // TODO: this should really only use the async client, but reqwest async bodies are extremely limited
        // and only support owned bytes, which means the whole toolchain would end up in memory
        client: reqwest::Client,
        client_async: reqwest::unstable::async::Client,
        pool: CpuPool,
        tc_cache: cache::ClientToolchains,
    }

    impl Client {
        pub fn new(handle: &tokio_core::reactor::Handle, pool: &CpuPool, scheduler_addr: IpAddr, cache_dir: &Path, cache_size: u64, custom_toolchains: &[config::DistCustomToolchain], auth: &'static config::DistAuth) -> Self {
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let client = reqwest::ClientBuilder::new().timeout(timeout).build().unwrap();
            let client_async = reqwest::unstable::async::ClientBuilder::new().timeout(timeout).build(handle).unwrap();
            Self {
                auth,
                scheduler_addr: Cfg::scheduler_connect_addr(scheduler_addr),
                client,
                client_async,
                pool: pool.clone(),
                tc_cache: cache::ClientToolchains::new(cache_dir, cache_size, custom_toolchains),
            }
        }
    }

    impl dist::Client for Client {
        fn do_alloc_job(&self, tc: Toolchain) -> SFuture<AllocJobResult> {
            let token = match self.auth {
                config::DistAuth::Token { token } => token,
            };
            let url = format!("http://{}/api/v1/scheduler/alloc_job", self.scheduler_addr);
            Box::new(f_res(self.client_async.post(&url).bearer_auth(token.to_owned()).bincode(&tc).map(bincode_req_fut)).and_then(|r| r))
        }
        fn do_submit_toolchain(&self, job_alloc: JobAlloc, tc: Toolchain) -> SFuture<SubmitToolchainResult> {
            if let Some(toolchain_file) = self.tc_cache.get_toolchain(&tc) {
                let url = format!("http://{}/api/v1/distserver/submit_toolchain/{}", job_alloc.server_id.addr(), job_alloc.job_id);
                let mut req = self.client.post(&url);

                Box::new(self.pool.spawn_fn(move || {
                    req.bearer_auth(job_alloc.auth.clone()).body(toolchain_file);
                    bincode_req(&mut req)
                }))
            } else {
                f_err("couldn't find toolchain locally")
            }
        }
        fn do_run_job(&self, job_alloc: JobAlloc, command: CompileCommand, outputs: Vec<String>, inputs_packager: Box<InputsPackager>) -> SFuture<RunJobResult> {
            let url = format!("http://{}/api/v1/distserver/run_job/{}", job_alloc.server_id.addr(), job_alloc.job_id);
            let mut req = self.client.post(&url);

            Box::new(self.pool.spawn_fn(move || {
                let bincode = bincode::serialize(&RunJobHttpRequest { command, outputs }).unwrap();
                let bincode_length = bincode.len();

                let mut body = vec![];
                body.write_u32::<BigEndian>(bincode_length as u32).unwrap();
                body.write(&bincode).unwrap();
                {
                    let mut compressor = ZlibWriteEncoder::new(&mut body, Compression::fast());
                    inputs_packager.write_inputs(&mut compressor).chain_err(|| "Could not write inputs for compilation")?;
                    compressor.flush().unwrap();
                    trace!("Compressed inputs from {} -> {}", compressor.total_in(), compressor.total_out());
                    compressor.finish().unwrap();
                }

                req.bearer_auth(job_alloc.auth.clone()).bytes(body);
                bincode_req(&mut req)
            }))
        }

        fn put_toolchain(&self, compiler_path: &Path, weak_key: &str, toolchain_packager: Box<ToolchainPackager>) -> Result<(Toolchain, Option<String>)> {
            self.tc_cache.put_toolchain(compiler_path, weak_key, toolchain_packager)
        }
        fn may_dist(&self) -> bool {
            true
        }
    }
}
