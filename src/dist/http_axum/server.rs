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

//! Dist server implementation with axum
//!
//! HTTPS server that handles:
//! - Job assignment
//! - Toolchain submission
//! - Job execution

use crate::dist::http::common::HeartbeatServerHttpRequest;
use crate::dist::http::server::JWT_KEY_LENGTH;
use crate::dist::http::urls;
use crate::dist::{self, JobId};
use crate::errors::*;
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use rand::RngCore;
use rand::rngs::OsRng;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tower::Service;

use super::auth::{JWTJobAuthorizer, JobAuthorizer, extract_bearer};
use super::extractors::{Bincode, ResponseFormat};
use super::tls;

pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_ERROR_INTERVAL: Duration = Duration::from_secs(10);

pub struct Server<S> {
    bind_address: SocketAddr,
    scheduler_url: reqwest::Url,
    scheduler_auth: String,
    cert_digest: Vec<u8>,
    cert_pem: Vec<u8>,
    privkey_pem: Vec<u8>,
    jwt_key: Vec<u8>,
    server_nonce: dist::ServerNonce,
    handler: S,
}

impl<S: dist::ServerIncoming + Send + Sync + Clone + 'static> Server<S> {
    pub fn new(
        public_addr: SocketAddr,
        bind_address: Option<SocketAddr>,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
        handler: S,
    ) -> Result<Self> {
        let (cert_digest, cert_pem, privkey_pem) = tls::create_https_cert_and_privkey(public_addr)
            .context("failed to create HTTPS certificate for server")?;
        let mut jwt_key = vec![0; JWT_KEY_LENGTH];
        OsRng.fill_bytes(&mut jwt_key);
        let server_nonce = dist::ServerNonce::new();

        Ok(Self {
            bind_address: bind_address.unwrap_or(public_addr),
            scheduler_url,
            scheduler_auth,
            cert_digest,
            cert_pem,
            privkey_pem,
            jwt_key,
            server_nonce,
            handler,
        })
    }

    pub fn start(self) -> Result<Infallible> {
        let Self {
            bind_address,
            scheduler_url,
            scheduler_auth,
            cert_digest,
            cert_pem,
            privkey_pem,
            jwt_key,
            server_nonce,
            handler,
        } = self;

        fn get_num_cpus() -> usize {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        }

        let heartbeat_req = HeartbeatServerHttpRequest {
            num_cpus: get_num_cpus(),
            jwt_key: jwt_key.clone(),
            server_nonce,
            cert_digest,
            cert_pem: cert_pem.clone(),
        };

        let job_authorizer = JWTJobAuthorizer::new(jwt_key);
        let heartbeat_url = urls::scheduler_heartbeat_server(&scheduler_url);
        let requester = Arc::new(ServerRequester {
            client: tokio::sync::Mutex::new(create_http_client()),
            scheduler_url: scheduler_url.clone(),
            scheduler_auth: scheduler_auth.clone(),
        });

        let state = ServerState {
            handler: Arc::new(handler),
            job_authorizer: job_authorizer.clone(),
            requester: requester.clone(),
        };

        let app = Router::new()
            .route("/api/v1/distserver/assign_job/:job_id", post(assign_job))
            .route(
                "/api/v1/distserver/submit_toolchain/:job_id",
                post(submit_toolchain),
            )
            .route("/api/v1/distserver/run_job/:job_id", post(run_job))
            .with_state(state);

        info!("Server listening for clients on {}", bind_address);

        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let https_server = tls::HttpsServer::bind(bind_address, &cert_pem, &privkey_pem)
                .await
                .context("failed to bind HTTPS server")?;

            tokio::spawn(async move {
                loop {
                    trace!(target: "sccache_heartbeat", "Performing heartbeat");
                    let client = create_http_client();
                    match send_heartbeat(&client, &heartbeat_url, &scheduler_auth, &heartbeat_req)
                        .await
                    {
                        Ok(is_new) => {
                            trace!(target: "sccache_heartbeat", "Heartbeat success is_new={}", is_new);
                            if is_new {
                                info!("Server connected to scheduler");
                            }
                            sleep(HEARTBEAT_INTERVAL).await;
                        }
                        Err(e) => {
                            error!(target: "sccache_heartbeat", "Failed to send heartbeat to server: {}", e);
                            sleep(HEARTBEAT_ERROR_INTERVAL).await;
                        }
                    }
                }
            });

            serve_https(https_server, app).await?;

            Ok::<(), anyhow::Error>(())
        })?;

        panic!("Axum server terminated")
    }
}

#[derive(Clone)]
struct ServerState<S> {
    handler: Arc<S>,
    job_authorizer: Arc<dyn JobAuthorizer>,
    requester: Arc<ServerRequester>,
}

struct ServerRequester {
    client: tokio::sync::Mutex<reqwest::Client>,
    scheduler_url: reqwest::Url,
    scheduler_auth: String,
}

struct BodyReader {
    body: axum::body::Body,
    runtime: tokio::runtime::Handle,
}

impl BodyReader {
    fn new(body: axum::body::Body) -> Self {
        Self {
            body,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl std::io::Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.runtime.block_on(async {
            match axum::body::to_bytes(
                std::mem::replace(&mut self.body, axum::body::Body::empty()),
                usize::MAX,
            )
            .await
            {
                Ok(data) => {
                    let len = std::cmp::min(buf.len(), data.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    if data.len() > len {
                        self.body = axum::body::Body::from(data.slice(len..));
                    }
                    Ok(len)
                }
                Err(e) => Err(std::io::Error::other(e)),
            }
        })
    }
}

impl dist::ServerOutgoing for ServerRequester {
    fn do_update_job_state(
        &self,
        job_id: dist::JobId,
        state: dist::JobState,
    ) -> Result<dist::UpdateJobStateResult> {
        tokio::runtime::Handle::current().block_on(async {
            let url = urls::scheduler_job_state(&self.scheduler_url, job_id);
            let bytes =
                bincode::serialize(&state).context("Failed to serialize job state to bincode")?;

            let client = self.client.lock().await;
            let res = client
                .post(url)
                .bearer_auth(self.scheduler_auth.clone())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, bytes.len())
                .body(bytes)
                .send()
                .await
                .context("POST to scheduler job_state failed")?;

            let bytes = res.bytes().await?;
            Ok(bincode::deserialize(&bytes)?)
        })
    }
}

fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .expect("failed to create HTTP client")
}

async fn send_heartbeat(
    client: &reqwest::Client,
    url: &reqwest::Url,
    auth: &str,
    heartbeat: &HeartbeatServerHttpRequest,
) -> Result<bool> {
    let bytes =
        bincode::serialize(heartbeat).context("Failed to serialize heartbeat to bincode")?;

    let res = client
        .post(url.clone())
        .bearer_auth(auth)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(bytes)
        .send()
        .await?;

    let bytes = res.bytes().await?;
    let result: dist::HeartbeatServerResult = bincode::deserialize(&bytes)?;
    Ok(result.is_new)
}

async fn serve_https(https_server: tls::HttpsServer, app: Router) -> Result<()> {
    loop {
        let tls_stream = https_server.accept().await?;
        let tower_service = app.clone();

        tokio::spawn(async move {
            let hyper_service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    let mut svc = tower_service.clone();
                    svc.call(request)
                },
            );

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper_service)
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn assign_job<S>(
    State(state): State<ServerState<S>>,
    Path(job_id): Path<JobId>,
    headers: HeaderMap,
    Bincode(toolchain): Bincode<dist::Toolchain>,
) -> std::result::Result<Response, AppError>
where
    S: dist::ServerIncoming + Send + Sync,
{
    let bearer_token = extract_bearer(&headers).map_err(|_| AppError::Unauthorized)?;

    state
        .job_authorizer
        .verify_token(job_id, bearer_token)
        .map_err(|_| AppError::Unauthorized)?;

    trace!("assign_job({}): {:?}", job_id, toolchain);

    let res = state
        .handler
        .handle_assign_job(job_id, toolchain)
        .map_err(AppError::Internal)?;

    let format =
        ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

async fn submit_toolchain<S>(
    State(state): State<ServerState<S>>,
    Path(job_id): Path<JobId>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> std::result::Result<Response, AppError>
where
    S: dist::ServerIncoming + Send + Sync,
{
    let bearer_token = extract_bearer(&headers).map_err(|_| AppError::Unauthorized)?;

    state
        .job_authorizer
        .verify_token(job_id, bearer_token)
        .map_err(|_| AppError::Unauthorized)?;

    trace!("submit_toolchain({})", job_id);

    let body_reader = BodyReader::new(body);
    let toolchain_rdr = dist::ToolchainReader(Box::new(body_reader));

    let res = state
        .handler
        .handle_submit_toolchain(&*state.requester, job_id, toolchain_rdr)
        .map_err(AppError::Internal)?;

    let format =
        ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

async fn run_job<S>(
    State(state): State<ServerState<S>>,
    Path(job_id): Path<JobId>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> std::result::Result<Response, AppError>
where
    S: dist::ServerIncoming + Send + Sync,
{
    let bearer_token = extract_bearer(&headers).map_err(|_| AppError::Unauthorized)?;

    state
        .job_authorizer
        .verify_token(job_id, bearer_token)
        .map_err(|_| AppError::Unauthorized)?;

    let stream_data = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read body: {}", e)))?;

    let mut cursor = std::io::Cursor::new(stream_data);

    let mut len_bytes = [0u8; 4];
    std::io::Read::read_exact(&mut cursor, &mut len_bytes)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read length prefix: {}", e)))?;

    let bincode_len = u32::from_be_bytes(len_bytes) as usize;

    let mut bincode_buf = vec![0u8; bincode_len];
    std::io::Read::read_exact(&mut cursor, &mut bincode_buf)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read bincode data: {}", e)))?;

    let request: super::streaming::RunJobHttpRequest = bincode::deserialize(&bincode_buf)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to parse bincode: {}", e)))?;

    let mut remaining = Vec::new();
    std::io::Read::read_to_end(&mut cursor, &mut remaining)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read remaining data: {}", e)))?;

    let inputs_reader = dist::InputsReader(Box::new(flate2::read::ZlibDecoder::new(
        std::io::Cursor::new(remaining),
    )));

    trace!("run_job({}): command={:?}", job_id, request.command);

    let outputs = request.outputs.into_iter().collect();

    let res = state
        .handler
        .handle_run_job(
            &*state.requester,
            job_id,
            request.command,
            outputs,
            inputs_reader,
        )
        .map_err(AppError::Internal)?;

    let format =
        ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

#[derive(Debug)]
enum AppError {
    Unauthorized,
    Internal(anyhow::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::Internal(err) => write!(f, "Internal error: {}", err),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Internal(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer error=\"invalid_jwt\"")],
                "Unauthorized",
            )
                .into_response(),
            AppError::Internal(err) => {
                error!("Internal server error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{:#}", err)).into_response()
            }
        }
    }
}
