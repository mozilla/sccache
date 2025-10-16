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

//! Scheduler HTTP server implementation with axum
//!
//! Handles:
//! - Job allocation
//! - Server heartbeats and certificate distribution
//! - Job state updates

use crate::dist::{self, ServerId};
use crate::errors::*;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::auth::extract_bearer;
use super::extractors::{Bincode, ResponseFormat};
use super::{ClientAuthCheck, ClientVisibleMsg, ServerAuthCheck};
use crate::dist::http::common::{
    AllocJobHttpResponse, HashMap, HeartbeatServerHttpRequest, JobJwt,
    ServerCertificateHttpResponse,
};

/// Scheduler state shared across all handlers
#[derive(Clone)]
pub struct SchedulerState<S> 
where
    S: Clone,
{
    handler: Arc<S>,
    check_client_auth: Arc<Box<dyn ClientAuthCheck>>,
    check_server_auth: Arc<ServerAuthCheck>,
    requester: Arc<SchedulerRequester>,
    /// Server certificates: server_id -> (cert_digest, cert_pem)
    server_certificates: Arc<RwLock<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
}

/// HTTP client for making requests to servers
pub struct SchedulerRequester {
    client: tokio::sync::Mutex<reqwest::Client>,
}

impl SchedulerRequester {
    fn new() -> Self {
        Self {
            client: tokio::sync::Mutex::new(create_http_client(&HashMap::new())),
        }
    }

    /// Update client with new certificates
    async fn update_certs(&self, certs: &HashMap<ServerId, (Vec<u8>, Vec<u8>)>) -> Result<()> {
        let new_client = create_http_client(certs);
        *self.client.lock().await = new_client;
        Ok(())
    }
}

impl dist::SchedulerOutgoing for SchedulerRequester {
    fn do_assign_job(
        &self,
        server_id: ServerId,
        job_id: dist::JobId,
        tc: dist::Toolchain,
        auth: String,
    ) -> Result<dist::AssignJobResult> {
        // Bridge async to sync for trait compatibility
        tokio::runtime::Handle::current().block_on(async {
            let url = crate::dist::http::urls::server_assign_job(server_id, job_id);
            let bytes = bincode::serialize(&tc)?;

            let client = self.client.lock().await;
            let res = client
                .post(url)
                .bearer_auth(auth)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes)
                .send()
                .await?;

            let bytes = res.bytes().await?;
            Ok(bincode::deserialize(&bytes)?)
        })
    }
}

/// Create HTTP client with certificates
fn create_http_client(certs: &HashMap<ServerId, (Vec<u8>, Vec<u8>)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(0); // Disable connection pool

    for (_, cert_pem) in certs.values() {
        if let Ok(cert) = reqwest::Certificate::from_pem(cert_pem) {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder.build().expect("failed to create HTTP client")
}

pub struct Scheduler<S> {
    pub_addr: SocketAddr,
    handler: S,
    check_client_auth: Box<dyn ClientAuthCheck>,
    check_server_auth: ServerAuthCheck,
}

impl<S: dist::SchedulerIncoming + Send + Sync + Clone + 'static> Scheduler<S> {
    pub fn new(
        public_addr: SocketAddr,
        handler: S,
        check_client_auth: Box<dyn ClientAuthCheck>,
        check_server_auth: ServerAuthCheck,
    ) -> Self {
        Self {
            pub_addr: public_addr,
            handler,
            check_client_auth,
            check_server_auth,
        }
    }

    pub fn start(self) -> Result<Infallible> {
        let Self {
            pub_addr,
            handler,
            check_client_auth,
            check_server_auth,
        } = self;

        let state = SchedulerState {
            handler: Arc::new(handler),
            check_client_auth: Arc::new(check_client_auth),
            check_server_auth: Arc::new(check_server_auth),
            requester: Arc::new(SchedulerRequester::new()),
            server_certificates: Arc::new(RwLock::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/api/v1/scheduler/alloc_job", post(alloc_job))
            .route(
                "/api/v1/scheduler/server_certificate/:server_id",
                get(server_certificate),
            )
            .route(
                "/api/v1/scheduler/heartbeat_server",
                post(heartbeat_server),
            )
            .route(
                "/api/v1/scheduler/job_state/:job_id",
                post(job_state),
            )
            .route("/api/v1/scheduler/status", get(status))
            .with_state(state);

        info!("Scheduler listening for clients on {}", pub_addr);

        // Create tokio runtime
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind(pub_addr)
                .await
                .context("failed to bind TCP listener")?;

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .context("server error")?;

            Ok::<(), anyhow::Error>(())
        })?;

        panic!("Axum server terminated")
    }
}

// Handler implementations

async fn alloc_job<S>(
    State(state): State<SchedulerState<S>>,
    headers: HeaderMap,
    Bincode(toolchain): Bincode<dist::Toolchain>,
) -> std::result::Result<Response, AppError>
where
    S: dist::SchedulerIncoming + Clone,
{
    // Check client authentication
    let bearer_token = extract_bearer(&headers).map_err(|_| AppError::Unauthorized)?;

    state
        .check_client_auth
        .check(bearer_token)
        .map_err(AppError::ClientAuthFailed)?;

    trace!("alloc_job: {:?}", toolchain);

    // Call handler
    let alloc_job_res = state
        .handler
        .handle_alloc_job(&*state.requester, toolchain)
        .map_err(AppError::Internal)?;

    // Get certificates for response
    let certs = state.server_certificates.read().await;
    let res = AllocJobHttpResponse::from_alloc_job_result(alloc_job_res, &certs);

    // Format response
    let format = ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

async fn server_certificate<S>(
    State(state): State<SchedulerState<S>>,
    Path(server_id): Path<ServerId>,
    headers: HeaderMap,
) -> std::result::Result<Response, AppError>
where
    S: dist::SchedulerIncoming + Clone,
{
    let certs = state.server_certificates.read().await;
    let (cert_digest, cert_pem) = certs
        .get(&server_id)
        .ok_or_else(|| AppError::NotFound("server cert not available".to_string()))?
        .clone();

    let res = ServerCertificateHttpResponse {
        cert_digest,
        cert_pem,
    };

    let format = ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

async fn heartbeat_server<S>(
    State(state): State<SchedulerState<S>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Bincode(heartbeat): Bincode<HeartbeatServerHttpRequest>,
) -> std::result::Result<Response, AppError>
where
    S: dist::SchedulerIncoming + Clone,
{
    // Check server authentication
    let bearer_token = extract_bearer(&headers).map_err(|_| AppError::Unauthorized)?;

    let server_id = (state.check_server_auth)(bearer_token)
        .ok_or(AppError::Unauthorized)?;

    // Check IP matches (support X-Real-IP for proxies)
    let origin_ip = if let Some(real_ip) = headers.get("X-Real-IP") {
        real_ip
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AppError::BadRequest("Invalid X-Real-IP header".to_string()))?
    } else {
        addr.ip()
    };

    if server_id.addr().ip() != origin_ip {
        warn!(
            "IP mismatch: server_id={:?}, origin={:?}",
            server_id.addr().ip(),
            origin_ip
        );
        return Err(AppError::IpMismatch);
    }

    trace!(target: "sccache_heartbeat", "heartbeat_server: {:?}", heartbeat);

    let HeartbeatServerHttpRequest {
        num_cpus,
        jwt_key,
        server_nonce,
        cert_digest,
        cert_pem,
    } = heartbeat;

    // Update certificates
    {
        let mut certs = state.server_certificates.write().await;
        if let Some((saved_digest, _)) = certs.get(&server_id) {
            if saved_digest != &cert_digest {
                info!(
                    "Updating certificate for {} in scheduler",
                    server_id.addr()
                );
                certs.insert(server_id, (cert_digest, cert_pem.clone()));
                state.requester.update_certs(&certs).await.map_err(AppError::Internal)?;
            }
        } else {
            info!("Adding new certificate for {} to scheduler", server_id.addr());
            certs.insert(server_id, (cert_digest, cert_pem.clone()));
            state.requester.update_certs(&certs).await.map_err(AppError::Internal)?;
        }
    }

    // Create job authorizer
    let job_authorizer = JWTJobAuthorizer::new(jwt_key);

    // Call handler
    let res = state
        .handler
        .handle_heartbeat_server(server_id, server_nonce, num_cpus, job_authorizer)
        .map_err(AppError::Internal)?;

    let format = ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

async fn job_state<S>(
    State(state): State<SchedulerState<S>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(job_id): Path<dist::JobId>,
    Bincode(job_state): Bincode<dist::JobState>,
) -> std::result::Result<Response, AppError>
where
    S: dist::SchedulerIncoming + Clone,
{
    // Check server authentication
    let bearer_token = extract_bearer(&headers).map_err(|_| AppError::Unauthorized)?;

    let server_id = (state.check_server_auth)(bearer_token)
        .ok_or(AppError::Unauthorized)?;

    // Check IP matches
    let origin_ip = if let Some(real_ip) = headers.get("X-Real-IP") {
        real_ip
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AppError::BadRequest("Invalid X-Real-IP header".to_string()))?
    } else {
        addr.ip()
    };

    if server_id.addr().ip() != origin_ip {
        return Err(AppError::IpMismatch);
    }

    trace!("job_state: {:?}", job_state);

    // Call handler
    let res = state
        .handler
        .handle_update_job_state(job_id, server_id, job_state)
        .map_err(AppError::Internal)?;

    let format = ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

async fn status<S>(
    State(state): State<SchedulerState<S>>,
    headers: HeaderMap,
) -> std::result::Result<Response, AppError>
where
    S: dist::SchedulerIncoming + Clone,
{
    let res = state.handler.handle_status().map_err(AppError::Internal)?;

    let format = ResponseFormat::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));
    Ok(format
        .into_response(&res)
        .map_err(|e| AppError::Internal(e.into()))?
        .into_response())
}

// JWT Job Authorizer implementation
#[cfg(feature = "jwt")]
struct JWTJobAuthorizer {
    server_key: Vec<u8>,
}

#[cfg(feature = "jwt")]
impl JWTJobAuthorizer {
    fn new(server_key: Vec<u8>) -> Box<Self> {
        Box::new(Self { server_key })
    }
}

#[cfg(feature = "jwt")]
impl dist::JobAuthorizer for JWTJobAuthorizer {
    fn generate_token(&self, job_id: dist::JobId) -> Result<String> {
        let claims = JobJwt { exp: 0, job_id };
        let key = jwt::EncodingKey::from_secret(&self.server_key);
        let header = jwt::Header::new(jwt::Algorithm::HS256);
        jwt::encode(&header, &claims, &key)
            .map_err(|e| anyhow::anyhow!("Failed to create JWT for job: {}", e))
    }

    fn verify_token(&self, job_id: dist::JobId, token: &str) -> Result<()> {
        let valid_claims = JobJwt { exp: 0, job_id };
        let key = jwt::DecodingKey::from_secret(&self.server_key);
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;
        validation.validate_exp = false;
        validation.validate_nbf = false;

        let token_data = jwt::decode::<JobJwt>(token, &key, &validation)
            .map_err(|e| anyhow::anyhow!("JWT decode failed: {}", e))?;

        if token_data.claims == valid_claims {
            Ok(())
        } else {
            Err(anyhow::anyhow!("mismatched claims"))
        }
    }
}

// Error handling

#[derive(Debug)]
enum AppError {
    Unauthorized,
    ClientAuthFailed(ClientVisibleMsg),
    IpMismatch,
    NotFound(String),
    BadRequest(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::ClientAuthFailed(msg) => write!(f, "Client auth failed: {}", msg.0),
            AppError::IpMismatch => write!(f, "IP address mismatch"),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
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
                [("WWW-Authenticate", "Bearer error=\"invalid_bearer_token\"")],
                "Unauthorized",
            )
                .into_response(),
            AppError::ClientAuthFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer error=\"bearer_auth_failed\"")],
                msg.0,
            )
                .into_response(),
            AppError::IpMismatch => (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer error=\"invalid_bearer_token_mismatched_address\"")],
                "IP address mismatch",
            )
                .into_response(),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            AppError::Internal(err) => {
                error!("Internal server error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{:#}", err)).into_response()
            }
        }
    }
}
