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

//! Authentication middleware and extractors
//!
//! This module implements three types of authentication:
//! 1. Client Bearer token authentication (ClientAuthCheck)
//! 2. Server Bearer token + IP address verification (ServerAuthCheck)
//! 3. JWT-based job authorization (HS256)

use crate::dist::{JobId, ServerId};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use super::ClientVisibleMsg;

/// Extract and validate Bearer token from Authorization header
pub fn extract_bearer(headers: &HeaderMap) -> Result<&str, AuthError> {
    let header = headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingAuthHeader)?
        .to_str()
        .map_err(|_| AuthError::InvalidAuthHeader)?;

    let mut split = header.splitn(2, ' ');
    let auth_type = split.next().ok_or(AuthError::InvalidAuthHeader)?;

    if auth_type != "Bearer" {
        return Err(AuthError::InvalidAuthType);
    }

    split.next().ok_or(AuthError::MissingToken)
}

/// Client authentication extractor
///
/// This validates that the client has a valid bearer token.
/// Used for: POST /api/v1/scheduler/alloc_job
pub struct ClientAuth;

#[async_trait]
impl<S> FromRequestParts<S> for ClientAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // This is a marker type - actual validation is done in the handler
        // because we need access to the ClientAuthCheck from state
        Ok(ClientAuth)
    }
}

/// Server authentication extractor with IP verification
///
/// This validates:
/// 1. Bearer token maps to a valid ServerId
/// 2. Request origin IP matches the server's declared IP (or X-Real-IP if behind proxy)
///
/// Used for: POST /api/v1/scheduler/heartbeat_server, POST /api/v1/scheduler/job_state/:id
pub struct ServerAuth(pub ServerId);

#[async_trait]
impl<S> FromRequestParts<S> for ServerAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Actual validation happens in middleware with state
        // This is just a placeholder
        Err(AuthError::InternalError(
            "ServerAuth must be validated in middleware".to_string(),
        ))
    }
}

/// JWT-based job authorization extractor
///
/// This validates that the request has a valid JWT for the specific job.
/// The JWT is signed with HS256 using a symmetric key provided by the server.
///
/// Used for all job-related endpoints on the dist server.
pub struct JwtAuth {
    pub job_id: JobId,
}

/// Authentication errors
#[derive(Debug)]
pub enum AuthError {
    MissingAuthHeader,
    InvalidAuthHeader,
    InvalidAuthType,
    MissingToken,
    InvalidToken(String),
    IpMismatch {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    ClientAuthFailed(ClientVisibleMsg),
    InternalError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, body) = match self {
            AuthError::MissingAuthHeader => {
                (StatusCode::UNAUTHORIZED, "no_bearer_auth", String::new())
            }
            AuthError::InvalidAuthHeader | AuthError::InvalidAuthType => (
                StatusCode::UNAUTHORIZED,
                "invalid_bearer_token",
                String::new(),
            ),
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "missing_token", String::new()),
            AuthError::InvalidToken(msg) => (StatusCode::UNAUTHORIZED, "invalid_jwt", msg),
            AuthError::IpMismatch { expected, actual } => (
                StatusCode::UNAUTHORIZED,
                "invalid_bearer_token_mismatched_address",
                format!(
                    "Server IP mismatch: expected {}, got {}",
                    expected.ip(),
                    actual.ip()
                ),
            ),
            AuthError::ClientAuthFailed(msg) => {
                (StatusCode::UNAUTHORIZED, "bearer_auth_failed", msg.0)
            }
            AuthError::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg)
            }
        };

        // Format WWW-Authenticate header as per RFC 6750
        let www_authenticate = format!("Bearer error=\"{}\"", error_code);

        (
            status,
            [("WWW-Authenticate", www_authenticate.as_str())],
            body,
        )
            .into_response()
    }
}

/// JWT token claims structure
///
/// Note: exp validation is disabled in the legacy implementation,
/// and exp is always set to 0. This maintains that behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobJwtClaims {
    pub exp: u64,
    pub job_id: JobId,
}

/// Job authorizer trait (matches legacy implementation)
pub trait JobAuthorizer: Send + Sync {
    fn generate_token(&self, job_id: JobId) -> crate::errors::Result<String>;
    fn verify_token(&self, job_id: JobId, token: &str) -> crate::errors::Result<()>;
}

/// JWT-based job authorizer using HS256
#[cfg(feature = "jwt")]
pub struct JWTJobAuthorizer {
    server_key: Vec<u8>,
    header: jwt::Header,
    validation: jwt::Validation,
}

#[cfg(feature = "jwt")]
impl JWTJobAuthorizer {
    pub fn new(server_key: Vec<u8>) -> Arc<Self> {
        let header = jwt::Header::new(jwt::Algorithm::HS256);
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;
        validation.validate_exp = false;
        validation.validate_nbf = false;

        Arc::new(Self {
            server_key,
            header,
            validation,
        })
    }
}

#[cfg(feature = "jwt")]
impl JobAuthorizer for JWTJobAuthorizer {
    fn generate_token(&self, job_id: JobId) -> crate::errors::Result<String> {
        let claims = JobJwtClaims { exp: 0, job_id };
        let key = jwt::EncodingKey::from_secret(&self.server_key);
        jwt::encode(&self.header, &claims, &key)
            .map_err(|e| anyhow::anyhow!("Failed to create JWT for job: {}", e))
    }

    fn verify_token(&self, job_id: JobId, token: &str) -> crate::errors::Result<()> {
        let valid_claims = JobJwtClaims { exp: 0, job_id };
        let key = jwt::DecodingKey::from_secret(&self.server_key);
        let token_data = jwt::decode::<JobJwtClaims>(token, &key, &self.validation)
            .map_err(|e| anyhow::anyhow!("JWT decode failed: {}", e))?;

        if token_data.claims == valid_claims {
            Ok(())
        } else {
            Err(anyhow::anyhow!("mismatched claims"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_token_verification() {
        let ja = JWTJobAuthorizer::new(vec![1, 2, 2]);

        let job_id = JobId(55);
        let token = ja.generate_token(job_id).unwrap();

        let job_id2 = JobId(56);
        let token2 = ja.generate_token(job_id2).unwrap();

        let ja2 = JWTJobAuthorizer::new(vec![1, 2, 3]);

        // Check tokens are deterministic
        assert_eq!(token, ja.generate_token(job_id).unwrap());
        // Check token verification works
        assert!(ja.verify_token(job_id, &token).is_ok());
        assert!(ja.verify_token(job_id, &token2).is_err());
        assert!(ja.verify_token(job_id2, &token).is_err());
        assert!(ja.verify_token(job_id2, &token2).is_ok());
        // Check token verification with a different key fails
        assert!(ja2.verify_token(job_id, &token).is_err());
        assert!(ja2.verify_token(job_id2, &token2).is_err());
    }
}
