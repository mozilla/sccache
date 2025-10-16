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

//! Custom extractors for axum
//!
//! This module provides extractors that handle the legacy protocol format,
//! including bincode serialization and special streaming formats.

use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequest, Request},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Extractor for bincode-serialized request bodies
///
/// This extractor expects:
/// - Content-Type: application/octet-stream
/// - Body: bincode-serialized data
///
/// This matches the legacy protocol format exactly.
pub struct Bincode<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for Bincode<T>
where
    S: Send + Sync,
    T: for<'de> Deserialize<'de>,
{
    type Rejection = BincodeRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Check Content-Type header
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .ok_or(BincodeRejection::WrongContentType)?;

        if !content_type.starts_with("application/octet-stream") {
            return Err(BincodeRejection::WrongContentType);
        }

        // Extract body bytes
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| BincodeRejection::BodyAlreadyExtracted)?;

        // Deserialize from bincode
        let value = bincode::deserialize(&bytes).map_err(BincodeRejection::ParseError)?;

        Ok(Bincode(value))
    }
}

/// Rejection types for bincode extraction
#[derive(Debug)]
pub enum BincodeRejection {
    WrongContentType,
    BodyAlreadyExtracted,
    ParseError(bincode::Error),
}

impl IntoResponse for BincodeRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            BincodeRejection::WrongContentType => (
                StatusCode::BAD_REQUEST,
                "Content-Type must be application/octet-stream",
            ),
            BincodeRejection::BodyAlreadyExtracted => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Body already extracted")
            }
            BincodeRejection::ParseError(_) => {
                (StatusCode::BAD_REQUEST, "Failed to parse bincode body")
            }
        };

        (status, message).into_response()
    }
}

impl std::fmt::Display for BincodeRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BincodeRejection::WrongContentType => {
                write!(f, "the request didn't have a binary content type")
            }
            BincodeRejection::BodyAlreadyExtracted => {
                write!(f, "the body of the request was already extracted")
            }
            BincodeRejection::ParseError(_) => write!(f, "error while parsing the bincode body"),
        }
    }
}

impl std::error::Error for BincodeRejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BincodeRejection::ParseError(e) => Some(e),
            _ => None,
        }
    }
}

/// Response format enum to support both bincode and JSON
///
/// The legacy protocol supports content negotiation via Accept header:
/// - application/octet-stream -> bincode (default)
/// - application/json -> JSON
#[derive(Debug, Clone, Copy)]
pub enum ResponseFormat {
    Bincode,
    Json,
}

impl ResponseFormat {
    /// Determine response format from Accept header
    pub fn from_accept(accept: Option<&str>) -> Self {
        if let Some(accept) = accept {
            if accept.contains("application/json") {
                return Self::Json;
            }
        }
        Self::Bincode
    }

    /// Convert data to response with appropriate format
    pub fn into_response<T: Serialize>(self, data: &T) -> Result<Response, ResponseError> {
        match self {
            Self::Bincode => {
                let bytes = bincode::serialize(data)
                    .map_err(|e| ResponseError::SerializationError(e.to_string()))?;

                Ok((
                    StatusCode::OK,
                    [(CONTENT_TYPE, "application/octet-stream")],
                    bytes,
                )
                    .into_response())
            }
            Self::Json => {
                let json = serde_json::to_vec(data)
                    .map_err(|e| ResponseError::SerializationError(e.to_string()))?;

                Ok((StatusCode::OK, [(CONTENT_TYPE, "application/json")], json).into_response())
            }
        }
    }
}

/// Error type for response formatting
#[derive(Debug)]
pub enum ResponseError {
    SerializationError(String),
}

impl From<ResponseError> for anyhow::Error {
    fn from(err: ResponseError) -> Self {
        match err {
            ResponseError::SerializationError(msg) => {
                anyhow::anyhow!("Serialization error: {}", msg)
            }
        }
    }
}

impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        match self {
            ResponseError::SerializationError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_format_from_accept() {
        assert!(matches!(
            ResponseFormat::from_accept(None),
            ResponseFormat::Bincode
        ));
        assert!(matches!(
            ResponseFormat::from_accept(Some("application/octet-stream")),
            ResponseFormat::Bincode
        ));
        assert!(matches!(
            ResponseFormat::from_accept(Some("application/json")),
            ResponseFormat::Json
        ));
        assert!(matches!(
            ResponseFormat::from_accept(Some("text/html, application/json")),
            ResponseFormat::Json
        ));
    }
}
