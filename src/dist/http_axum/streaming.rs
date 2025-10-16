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

//! Streaming request body handlers
//!
//! This module handles special streaming formats used by the dist protocol:
//! 1. submit_toolchain: raw byte stream
//! 2. run_job: custom format with length-prefixed bincode + zlib-compressed inputs

use crate::dist::{CompileCommand, InputsReader, ToolchainReader};
use axum::{
    async_trait,
    body::Body,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use tokio::io::AsyncRead;

/// Extractor for toolchain upload stream
///
/// This simply wraps the request body as a raw byte stream
/// for the toolchain handler to process.
pub struct ToolchainStream<'a>(pub ToolchainReader<'a>);

#[async_trait]
impl<'a, S> FromRequest<S> for ToolchainStream<'a>
where
    S: Send + Sync,
{
    type Rejection = StreamError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let body = req.into_body();
        
        // Convert axum body to a synchronous reader for compatibility
        // with existing ToolchainReader interface
        let reader = BodyReader::new(body);
        
        Ok(ToolchainStream(ToolchainReader(Box::new(reader))))
    }
}

/// Request structure for run_job endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct RunJobHttpRequest {
    pub command: CompileCommand,
    pub outputs: Vec<String>,
}

/// Extractor for run_job special format
///
/// Format:
/// - 4 bytes: big-endian u32 length (L) of bincode data
/// - L bytes: bincode-serialized RunJobHttpRequest
/// - Remaining: zlib-compressed inputs stream
pub struct RunJobBody<'a> {
    pub command: CompileCommand,
    pub outputs: Vec<String>,
    pub inputs_reader: InputsReader<'a>,
}

#[async_trait]
impl<'a, S> FromRequest<S> for RunJobBody<'a>
where
    S: Send + Sync,
{
    type Rejection = StreamError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let body = req.into_body();
        let stream_data = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|e| StreamError::ReadError(format!("Failed to read body: {}", e)))?;
        
        let mut cursor = std::io::Cursor::new(stream_data);

        // 1. Read 4-byte length prefix
        let mut len_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut len_bytes)
            .map_err(|e| StreamError::ReadError(format!("Failed to read length prefix: {}", e)))?;
        
        let bincode_len = u32::from_be_bytes(len_bytes) as usize;

        // 2. Read bincode portion
        let mut bincode_buf = vec![0u8; bincode_len];
        std::io::Read::read_exact(&mut cursor, &mut bincode_buf)
            .map_err(|e| StreamError::ReadError(format!("Failed to read bincode data: {}", e)))?;

        let request: RunJobHttpRequest = bincode::deserialize(&bincode_buf)
            .map_err(|e| StreamError::ParseError(format!("Failed to parse bincode: {}", e)))?;

        // 3. Read remaining data into buffer for zlib decompression
        let mut remaining = Vec::new();
        std::io::Read::read_to_end(&mut cursor, &mut remaining)
            .map_err(|e| StreamError::ReadError(format!("Failed to read remaining data: {}", e)))?;
        
        // Wrap in zlib decoder
        let inputs_reader = InputsReader(Box::new(flate2::read::ZlibDecoder::new(std::io::Cursor::new(remaining))));

        Ok(RunJobBody {
            command: request.command,
            outputs: request.outputs,
            inputs_reader,
        })
    }
}

/// Error types for streaming operations
#[derive(Debug)]
pub enum StreamError {
    ReadError(String),
    ParseError(String),
}

impl IntoResponse for StreamError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            StreamError::ReadError(msg) => (StatusCode::BAD_REQUEST, msg),
            StreamError::ParseError(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, message).into_response()
    }
}

/// Adapter to convert axum Body to synchronous Read
///
/// This is needed because the existing dist infrastructure expects
/// synchronous Read traits. We use tokio::runtime::Handle::block_on
/// to bridge async to sync.
struct BodyReader {
    body: Body,
    runtime: tokio::runtime::Handle,
}

impl BodyReader {
    fn new(body: Body) -> Self {
        Self {
            body,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // For simplicity in this impl, we just collect all bytes
        // In production, this should use a buffered approach
        self.runtime.block_on(async {
            
            
            
            // Collect body into bytes
            match axum::body::to_bytes(std::mem::replace(&mut self.body, Body::empty()), usize::MAX)
                .await 
            {
                Ok(data) => {
                    let len = std::cmp::min(buf.len(), data.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    // Store remaining data back
                    if data.len() > len {
                        self.body = Body::from(data.slice(len..));
                    }
                    Ok(len)
                }
                Err(e) => Err(io::Error::other(e)),
            }
        })
    }
}

/// Adapter to convert AsyncRead to synchronous Read
///
/// Similar to BodyReader, this bridges async to sync for compatibility.
struct AsyncToSyncReader<R> {
    inner: R,
    runtime: tokio::runtime::Handle,
}

impl<R: AsyncRead + Unpin> AsyncToSyncReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl<R: AsyncRead + Unpin> Read for AsyncToSyncReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.runtime.block_on(async {
            use tokio::io::AsyncReadExt;
            self.inner.read(buf).await
        })
    }
}
