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

//! Modern axum-based HTTP server implementation for dist-server
//!
//! This module provides an async, high-performance alternative to the legacy
//! rouille-based implementation. It maintains 100% protocol compatibility
//! while offering better performance and maintainability.

mod auth;
mod extractors;
mod handlers;
mod scheduler;
mod server;
mod streaming;
mod tls;

#[cfg(test)]
mod tests;

pub use scheduler::Scheduler;
pub use server::{HEARTBEAT_TIMEOUT, Server};

// Re-export common types that are used by both implementations
pub use super::http::server::{ClientAuthCheck, ClientVisibleMsg, ServerAuthCheck};
