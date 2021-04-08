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

pub use anyhow::{anyhow, bail, Context, Error};
use std::process;

// We use `anyhow` for error handling.
// - Use `context()`/`with_context()` to annotate errors.
// - Use `anyhow!` with a string to create a new `anyhow::Error`.
// - The error types below (`BadHttpStatusError`, etc.) are internal ones that
//   need to be checked at points other than the outermost error-checking
//   layer.

#[cfg(feature = "hyper")]
#[derive(Debug)]
pub struct BadHttpStatusError(pub hyper::StatusCode);

#[derive(Debug)]
pub struct HttpClientError(pub String);

#[derive(Debug)]
pub struct ProcessError(pub process::Output);

#[cfg(feature = "hyper")]
impl std::error::Error for BadHttpStatusError {}

impl std::error::Error for HttpClientError {}

impl std::error::Error for ProcessError {}

#[cfg(feature = "hyper")]
impl std::fmt::Display for BadHttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "didn't get a successful HTTP status, got `{}`", self.0)
    }
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "didn't get a successful HTTP status, got `{}`", self.0)
    }
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0.stderr))
    }
}

pub type Result<T> = anyhow::Result<T>;
