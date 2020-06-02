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
use futures::future;
use futures::Future;
use std::boxed::Box;
use std::fmt::Display;
use std::process;

// We use `anyhow` for error handling.
// - Use `context()`/`with_context()` to annotate errors.
// - Use `anyhow!` with a string to create a new `anyhow::Error`.
// - The error types below (`BadHttpStatusError`, etc.) are internal ones that
//   need to be checked at points other than the outermost error-checking
//   layer.
// - There are some combinators below for working with futures.

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

pub type SFuture<T> = Box<dyn Future<Item = T, Error = Error>>;
pub type SFutureSend<T> = Box<dyn Future<Item = T, Error = Error> + Send>;

pub trait FutureContext<T> {
    fn fcontext<C>(self, context: C) -> SFuture<T>
    where
        C: Display + Send + Sync + 'static;

    fn fwith_context<C, CB>(self, callback: CB) -> SFuture<T>
    where
        CB: FnOnce() -> C + 'static,
        C: Display + Send + Sync + 'static;
}

impl<F> FutureContext<F::Item> for F
where
    F: Future + 'static,
    F::Error: Into<Error> + Send + Sync,
{
    fn fcontext<C>(self, context: C) -> SFuture<F::Item>
    where
        C: Display + Send + Sync + 'static,
    {
        Box::new(self.then(|r| r.map_err(F::Error::into).context(context)))
    }

    fn fwith_context<C, CB>(self, callback: CB) -> SFuture<F::Item>
    where
        CB: FnOnce() -> C + 'static,
        C: Display + Send + Sync + 'static,
    {
        Box::new(self.then(|r| r.map_err(F::Error::into).context(callback())))
    }
}

/// Like `try`, but returns an SFuture instead of a Result.
macro_rules! ftry {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Box::new($crate::futures::future::err(e.into())) as SFuture<_>,
        }
    };
}

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
macro_rules! ftry_send {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Box::new($crate::futures::future::err(e)) as SFutureSend<_>,
        }
    };
}

pub fn f_ok<T>(t: T) -> SFuture<T>
where
    T: 'static,
{
    Box::new(future::ok(t))
}

pub fn f_err<T, E>(e: E) -> SFuture<T>
where
    T: 'static,
    E: Into<Error>,
{
    Box::new(future::err(e.into()))
}
