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

use std::boxed::Box;
use std::error;
use std::io;
use std::process;

use bincode;
use futures::Future;
use futures::future;
#[cfg(feature = "hyper")]
use hyper;
#[cfg(feature = "jsonwebtoken")]
use jwt;
use lru_disk_cache;
#[cfg(feature = "memcached")]
use memcached;
use native_tls;
#[cfg(feature = "openssl")]
use openssl;
use serde_json;
#[cfg(feature = "redis")]
use redis;
use tempfile;

error_chain! {
    foreign_links {
        Hyper(hyper::Error) #[cfg(feature = "hyper")];
        Io(io::Error);
        Lru(lru_disk_cache::Error);
        Json(serde_json::Error);
        Jwt(jwt::errors::Error) #[cfg(feature = "jsonwebtoken")];
        Openssl(openssl::error::ErrorStack) #[cfg(feature = "openssl")];
        Bincode(bincode::Error);
        Memcached(memcached::proto::Error) #[cfg(feature = "memcached")];
        Redis(redis::RedisError) #[cfg(feature = "redis")];
        StrFromUtf8(::std::string::FromUtf8Error) #[cfg(feature = "gcs")];
        TempfilePersist(tempfile::PersistError);
        Tls(native_tls::Error);
    }

    errors {
        #[cfg(feature = "hyper")]
        BadHTTPStatus(status: hyper::StatusCode) {
            description("failed to get a successful HTTP status")
            display("didn't get a successful HTTP status, got `{}`", status)
        }
        ProcessError(output: process::Output)
    }
}

pub type SFuture<T> = Box<Future<Item = T, Error = Error>>;

pub trait FutureChainErr<T> {
    fn chain_err<F, E>(self, callback: F) -> SFuture<T>
        where F: FnOnce() -> E + 'static,
              E: Into<ErrorKind>;
}

impl<F> FutureChainErr<F::Item> for F
    where F: Future + 'static,
          F::Error: error::Error + Send + 'static,
{
    fn chain_err<C, E>(self, callback: C) -> SFuture<F::Item>
        where C: FnOnce() -> E + 'static,
              E: Into<ErrorKind>,
    {
        Box::new(self.then(|r| r.chain_err(callback)))
    }
}

/// Like `try`, but returns an SFuture instead of a Result.
macro_rules! ftry {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Box::new(future::err(e.into())),
        }
    }
}

pub fn f_ok<T>(t: T) -> SFuture<T>
    where T: 'static,
{
    Box::new(future::ok(t))
}

pub fn f_err<T, E>(e: E) -> SFuture<T>
    where T: 'static,
          E: Into<Error>,
{
    Box::new(future::err(e.into()))
}
