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
#![allow(renamed_and_removed_lints)]

use std::boxed::Box;
use std::convert;
use std::error;
use std::io;

use bincode;
use futures::Future;
use futures::future;
use lru_disk_cache;
use serde_json;
use reqwest;

error_chain! {
    foreign_links {
        Io(io::Error);
        Lru(lru_disk_cache::Error);
        Json(serde_json::Error);
        Bincode(bincode::Error);
        Reqwest(reqwest::Error);
    }

    errors {
    }
}

pub type SDFuture<T> = Box<Future<Item = T, Error = Error>>;

pub trait FutureChainErr<T> {
    fn chain_err<F, E>(self, callback: F) -> SDFuture<T>
        where F: FnOnce() -> E + 'static,
              E: Into<ErrorKind>;
}

impl<F> FutureChainErr<F::Item> for F
    where F: Future + 'static,
          F::Error: error::Error + Send + 'static,
{
    fn chain_err<C, E>(self, callback: C) -> SDFuture<F::Item>
        where C: FnOnce() -> E + 'static,
              E: Into<ErrorKind>,
    {
        Box::new(self.then(|r| r.chain_err(callback)))
    }
}

pub fn f_res<T, E: convert::Into<Error>>(t: ::std::result::Result<T, E>) -> SDFuture<T>
    where T: 'static,
{
    Box::new(future::result(t.map_err(Into::into)))
}

pub fn f_ok<T>(t: T) -> SDFuture<T>
    where T: 'static,
{
    Box::new(future::ok(t))
}

pub fn f_err<T, E>(e: E) -> SDFuture<T>
    where T: 'static,
          E: Into<Error>,
{
    Box::new(future::err(e.into()))
}
