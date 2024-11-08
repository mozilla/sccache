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

#[cfg(feature = "azure")]
pub mod azure;
#[allow(clippy::module_inception)]
pub mod cache;
pub mod disk;
#[cfg(feature = "gcs")]
pub mod gcs;
#[cfg(feature = "gha")]
pub mod gha;
#[cfg(feature = "memcached")]
pub mod memcached;
#[cfg(feature = "oss")]
pub mod oss;
pub mod readonly;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "webdav")]
pub mod webdav;

#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "s3",
    feature = "webdav",
    feature = "oss"
))]
pub(crate) mod http_client;

pub use crate::cache::cache::*;
