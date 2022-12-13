// Copyright 2017 Mozilla Foundation
// Copyright 2017 Google Inc.
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

use crate::errors::*;
use opendal::services::gcs;
use opendal::Operator;

#[derive(Copy, Clone)]
pub enum RWMode {
    ReadOnly,
    ReadWrite,
}

impl RWMode {
    fn to_scope(self) -> &'static str {
        match self {
            RWMode::ReadOnly => "https://www.googleapis.com/auth/devstorage.readonly",
            RWMode::ReadWrite => "https://www.googleapis.com/auth/devstorage.read_write",
        }
    }
}

/// A cache that stores entries in Google Cloud Storage
pub struct GCSCache;

impl GCSCache {
    /// Create a new `GCSCache` storing data in `bucket`
    pub fn build(
        bucket: &str,
        key_prefix: &str,
        cred_path: Option<&str>,
        service_account: Option<&str>,
        rw_mode: RWMode,
    ) -> Result<Operator> {
        let mut builder = gcs::Builder::default();
        builder.bucket(bucket);
        builder.root(key_prefix);
        builder.scope(rw_mode.to_scope());
        if let Some(service_account) = service_account {
            builder.service_account(service_account);
        }
        if let Some(path) = cred_path {
            builder.credential_path(path);
        }

        Ok(builder.build()?.into())
    }
}
