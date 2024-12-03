// Copyright 2018 Benjamin Bader
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

use opendal::Operator;

use opendal::layers::LoggingLayer;
use opendal::services::Azblob;

use crate::errors::*;

use super::http_client::set_user_agent;

pub struct AzureBlobCache;

impl AzureBlobCache {
    pub fn build(connection_string: &str, container: &str, key_prefix: &str) -> Result<Operator> {
        let builder = Azblob::from_connection_string(connection_string)?
            .container(container)
            .root(key_prefix)
            .http_client(set_user_agent());

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
