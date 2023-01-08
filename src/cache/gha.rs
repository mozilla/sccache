// Copyright 2022 Bitski Inc.
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

use opendal::layers::LoggingLayer;
use opendal::services::ghac;
use opendal::Operator;

use crate::errors::*;

/// A cache that stores entries in GHA Cache Services.
pub struct GHACache;

impl GHACache {
    pub fn build(version: &str) -> Result<Operator> {
        let mut builder = ghac::Builder::default();
        builder.version(version);

        let op: Operator = builder.build()?.into();
        Ok(op.layer(LoggingLayer::default()))
    }
}
