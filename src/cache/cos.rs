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
use opendal::layers::{HttpClientLayer, LoggingLayer};
use opendal::services::Cos;

use crate::errors::*;

use super::http_client::set_user_agent;

pub struct COSCache;

// Implement for Tencent Cloud Object Storage
impl COSCache {
    pub fn build(bucket: &str, key_prefix: &str, endpoint: Option<&str>) -> Result<Operator> {
        let mut builder = Cos::default().bucket(bucket).root(key_prefix);

        if let Some(endpoint) = endpoint {
            builder = builder.endpoint(endpoint);
        }

        let op = Operator::new(builder)?
            .layer(HttpClientLayer::new(set_user_agent()))
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
