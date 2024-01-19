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
use opendal::services::Oss;
use opendal::Operator;

use crate::errors::*;

pub struct OSSCache;

impl OSSCache {
    pub fn build(bucket: &str, key_prefix: &str, endpoint: Option<&str>) -> Result<Operator> {
        let mut builder = Oss::default();
        builder.bucket(bucket);
        builder.root(key_prefix);

        if let Some(endpoint) = endpoint {
            builder.endpoint(endpoint);
        }

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
