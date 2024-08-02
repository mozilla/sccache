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
use opendal::layers::LoggingLayer;
use opendal::services::Webdav;
use opendal::Operator;

/// A cache that stores entries in a Webdav.
pub struct WebdavCache;

impl WebdavCache {
    /// Create a new `WebdavCache`.
    pub fn build(
        endpoint: &str,
        key_prefix: &str,
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
    ) -> Result<Operator> {
        let builder = Webdav::default()
            .endpoint(endpoint)
            .root(key_prefix)
            .username(username.unwrap_or_default())
            .password(password.unwrap_or_default())
            .token(token.unwrap_or_default());

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }
}
