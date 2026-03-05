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

//! Preprocessing logic for client-side compilation.

use crate::errors::*;

/// Preprocess source files for caching.
///
/// This is a placeholder for the preprocessing logic that will
/// be moved from the server to the client.
pub async fn preprocess_source(_source_path: &str) -> Result<Vec<u8>> {
    // TODO: Implement preprocessing
    // This should use the same logic as the server currently uses
    bail!("Preprocessing not yet implemented")
}
