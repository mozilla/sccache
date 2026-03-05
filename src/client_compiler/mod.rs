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

//! Client-side compiler detection, caching, and compilation orchestration.
//!
//! This module handles all compiler-related operations on the client side,
//! allowing the server to become a pure storage service.

// Placeholder implementations are not yet wired up; suppress dead_code warnings.
#![allow(dead_code)]

pub mod cache;
pub mod compile;
pub mod detect;
pub mod hash;
pub mod preprocess;
