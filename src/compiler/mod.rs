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

#[macro_use]
mod args;
mod c;
mod clang;
#[macro_use]
#[allow(clippy::module_inception)]
mod compiler;
mod diab;
mod gcc;
mod msvc;
mod nvcc;
mod rust;
mod tasking_vx;

pub use crate::compiler::compiler::*;
