// Copyright 2016 Mozilla Foundation
// SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#![allow(unused_imports, dead_code, unused_variables)]

use crate::compiler::args::*;
use crate::compiler::c::{ArtifactDescriptor, CCompilerImpl, CCompilerKind, ParsedArguments};
use crate::compiler::cicc;
use crate::compiler::{
    CCompileCommand, Cacheable, ColorMode, CompileCommand, CompilerArguments, Language,
    SingleCompileCommand,
};
use crate::{counted_array, dist};

use crate::mock_command::{CommandCreator, CommandCreatorSync, RunCommand};

use async_trait::async_trait;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use crate::errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct CudaFE {
    pub version: Option<String>,
}

#[async_trait]
impl CCompilerImpl for CudaFE {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::CudaFE
    }
    fn plusplus(&self) -> bool {
        true
    }
    fn version(&self) -> Option<String> {
        self.version.clone()
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments> {
        cicc::parse_arguments(arguments, cwd, Language::CudaFE, &ARGS[..], 1)
    }
    #[allow(clippy::too_many_arguments)]
    async fn preprocess<T>(
        &self,
        _creator: &T,
        _executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
        _may_dist: bool,
        _rewrite_includes_only: bool,
        _preprocessor_cache_mode: bool,
    ) -> Result<process::Output>
    where
        T: CommandCreatorSync,
    {
        cicc::preprocess(cwd, parsed_args).await
    }
    fn generate_compile_commands<T>(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        _rewrite_includes_only: bool,
        _unique_compilation_key: &str,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )>
    where
        T: CommandCreatorSync,
    {
        generate_compile_commands(path_transformer, executable, parsed_args, cwd, env_vars).map(
            |(command, dist_command, cacheable)| {
                (CCompileCommand::new(command), dist_command, cacheable)
            },
        )
    }
}

pub fn generate_compile_commands(
    path_transformer: &mut dist::PathTransformer,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<(
    SingleCompileCommand,
    Option<dist::CompileCommand>,
    Cacheable,
)> {
    // Unused arguments
    #[cfg(not(feature = "dist-client"))]
    {
        let _ = path_transformer;
    }

    let lang_str = &parsed_args.language.as_str();
    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => &obj.path,
        None => return Err(anyhow!("Missing {:?} file output", lang_str)),
    };

    let mut arguments: Vec<OsString> = vec![];
    arguments.extend_from_slice(&parsed_args.common_args);
    arguments.extend_from_slice(&parsed_args.unhashed_args);
    arguments.extend(vec![
        "--module_id_file_name".into(),
        out_file.into(),
        (&parsed_args.input).into(),
    ]);

    if log_enabled!(log::Level::Trace) {
        trace!(
            "[{}]: {} command: {:?}",
            out_file.file_name().unwrap().to_string_lossy(),
            executable.file_name().unwrap().to_string_lossy(),
            [
                &[format!("cd {} &&", cwd.to_string_lossy()).to_string()],
                &[executable.to_str().unwrap_or_default().to_string()][..],
                &dist::osstrings_to_strings(&arguments).unwrap_or_default()[..]
            ]
            .concat()
            .join(" ")
        );
    }

    let command = SingleCompileCommand {
        executable: executable.to_owned(),
        arguments,
        env_vars: env_vars.to_owned(),
        cwd: cwd.to_owned(),
    };

    #[cfg(not(feature = "dist-client"))]
    let dist_command = None;
    #[cfg(feature = "dist-client")]
    let dist_command = (|| {
        let mut arguments: Vec<String> = vec![];
        arguments.extend(dist::osstrings_to_strings(&parsed_args.common_args)?);
        arguments.extend(dist::osstrings_to_strings(&parsed_args.unhashed_args)?);
        arguments.extend(vec![
            "--module_id_file_name".into(),
            path_transformer.as_dist(out_file)?,
            path_transformer.as_dist(&parsed_args.input)?,
        ]);
        Some(dist::CompileCommand {
            executable: path_transformer.as_dist(executable.canonicalize().unwrap().as_path())?,
            arguments,
            env_vars: dist::osstring_tuples_to_strings(env_vars)?,
            cwd: path_transformer.as_dist_abs(cwd)?,
        })
    })();

    Ok((command, dist_command, Cacheable::Yes))
}

use cicc::ArgData::*;

counted_array!(pub static ARGS: [ArgInfo<cicc::ArgData>; _] = [
    take_arg!("--gen_c_file_name", PathBuf, Separated, ExtraOutput),
    flag!("--gen_module_id_file", GenModuleIdFileFlag),
    take_arg!("--module_id_file_name", PathBuf, Separated, Output),
    take_arg!("--stub_file_name", OsString, Separated, UnhashedPassThrough),
]);
