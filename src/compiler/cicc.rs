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
pub struct Cicc {
    pub version: Option<String>,
}

#[async_trait]
impl CCompilerImpl for Cicc {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::Cicc
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
        parse_arguments(arguments, cwd, Language::Ptx, &ARGS[..])
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
        preprocess(cwd, parsed_args).await
    }
    fn generate_compile_commands<T>(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        _rewrite_includes_only: bool,
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

pub fn parse_arguments<S>(
    arguments: &[OsString],
    cwd: &Path,
    language: Language,
    arg_info: S,
) -> CompilerArguments<ParsedArguments>
where
    S: SearchableArgInfo<ArgData>,
{
    let mut args = arguments.to_vec();
    let input_loc = arguments.len() - 3;
    let input = args.splice(input_loc..input_loc + 1, []).next().unwrap();

    let mut take_next = false;
    let mut outputs = HashMap::new();
    let mut extra_dist_files = vec![];
    let mut gen_module_id_file = false;
    let mut module_id_file_name = Option::<PathBuf>::None;

    let mut common_args = vec![];
    let mut unhashed_args = vec![];

    for arg in ArgsIter::new(args.iter().cloned(), arg_info) {
        match arg {
            Ok(arg) => {
                let args = match arg.get_data() {
                    Some(PassThrough(_)) => {
                        take_next = false;
                        &mut common_args
                    }
                    Some(Output(o)) => {
                        take_next = false;
                        let path = cwd.join(o);
                        outputs.insert(
                            "obj",
                            ArtifactDescriptor {
                                path,
                                optional: false,
                            },
                        );
                        continue;
                    }
                    Some(UnhashedGenModuleIdFileFlag) => {
                        take_next = false;
                        gen_module_id_file = true;
                        &mut unhashed_args
                    }
                    Some(UnhashedModuleIdFileName(o)) => {
                        take_next = false;
                        module_id_file_name = Some(cwd.join(o));
                        &mut unhashed_args
                    }
                    Some(UnhashedOutput(o)) => {
                        take_next = false;
                        let path = cwd.join(o);
                        if let Some(flag) = arg.flag_str() {
                            outputs.insert(
                                flag,
                                ArtifactDescriptor {
                                    path,
                                    optional: false,
                                },
                            );
                        }
                        &mut unhashed_args
                    }
                    Some(UnhashedFlag) => {
                        take_next = false;
                        &mut unhashed_args
                    }
                    None => match arg {
                        Argument::Raw(ref p) => {
                            if take_next {
                                take_next = false;
                                &mut common_args
                            } else {
                                continue;
                            }
                        }
                        Argument::UnknownFlag(ref p) => {
                            let s = p.to_string_lossy();
                            take_next = s.starts_with('-');
                            &mut common_args
                        }
                        _ => unreachable!(),
                    },
                };
                args.extend(arg.iter_os_strings());
            }
            _ => continue,
        };
    }

    if let Some(module_id_path) = module_id_file_name {
        if gen_module_id_file {
            outputs.insert(
                "--module_id_file_name",
                ArtifactDescriptor {
                    path: module_id_path,
                    optional: true,
                },
            );
        } else {
            extra_dist_files.push(module_id_path);
        }
    }

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        outputs,
        double_dash_input: false,
        language,
        compilation_flag: OsString::new(),
        depfile: None,
        dependency_args: vec![],
        preprocessor_args: vec![],
        common_args,
        arch_args: vec![],
        unhashed_args,
        extra_dist_files,
        extra_hash_files: vec![],
        msvc_show_includes: false,
        profile_generate: false,
        color_mode: ColorMode::Off,
        suppress_rewrite_includes_only: false,
        too_hard_for_preprocessor_cache_mode: None,
    })
}

pub async fn preprocess(cwd: &Path, parsed_args: &ParsedArguments) -> Result<process::Output> {
    // cicc and ptxas expect input to be an absolute path
    let input = if parsed_args.input.is_absolute() {
        parsed_args.input.clone()
    } else {
        cwd.join(&parsed_args.input)
    };
    std::fs::read(input)
        .map_err(anyhow::Error::new)
        .map(|s| process::Output {
            status: process::ExitStatus::default(),
            stdout: s,
            stderr: vec![],
        })
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

    trace!("compile");

    let lang_str = &parsed_args.language.as_str();
    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => &obj.path,
        None => return Err(anyhow!("Missing {:?} file output", lang_str)),
    };

    let mut arguments: Vec<OsString> = vec![];
    arguments.extend_from_slice(&parsed_args.common_args);
    arguments.extend_from_slice(&parsed_args.unhashed_args);
    arguments.extend(vec![
        (&parsed_args.input).into(),
        "-o".into(),
        out_file.into(),
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
            path_transformer.as_dist(&parsed_args.input)?,
            "-o".into(),
            path_transformer.as_dist(out_file)?,
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

ArgData! { pub
    Output(PathBuf),
    PassThrough(OsString),
    UnhashedFlag,
    UnhashedGenModuleIdFileFlag,
    UnhashedModuleIdFileName(PathBuf),
    UnhashedOutput(PathBuf),
}

use self::ArgData::*;

counted_array!(pub static ARGS: [ArgInfo<ArgData>; _] = [
    take_arg!("--gen_c_file_name", PathBuf, Separated, UnhashedOutput),
    take_arg!("--gen_device_file_name", PathBuf, Separated, UnhashedOutput),
    flag!("--gen_module_id_file", UnhashedGenModuleIdFileFlag),
    take_arg!("--include_file_name", OsString, Separated, PassThrough),
    take_arg!("--module_id_file_name", PathBuf, Separated, UnhashedModuleIdFileName),
    take_arg!("--stub_file_name", PathBuf, Separated, UnhashedOutput),
    take_arg!("-o", PathBuf, Separated, Output),
]);
