// Copyright 2018 Mozilla Foundation
// Copyright 2019 ESRLabs AG
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

use crate::{
    compiler::{
        args::{
            ArgDisposition, ArgInfo, ArgToStringResult, ArgsIter, Argument, FromArg, IntoArg,
            NormalizedDisposition, PathTransformerFn, SearchableArgInfo,
        },
        c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments},
        Cacheable, ColorMode, CompileCommand, CompilerArguments,
    },
    dist,
    errors::*,
    mock_command::{CommandCreatorSync, RunCommand},
    util::run_input_output,
};
use futures::Future;
use log::Level::Trace;
use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    process,
};

#[derive(Clone, Debug)]
pub struct TaskingVX;

impl CCompilerImpl for TaskingVX {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::TaskingVX
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
    ) -> CompilerArguments<ParsedArguments> {
        parse_arguments(arguments, cwd, &ARGS[..])
    }

    fn preprocess<T>(
        &self,
        creator: &T,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        may_dist: bool,
        rewrite_includes_only: bool,
    ) -> SFuture<process::Output>
    where
        T: CommandCreatorSync,
    {
        preprocess(
            creator,
            executable,
            parsed_args,
            cwd,
            env_vars,
            may_dist,
            rewrite_includes_only,
        )
    }

    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        rewrite_includes_only: bool,
    ) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
        generate_compile_commands(
            path_transformer,
            executable,
            parsed_args,
            cwd,
            env_vars,
            rewrite_includes_only,
        )
    }
}

ArgData! { pub
    DoCompilation,
    Output(PathBuf),
    PassThrough(OsString),
    PreprocessorArgument(OsString),
    PreprocessorArgumentPath(PathBuf),
    DepFile(PathBuf),
    TooHardFlag,
    TooHard(OsString),
}

use self::ArgData::*;

counted_array!(pub static ARGS: [ArgInfo<ArgData>; _] = [
    take_arg!("--define", OsString, Concatenated('='), PreprocessorArgument),
    // --dep-file without any argument is valid too and uses the source file name
    // with extension .o as depfile name
    take_arg!("--dep-file", PathBuf, Concatenated('='), DepFile), // TODO
    take_arg!("--include-directory", PathBuf, Concatenated('='), PreprocessorArgumentPath),
    take_arg!("--library-directory", OsString, Concatenated('='), PassThrough),
    take_arg!("--option-file", OsString, Concatenated('='), TooHard),
    take_arg!("--output", PathBuf, Concatenated('='), Output),
    take_arg!("--preprocess", OsString, Concatenated('='), TooHard),
    take_arg!("--undefine", OsString, Separated, PreprocessorArgument), // ok
    take_arg!("-D", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-E", TooHardFlag),
    take_arg!("-I", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-L", OsString, CanBeSeparated, PassThrough),
    take_arg!("-U", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-c", DoCompilation),
    take_arg!("-f", OsString, Separated, TooHard),
    take_arg!("-o", PathBuf, Separated, Output),
]);

/// Parse `arguments`, determining whether it is supported.
///
/// If any of the entries in `arguments` result in a compilation that
/// cannot be cached, return `CompilerArguments::CannotCache`.
/// If the commandline described by `arguments` is not compilation,
/// return `CompilerArguments::NotCompilation`.
/// Otherwise, return `CompilerArguments::Ok(ParsedArguments)`, with
/// the `ParsedArguments` struct containing information parsed from
/// `arguments`.
fn parse_arguments<S>(
    arguments: &[OsString],
    _cwd: &Path,
    arg_info: S,
) -> CompilerArguments<ParsedArguments>
where
    S: SearchableArgInfo<ArgData>,
{
    let mut common_args = vec![];
    let mut compilation = false;
    let mut input_arg = None;
    let mut multiple_input = false;
    let mut output_arg = None;
    let mut preprocessor_args = vec![];
    let mut depfile = None;

    for arg in ArgsIter::new(arguments.iter().cloned(), arg_info) {
        let arg = try_or_cannot_cache!(arg, "argument parse");

        match arg.get_data() {
            Some(TooHardFlag) => {
                cannot_cache!(arg.flag_str().expect("Can't be Argument::Raw/UnknownFlag",))
            }
            Some(TooHard(_)) => {
                cannot_cache!(arg.flag_str().expect("Can't be Argument::Raw/UnknownFlag",))
            }
            Some(DoCompilation) => compilation = true,
            Some(Output(p)) => output_arg = Some(p.clone()),
            Some(DepFile(d)) => depfile = Some(d.clone()),
            Some(PreprocessorArgument(_))
            | Some(PreprocessorArgumentPath(_))
            | Some(PassThrough(_)) => {}
            None => match arg {
                Argument::Raw(ref val) => {
                    if input_arg.is_some() {
                        multiple_input = true;
                    }
                    input_arg = Some(val.clone());
                }
                Argument::UnknownFlag(_) => {}
                _ => unreachable!(),
            },
        }
        let args = match arg.get_data() {
            Some(PassThrough(_)) => &mut common_args,
            Some(DepFile(_)) => continue,
            Some(PreprocessorArgument(_)) | Some(PreprocessorArgumentPath(_)) => {
                &mut preprocessor_args
            }
            Some(DoCompilation) | Some(Output(_)) => continue,
            Some(TooHardFlag) => unreachable!(),
            Some(TooHard(_)) => unreachable!(),
            None => match arg {
                Argument::Raw(_) => continue,
                Argument::UnknownFlag(_) => &mut common_args,
                _ => unreachable!(),
            },
        };
        // Normalize attributes such as "-I foo", "-D FOO=bar", as
        // "-Ifoo", "-DFOO=bar", etc. and "-includefoo", "idirafterbar" as
        // "-include foo", "-idirafter bar", etc.
        let norm = match arg.flag_str() {
            Some(s) if s.len() == 2 => NormalizedDisposition::Concatenated,
            _ => NormalizedDisposition::Separated,
        };
        args.extend(arg.normalize(norm).iter_os_strings());
    }

    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    // Can't cache compilations with multiple inputs.
    if multiple_input {
        cannot_cache!("multiple input files");
    }
    let input = match input_arg {
        Some(i) => i.to_owned(),
        // We can't cache compilation without an input.
        None => cannot_cache!("no input file"),
    };
    let language = match Language::from_file_name(Path::new(&input)) {
        Some(l) => l,
        None => cannot_cache!("unknown source language"),
    };

    let output = output_arg
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&input).with_extension("o"));

    let mut outputs = HashMap::new();
    outputs.insert("obj", output);

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        language,
        compilation_flag: "-c".into(),
        depfile,
        outputs,
        dependency_args: vec![],
        preprocessor_args,
        common_args,
        extra_hash_files: vec![],
        msvc_show_includes: false,
        profile_generate: false,
        // FIXME: Implement me.
        color_mode: ColorMode::Auto,
    })
}

fn preprocess<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    _may_dist: bool,
    _rewrite_includes_only: bool,
) -> SFuture<process::Output>
where
    T: CommandCreatorSync,
{
    let mut preprocess = creator.clone().new_command_sync(&executable);
    preprocess
        .arg("-E")
        .arg(&parsed_args.input)
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);

    if log_enabled!(Trace) {
        trace!("preprocess: {:?}", preprocess);
    }

    let preprocess = run_input_output(preprocess, None);

    // Tasking can produce a dep file while preprocessing, BUT if this is
    // enabled the preprocessor output is discarded. Run depfile generation
    // first and preprocessing for hash generation afterwards.
    //
    // From: ASKING  VX-toolset for TriCore User Guide
    // With --preprocess=+make the compiler
    // will generate dependency lines that can be used in a Makefile. The
    // preprocessor output is discarded. The default target name is the basename
    // of the input file, with the extension .o. With the option --make-target
    // you can specify a target name which overrules the default target name.

    if let Some(ref depfile) = parsed_args.depfile {
        let mut generate_depfile = creator.clone().new_command_sync(&executable);
        generate_depfile
            .arg("-Em")
            .arg("-o")
            .arg(depfile)
            .arg(&parsed_args.input)
            .args(&parsed_args.preprocessor_args)
            .args(&parsed_args.common_args)
            .env_clear()
            .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
            .current_dir(cwd);

        if log_enabled!(Trace) {
            trace!("dep file generation: {:?}", generate_depfile);
        }
        let generate_depfile = run_input_output(generate_depfile, None);
        Box::new(generate_depfile.and_then(|_| preprocess))
    } else {
        Box::new(preprocess)
    }
}

fn generate_compile_commands(
    _: &mut dist::PathTransformer,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    _rewrite_includes_only: bool,
) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
    trace!("compile");

    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => return Err(anyhow!("Missing object file output")),
    };

    let mut arguments: Vec<OsString> = vec![
        parsed_args.compilation_flag.clone(),
        parsed_args.input.clone().into(),
        "-o".into(),
        out_file.into(),
    ];
    arguments.extend(parsed_args.preprocessor_args.clone());
    arguments.extend(parsed_args.common_args.clone());
    let command = CompileCommand {
        executable: executable.to_owned(),
        arguments,
        env_vars: env_vars.to_owned(),
        cwd: cwd.to_owned(),
    };

    Ok((command, None, Cacheable::Yes))
}
