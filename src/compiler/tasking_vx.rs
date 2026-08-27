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
        CCompileCommand, Cacheable, ColorMode, CompileCommand, CompilerArguments, Language,
        SingleCompileCommand,
        args::{
            ArgDisposition, ArgInfo, ArgToStringResult, ArgsIter, Argument, FromArg, IntoArg,
            NormalizedDisposition, PathTransformerFn, SearchableArgInfo,
        },
        c::{ArtifactDescriptor, CCompilerImpl, CCompilerKind, ParsedArguments},
    },
    counted_array, dist,
    errors::*,
    mock_command::{CommandCreatorSync, RunCommand},
    util::run_input_output,
};
use async_trait::async_trait;
use futures::TryFutureExt;
use log::Level::Trace;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process,
};

#[derive(Clone, Debug)]
pub struct TaskingVX;

#[async_trait]
impl CCompilerImpl for TaskingVX {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::TaskingVX
    }

    fn plusplus(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        None
    }

    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments> {
        parse_arguments(arguments, cwd, &ARGS[..])
    }

    async fn preprocess<T>(
        &self,
        creator: &T,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        may_dist: bool,
        rewrite_includes_only: bool,
        _preprocessor_cache_mode: bool,
    ) -> Result<process::Output>
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
        .await
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

ArgData! { pub
    DoCompilation,
    NotCompilationFlag,
    NotCompilation(OsString),
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
    take_arg!("--define", OsString, CanBeSeparated(b'='), PreprocessorArgument),
    take_arg!("--dep-file", PathBuf, Concatenated(b'='), DepFile),
    flag!("--dry-run", TooHardFlag),
    take_arg!("--help", OsString, Concatenated(b'='), NotCompilation),
    take_arg!("--include-directory", PathBuf, CanBeSeparated(b'='), PreprocessorArgumentPath),
    take_arg!("--include-file", PathBuf, CanBeSeparated(b'='), PreprocessorArgumentPath),
    take_arg!("--library-directory", OsString, Concatenated(b'='), PassThrough),
    take_arg!("--mil-split", OsString, CanBeSeparated(b'='), TooHard),
    take_arg!("--option-file", OsString, CanBeSeparated(b'='), TooHard),
    take_arg!("--output", PathBuf, CanBeSeparated(b'='), Output),
    take_arg!("--preprocess", OsString, Concatenated(b'='), TooHard),
    take_arg!("--undefine", OsString, CanBeSeparated(b'='), PreprocessorArgument),
    flag!("--version", NotCompilationFlag),
    flag!("-?", NotCompilationFlag),
    take_arg!("-D", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-E", TooHardFlag),
    take_arg!("-H", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-I", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-L", OsString, CanBeSeparated, PassThrough),
    take_arg!("-U", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-V", NotCompilationFlag),
    flag!("-c", DoCompilation),
    take_arg!("-f", OsString, CanBeSeparated, TooHard),
    flag!("-n", TooHardFlag),
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
    cwd: &Path,
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

    let arguments = ExpandOptionFiles::new(cwd, arguments);

    for arg in ArgsIter::new(arguments, arg_info) {
        let arg = try_or_cannot_cache!(arg, "argument parse");

        match arg.get_data() {
            Some(TooHardFlag) | Some(TooHard(_)) => {
                cannot_cache!(arg.flag_str().expect("Can't be Argument::Raw/UnknownFlag",))
            }
            Some(NotCompilationFlag) | Some(NotCompilation(_)) => {
                return CompilerArguments::NotCompilation;
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
            Some(TooHardFlag)
            | Some(TooHard(_))
            | Some(NotCompilationFlag)
            | Some(NotCompilation(_)) => unreachable!(),
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
        Some(i) => i,
        // We can't cache compilation without an input.
        None => cannot_cache!("no input file"),
    };
    let language = match Language::from_file_name(Path::new(&input)) {
        Some(l) => l,
        None => cannot_cache!("unknown source language"),
    };

    // --dep-file without any argument is valid too and uses the source file name
    // with extension .d as depfile name
    depfile = depfile.map(|d| {
        if d.as_os_str().is_empty() {
            Path::new(&input).with_extension("d")
        } else {
            d
        }
    });

    let output = output_arg.unwrap_or_else(|| Path::new(&input).with_extension("o"));

    let mut outputs = HashMap::with_capacity(1);
    outputs.insert(
        "obj",
        ArtifactDescriptor {
            path: output,
            optional: false,
        },
    );

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        double_dash_input: false,
        language,
        compilation_flag: "-c".into(),
        depfile,
        outputs,
        dependency_args: vec![],
        preprocessor_args,
        common_args,
        arch_args: vec![],
        unhashed_args: vec![],
        extra_dist_files: vec![],
        extra_hash_files: vec![],
        msvc_show_includes: false,
        profile_generate: false,
        color_mode: ColorMode::Auto,
        suppress_rewrite_includes_only: false,
        too_hard_for_preprocessor_cache_mode: None,
    })
}

struct ExpandOptionFiles<'a> {
    stack: Vec<OptionFileArgument>,
    cwd: &'a Path,
    previous_may_consume_argument: bool,
}

struct OptionFileArgument {
    value: OsString,
    depth: usize,
}

impl<'a> ExpandOptionFiles<'a> {
    fn new(cwd: &'a Path, arguments: &[OsString]) -> Self {
        Self {
            stack: arguments
                .iter()
                .rev()
                .cloned()
                .map(|value| OptionFileArgument { value, depth: 0 })
                .collect(),
            cwd,
            previous_may_consume_argument: false,
        }
    }

    fn expand(&mut self, value: &OsString, depth: usize) -> Result<()> {
        const MAX_NESTING_DEPTH: usize = 25;
        if depth >= MAX_NESTING_DEPTH {
            bail!("option files cannot be nested more than {MAX_NESTING_DEPTH} levels");
        }

        let values = value
            .to_str()
            .map(|value| value.split(',').collect::<Vec<_>>())
            .unwrap_or_default();
        if values.is_empty() {
            bail!("option file path is not valid UTF-8");
        }

        let mut arguments = Vec::new();
        for value in values {
            let path = self.cwd.join(value);
            let mut contents = String::new();
            File::open(&path)?.read_to_string(&mut contents)?;
            arguments.extend(split_option_file_args(&contents)?);
        }
        self.stack
            .extend(arguments.into_iter().rev().map(|value| OptionFileArgument {
                value,
                depth: depth + 1,
            }));
        Ok(())
    }
}

impl Iterator for ExpandOptionFiles<'_> {
    type Item = OsString;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let arg = self.stack.pop()?;

            if self.previous_may_consume_argument {
                self.previous_may_consume_argument = false;
                return Some(arg.value);
            }

            let Some(arg_str) = arg.value.to_str() else {
                return Some(arg.value);
            };

            if is_option_file_flag(arg_str) {
                let Some(value) = self.stack.pop() else {
                    return Some(if arg_str == "-f" {
                        arg.value
                    } else {
                        "--option-file".into()
                    });
                };
                if let Err(error) = self.expand(&value.value, arg.depth) {
                    debug!(
                        "failed to read TASKING option file `{}`: {error}",
                        self.cwd.join(&value.value).display()
                    );
                    self.stack.push(value);
                    return Some(if arg_str == "-f" {
                        arg.value
                    } else {
                        "--option-file".into()
                    });
                }
                continue;
            }

            let value = if let Some((flag, value)) = arg_str.split_once('=')
                && is_option_file_flag(flag)
            {
                value
            } else if let Some(value) = arg_str.strip_prefix("-f") {
                if value.is_empty() {
                    return Some(arg.value);
                }
                value
            } else {
                self.previous_may_consume_argument = argument_may_consume_value(arg_str);
                return Some(arg.value);
            };
            if let Err(error) = self.expand(&OsString::from(value), arg.depth) {
                debug!("failed to read TASKING option file `{value}`: {error}");
                return Some(if arg_str.starts_with("--") {
                    format!("--option-file={value}").into()
                } else {
                    arg.value
                });
            }
        }
    }
}

fn is_option_file_flag(argument: &str) -> bool {
    argument == "-f" || (argument.len() >= "--op".len() && "--option-file".starts_with(argument))
}

fn argument_may_consume_value(argument: &str) -> bool {
    if !argument.starts_with('-') {
        return false;
    }

    for info in ARGS.iter() {
        match info {
            ArgInfo::Flag(flag, _) if argument == *flag => return false,
            ArgInfo::TakeArg(flag, _, disposition) if argument == *flag => {
                return !matches!(disposition, ArgDisposition::Concatenated(_));
            }
            ArgInfo::TakeArg(flag, _, disposition)
                if argument.len() > flag.len() && argument.starts_with(flag) =>
            {
                let is_concatenated = match disposition {
                    ArgDisposition::Separated => false,
                    ArgDisposition::CanBeConcatenated(None)
                    | ArgDisposition::CanBeSeparated(None)
                    | ArgDisposition::Concatenated(None) => true,
                    ArgDisposition::CanBeConcatenated(Some(delimiter))
                    | ArgDisposition::CanBeSeparated(Some(delimiter))
                    | ArgDisposition::Concatenated(Some(delimiter)) => {
                        argument.as_bytes()[flag.len()] == *delimiter
                    }
                };
                if is_concatenated {
                    return false;
                }
            }
            _ => {}
        }
    }

    true
}

fn split_option_file_args(contents: &str) -> Result<Vec<OsString>> {
    let mut arguments = Vec::new();
    let mut argument = String::new();
    let mut quote = None;
    let contents = contents.chars().collect::<Vec<_>>();
    let mut index = 0;

    while index < contents.len() {
        let character = contents[index];
        if character == '\\' {
            let continuation_length = if contents.get(index + 1) == Some(&'\n') {
                2
            } else if contents.get(index + 1) == Some(&'\r')
                && contents.get(index + 2) == Some(&'\n')
            {
                3
            } else {
                0
            };
            if continuation_length != 0 {
                index += continuation_length;
                if quote.is_none() {
                    while matches!(contents.get(index), Some(' ' | '\t')) {
                        index += 1;
                    }
                }
                continue;
            }
        }

        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            Some(_) => argument.push(character),
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character.is_ascii_whitespace() => {
                if !argument.is_empty() {
                    arguments.push(OsString::from(std::mem::take(&mut argument)));
                }
            }
            None => argument.push(character),
        }
        index += 1;
    }
    if !argument.is_empty() {
        arguments.push(argument.into());
    }
    if quote.is_some() {
        bail!("unterminated quote in option file");
    }
    Ok(arguments)
}

async fn preprocess<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    _may_dist: bool,
    _rewrite_includes_only: bool,
) -> Result<process::Output>
where
    T: CommandCreatorSync,
{
    let mut preprocess = creator.clone().new_command_sync(executable);
    preprocess
        .arg("-E")
        .arg(&parsed_args.input)
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);

    if log_enabled!(Trace) {
        trace!("preprocess: {:?}", preprocess);
    }

    let preprocess = run_input_output(preprocess, None);

    // Tasking can produce a dep file while preprocessing, BUT if this is
    // enabled the preprocessor output is discarded. Run depfile generation
    // first and preprocessing for hash generation afterwards.
    //
    // From: TASKING  VX-toolset for TriCore User Guide
    // With --preprocess=+make the compiler
    // will generate dependency lines that can be used in a Makefile. The
    // preprocessor output is discarded. The default target name is the basename
    // of the input file, with the extension .o. With the option --make-target
    // you can specify a target name which overrules the default target name.

    if let Some(ref depfile) = parsed_args.depfile {
        let mut generate_depfile = creator.clone().new_command_sync(executable);
        generate_depfile
            .arg("-Em")
            .arg("-o")
            .arg(depfile)
            .arg(&parsed_args.input)
            .args(&parsed_args.preprocessor_args)
            .args(&parsed_args.common_args)
            .env_clear()
            .envs(env_vars.to_vec())
            .current_dir(cwd);

        if log_enabled!(Trace) {
            trace!("dep file generation: {:?}", generate_depfile);
        }
        let generate_depfile = run_input_output(generate_depfile, None);
        generate_depfile.and_then(|_| preprocess).await
    } else {
        preprocess.await
    }
}

fn generate_compile_commands(
    _: &mut dist::PathTransformer,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<(
    SingleCompileCommand,
    Option<dist::CompileCommand>,
    Cacheable,
)> {
    trace!("compile");

    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => return Err(anyhow!("Missing object file output")),
    };

    let mut arguments: Vec<OsString> = vec![
        parsed_args.compilation_flag.clone(),
        parsed_args.input.clone().into(),
        "-o".into(),
        out_file.path.as_os_str().into(),
    ];
    arguments.extend_from_slice(&parsed_args.preprocessor_args);
    arguments.extend_from_slice(&parsed_args.unhashed_args);
    arguments.extend_from_slice(&parsed_args.common_args);
    let command = SingleCompileCommand {
        executable: executable.to_owned(),
        arguments,
        env_vars: env_vars.to_owned(),
        cwd: cwd.to_owned(),
    };

    Ok((command, None, Cacheable::Yes))
}

#[cfg(test)]
mod test {
    use super::{
        ARGS, Language, OsString, ParsedArguments, PathBuf, dist, generate_compile_commands,
        parse_arguments, split_option_file_args,
    };
    use crate::compiler::c::ArtifactDescriptor;
    use crate::compiler::*;
    use crate::mock_command::*;
    use crate::server;
    use crate::test::mock_storage::MockStorage;
    use crate::test::utils::*;
    use std::{fs, path::Path};

    fn parse_arguments_(arguments: Vec<String>) -> CompilerArguments<ParsedArguments> {
        let args = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&args, ".".as_ref(), &ARGS[..])
    }

    fn parse_arguments_in(
        arguments: Vec<String>,
        cwd: &Path,
    ) -> CompilerArguments<ParsedArguments> {
        let args = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&args, cwd, &ARGS[..])
    }

    #[test]
    fn test_parse_arguments_simple() {
        let args = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_default_name() {
        let args = stringvec!["-c", "foo.c"];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_extra() {
        let args = stringvec!["-c", "foo.cc", "--unknown=abc", "-o", "foo.o", "-mxyz"];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.cc"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["--unknown=abc", "-mxyz"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_values() {
        let args = stringvec![
            "-c",
            "foo.cxx",
            "--unknown=abc",
            "-I",
            "include",
            "-o",
            "foo.o",
            "-H",
            "file"
        ];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.cxx"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert_eq!(ovec!["-Iinclude", "-Hfile"], preprocessor_args);
        assert_eq!(ovec!["--unknown=abc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_preprocessor_args() {
        let args = stringvec![
            "-c",
            "foo.c",
            "--unknown=abc",
            "--include-directory=bar",
            "--include-file=foo",
            "-o",
            "foo.o"
        ];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert_eq!(
            ovec!["--include-directory", "bar", "--include-file", "foo"],
            preprocessor_args
        );
        assert_eq!(ovec!["--unknown=abc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_option_file() {
        let fixture = TestFixture::new();
        fs::write(
            fixture.tempdir.path().join("options"),
            r#"-I "include directory" -DVALUE=\"Debug\""#,
        )
        .unwrap();

        let ParsedArguments {
            input,
            outputs,
            preprocessor_args,
            ..
        } = match parse_arguments_in(
            stringvec!["-f", "options", "-c", "foo.c", "-o", "foo.o"],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(Path::new("foo.c"), input);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert_eq!(
            ovec!["-Iinclude directory", r#"-DVALUE=\Debug\"#],
            preprocessor_args
        );
    }

    #[test]
    fn test_parse_arguments_long_option_files() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("defines"), "-DFOO=1").unwrap();
        fs::write(fixture.tempdir.path().join("includes"), "-Iinclude").unwrap();

        let argument = "--option-file=defines,includes".to_string();
        let ParsedArguments {
            preprocessor_args, ..
        } = match parse_arguments_in(
            vec![argument, "-c".into(), "foo.c".into()],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(ovec!["-DFOO=1", "-Iinclude"], preprocessor_args);
    }

    #[test]
    fn test_parse_arguments_concatenated_option_file() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let argument = format!("-f{}", fixture.tempdir.path().join("options").display());
        let ParsedArguments {
            preprocessor_args, ..
        } = match parse_arguments_in(
            vec![argument, "-c".into(), "foo.c".into()],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(ovec!["-DFOO=1"], preprocessor_args);
    }

    #[test]
    fn test_parse_arguments_separated_long_option_file() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let ParsedArguments {
            preprocessor_args, ..
        } = match parse_arguments_in(
            stringvec!["--option-file", "options", "-c", "foo.c"],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(ovec!["-DFOO=1"], preprocessor_args);
    }

    #[test]
    fn test_parse_arguments_abbreviated_option_file() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let ParsedArguments {
            preprocessor_args, ..
        } = match parse_arguments_in(
            stringvec!["--op", "options", "-c", "foo.c"],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(ovec!["-DFOO=1"], preprocessor_args);
    }

    #[test]
    fn test_parse_arguments_missing_abbreviated_option_file() {
        let fixture = TestFixture::new();
        assert_eq!(
            CompilerArguments::CannotCache("--option-file", None),
            parse_arguments_in(
                stringvec!["--op", "missing", "-c", "foo.c"],
                fixture.tempdir.path()
            )
        );
    }

    #[test]
    fn test_parse_arguments_missing_option_file() {
        let fixture = TestFixture::new();
        assert_eq!(
            CompilerArguments::CannotCache("-f", None),
            parse_arguments_in(
                stringvec!["-f", "missing", "-c", "foo.c"],
                fixture.tempdir.path()
            )
        );
    }

    #[test]
    fn test_option_file_like_output_is_not_expanded() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let output = format!("-f{}", fixture.tempdir.path().join("options").display());
        let ParsedArguments { outputs, .. } = match parse_arguments_in(
            vec!["-c".into(), "foo.c".into(), "-o".into(), output.clone()],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from(output.clone()),
                    optional: false
                }
            )
        );
    }

    #[test]
    fn test_option_file_like_long_output_is_not_expanded() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let output = format!("-f{}", fixture.tempdir.path().join("options").display());
        let ParsedArguments { outputs, .. } = match parse_arguments_in(
            vec![
                "-c".into(),
                "foo.c".into(),
                "--output".into(),
                output.clone(),
            ],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from(output.clone()),
                    optional: false
                }
            )
        );
    }

    #[test]
    fn test_option_file_like_unknown_option_value_is_not_expanded() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let value = format!("-f{}", fixture.tempdir.path().join("options").display());
        assert_eq!(
            CompilerArguments::CannotCache("-f", None),
            parse_arguments_in(
                vec!["-Wc".into(), value, "-c".into(), "foo.c".into()],
                fixture.tempdir.path()
            )
        );
    }

    #[test]
    fn test_option_file_after_concatenated_option_is_expanded() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-DFOO=1").unwrap();

        let ParsedArguments {
            preprocessor_args, ..
        } = match parse_arguments_in(
            stringvec!["-Iinclude", "-f", "options", "-c", "foo.c"],
            fixture.tempdir.path(),
        ) {
            CompilerArguments::Ok(args) => args,
            other => panic!("Got unexpected parse result: {other:?}"),
        };

        assert_eq!(ovec!["-Iinclude", "-DFOO=1"], preprocessor_args);
    }

    #[test]
    fn test_split_option_file_args() {
        assert_eq!(
            ovec!["-DNAME=a b", r#"-DVALUE=\Debug\"#, "foo.c"],
            split_option_file_args(r#"-DNAME="a b" -DVALUE=\"Debug\" foo.c"#).unwrap()
        );
    }

    #[test]
    fn test_split_option_file_line_continuations() {
        assert_eq!(
            ovec![
                "-DNAME=value",
                "-Iinclude",
                "-DOTHER=foobar",
                "-DQUOTED=foo   bar"
            ],
            split_option_file_args(
                "-DNAME=val\\\r\nue -Iinc\\\nlude -DOTHER=foo\\\n   bar -DQUOTED=\"foo\\\n   bar\""
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_arguments_unterminated_option_file_quote() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), r#"-DNAME="value"#).unwrap();
        assert_eq!(
            CompilerArguments::CannotCache("-f", None),
            parse_arguments_in(
                stringvec!["-f", "options", "-c", "foo.c"],
                fixture.tempdir.path()
            )
        );
    }

    #[test]
    fn test_parse_arguments_option_file_nesting_limit() {
        let fixture = TestFixture::new();
        fs::write(fixture.tempdir.path().join("options"), "-f options").unwrap();
        assert_eq!(
            CompilerArguments::CannotCache("-f", None),
            parse_arguments_in(
                stringvec!["-f", "options", "-c", "foo.c"],
                fixture.tempdir.path()
            )
        );
    }

    #[test]
    fn test_parse_arguments_explicit_dep_target() {
        let args = stringvec![
            "-c",
            "foo.c",
            "--dep-file=depfile",
            "--unknown=abc",
            "-o",
            "foo.o"
        ];
        let ParsedArguments {
            input,
            language,
            depfile,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_eq!(Some("depfile"), depfile.unwrap().to_str());
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["--unknown=abc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_implicit_dep_target() {
        let args = stringvec!["-c", "foo.c", "--dep-file", "--unknown=abc", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments_(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_eq!(Some("foo.d"), depfile.unwrap().to_str());
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.o"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["--unknown=abc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation, parse_arguments_(vec![]));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(
            CompilerArguments::NotCompilation,
            parse_arguments_(stringvec!["-o", "foo"])
        );
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(
            CompilerArguments::CannotCache("multiple input files", None),
            parse_arguments_(stringvec!["-c", "foo.c", "-o", "foo.o", "bar.c"])
        );
    }

    #[test]
    fn test_parse_arguments_link() {
        assert_eq!(
            CompilerArguments::NotCompilation,
            parse_arguments_(stringvec!["--link-only", "foo.o", "-o", "foo.so", "bar.o"])
        );
    }

    #[test]
    fn test_parse_dry_run() {
        assert_eq!(
            CompilerArguments::CannotCache("--dry-run", None),
            parse_arguments_(stringvec!["--dry-run", "-c", "foo.c"])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-n", None),
            parse_arguments_(stringvec!["-n", "-c", "foo.c"])
        );
    }

    #[test]
    fn test_compile_simple() {
        let creator = new_creator();
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            double_dash_input: false,
            language: Language::C,
            compilation_flag: "-c".into(),
            depfile: None,
            outputs: vec![(
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false,
                },
            )]
            .into_iter()
            .collect(),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: vec![],
            arch_args: vec![],
            unhashed_args: vec![],
            extra_dist_files: vec![],
            extra_hash_files: vec![],
            msvc_show_includes: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        };
        let runtime = single_threaded_runtime();
        let storage = MockStorage::new(None, false);
        let storage: std::sync::Arc<MockStorage> = std::sync::Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage, runtime.handle().clone());
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::new();
        let (command, _, cacheable) = generate_compile_commands(
            &mut path_transformer,
            compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
        )
        .unwrap();
        let _ = command.execute(&service, &creator).wait();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn test_cuda_threads_included_in_compile_command() {
        let creator = new_creator();
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.cu".into(),
            double_dash_input: false,
            language: Language::Cuda,
            compilation_flag: "-c".into(),
            depfile: None,
            outputs: vec![(
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false,
                },
            )]
            .into_iter()
            .collect(),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: vec![],
            arch_args: vec![],
            unhashed_args: ovec!["--threads", "2"],
            extra_dist_files: vec![],
            extra_hash_files: vec![],
            msvc_show_includes: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        };
        let runtime = single_threaded_runtime();
        let storage = MockStorage::new(None, false);
        let storage: std::sync::Arc<MockStorage> = std::sync::Arc::new(storage);
        let service = server::SccacheService::mock_with_storage(storage, runtime.handle().clone());
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::new();
        let (command, _, cacheable) = generate_compile_commands(
            &mut path_transformer,
            compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
        )
        .unwrap();
        assert_eq!(
            ovec!["-c", "foo.cu", "-o", "foo.o", "--threads", "2"],
            command.arguments
        );
        let _ = command.execute(&service, &creator).wait();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
