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
    fn plusplus(&self) -> bool {
        false
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
        _rewrite_includes_only: bool,
    ) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
        generate_compile_commands(path_transformer, executable, parsed_args, cwd, env_vars)
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
    take_arg!("--define", OsString, Concatenated('='), PreprocessorArgument),
    take_arg!("--dep-file", PathBuf, Concatenated('='), DepFile),
    flag!("--dry-run", TooHardFlag),
    take_arg!("--help", OsString, Concatenated('='), NotCompilation),
    take_arg!("--include-directory", PathBuf, Concatenated('='), PreprocessorArgumentPath),
    take_arg!("--include-file", PathBuf, Concatenated('='), PreprocessorArgumentPath),
    take_arg!("--library-directory", OsString, Concatenated('='), PassThrough),
    take_arg!("--mil-split", OsString, Concatenated('='), TooHard),
    take_arg!("--option-file", OsString, Concatenated('='), TooHard),
    take_arg!("--output", PathBuf, Concatenated('='), Output),
    take_arg!("--preprocess", OsString, Concatenated('='), TooHard),
    take_arg!("--undefine", OsString, Separated, PreprocessorArgument), // ok
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
    take_arg!("-f", OsString, Separated, TooHard),
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
            Some(TooHardFlag) | Some(TooHard(_)) => {
                cannot_cache!(arg.flag_str().expect("Can't be Argument::Raw/UnknownFlag",))
            }
            Some(NotCompilationFlag) | Some(NotCompilation(_)) => {
                return CompilerArguments::NotCompilation
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
        Some(i) => i.to_owned(),
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
    // From: TASKING  VX-toolset for TriCore User Guide
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

#[cfg(test)]
mod test {
    use super::{
        dist, generate_compile_commands, parse_arguments, Language, OsString, ParsedArguments,
        PathBuf, ARGS,
    };
    use crate::compiler::*;
    use crate::mock_command::*;
    use crate::test::utils::*;
    use futures::Future;

    fn parse_arguments_(arguments: Vec<String>) -> CompilerArguments<ParsedArguments> {
        let args = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&args, ".".as_ref(), &ARGS[..])
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_extra() {
        let args = stringvec!["-c", "foo.cc", "-fabc", "-o", "foo.o", "-mxyz"];
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-fabc", "-mxyz"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_values() {
        let args =
            stringvec!["-c", "foo.cxx", "-fabc", "-I", "include", "-o", "foo.o", "-H", "file"];
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        assert_eq!(ovec!["-Iinclude", "-Hfile"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_preprocessor_args() {
        let args = stringvec![
            "-c",
            "foo.c",
            "-fabc",
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        assert_eq!(
            ovec!["--include-directory=bar", "--include-file=foo"],
            preprocessor_args
        );
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_explicit_dep_target() {
        let args = stringvec!["-c", "foo.c", "--dep-file=depfile", "-fabc", "-o", "foo.o"];
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_implicit_dep_target() {
        let args = stringvec!["-c", "foo.c", "--dep-file", "-fabc", "-o", "foo.o"];
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
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-fabc"], common_args);
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
            language: Language::C,
            compilation_flag: "-c".into(),
            depfile: None,
            outputs: vec![("obj", "foo.o".into())].into_iter().collect(),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: vec![],
            extra_hash_files: vec![],
            msvc_show_includes: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::default();
        let (command, _, cacheable) = generate_compile_commands(
            &mut path_transformer,
            &compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
        )
        .unwrap();
        let _ = command.execute(&creator).wait();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
