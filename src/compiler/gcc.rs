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

use ::compiler::{
    Cacheable,
    CompilerArguments,
    CompileCommand,
};
use compiler::args::*;
use compiler::c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments};
use log::Level::Trace;
use mock_command::{
    CommandCreatorSync,
    RunCommand,
};
use std::collections::HashMap;
use dist;
use std::io::Read;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process;
use util::{run_input_output, OsStrExt};

use errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct GCC;

impl CCompilerImpl for GCC {
    fn kind(&self) -> CCompilerKind { CCompilerKind::GCC }
    fn parse_arguments(&self,
                       arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        parse_arguments(arguments, cwd, &ARGS[..])
    }

    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     may_dist: bool)
                     -> SFuture<process::Output> where T: CommandCreatorSync
    {
        preprocess(creator, executable, parsed_args, cwd, env_vars, may_dist)
    }

    fn generate_compile_commands(&self,
                                path_transformer: &mut dist::PathTransformer,
                                executable: &Path,
                                parsed_args: &ParsedArguments,
                                cwd: &Path,
                                env_vars: &[(OsString, OsString)])
                                -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>
    {
        generate_compile_commands(path_transformer, executable, parsed_args, cwd, env_vars)
    }
}

ArgData!{ pub
    TooHardFlag,
    TooHard(OsString),
    PassThrough(OsString),
    PassThroughPath(PathBuf),
    PreprocessorArgumentFlag,
    PreprocessorArgument(OsString),
    PreprocessorArgumentPath(PathBuf),
    DoCompilation,
    Output(PathBuf),
    NeedDepTarget,
    // Though you might think this should be a path as it's a Makefile target,
    // it's not treated as a path by the compiler - it's just written wholesale
    // (including any funny make syntax) into the dep file.
    DepTarget(OsString),
    Language(OsString),
    SplitDwarf,
    ProfileGenerate,
    TestCoverage,
    Coverage,
}

use self::ArgData::*;

// Mostly taken from https://github.com/ccache/ccache/blob/master/src/compopt.c#L32-L84
counted_array!(pub static ARGS: [ArgInfo<ArgData>; _] = [
    flag!("-", TooHardFlag),
    flag!("--coverage", Coverage),
    take_arg!("--param", OsString, Separated, PassThrough),
    flag!("--save-temps", TooHardFlag),
    take_arg!("--serialize-diagnostics", PathBuf, Separated, PassThroughPath),
    take_arg!("--sysroot", PathBuf, Separated, PassThroughPath),
    take_arg!("-A", OsString, Separated, PassThrough),
    take_arg!("-B", PathBuf, CanBeSeparated, PassThroughPath),
    take_arg!("-D", OsString, CanBeSeparated, PreprocessorArgument),
    flag!("-E", TooHardFlag),
    take_arg!("-F", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-G", OsString, Separated, PassThrough),
    take_arg!("-I", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-L", OsString, Separated, PassThrough),
    flag!("-M", TooHardFlag),
    flag!("-MD", NeedDepTarget),
    take_arg!("-MF", PathBuf, Separated, PreprocessorArgumentPath),
    flag!("-MM", TooHardFlag),
    flag!("-MMD", NeedDepTarget),
    flag!("-MP", NeedDepTarget),
    take_arg!("-MQ", OsString, Separated, PreprocessorArgument),
    take_arg!("-MT", OsString, Separated, DepTarget),
    flag!("-P", TooHardFlag),
    take_arg!("-U", OsString, CanBeSeparated, PreprocessorArgument),
    take_arg!("-V", OsString, Separated, PassThrough),
    take_arg!("-Xassembler", OsString, Separated, PassThrough),
    take_arg!("-Xlinker", OsString, Separated, PassThrough),
    take_arg!("-Xpreprocessor", OsString, Separated, PreprocessorArgument),
    take_arg!("-arch", OsString, Separated, PassThrough),
    take_arg!("-aux-info", OsString, Separated, PassThrough),
    take_arg!("-b", OsString, Separated, PassThrough),
    flag!("-c", DoCompilation),
    take_arg!("-dependency-file", PathBuf, Separated, PreprocessorArgumentPath),
    flag!("-fno-working-directory", PreprocessorArgumentFlag),
    flag!("-fplugin=libcc1plugin", TooHardFlag),
    flag!("-fprofile-arcs", ProfileGenerate),
    flag!("-fprofile-generate", ProfileGenerate),
    flag!("-fprofile-use", TooHardFlag),
    flag!("-frepo", TooHardFlag),
    flag!("-fsyntax-only", TooHardFlag),
    flag!("-ftest-coverage", TestCoverage),
    flag!("-fworking-directory", PreprocessorArgumentFlag),
    flag!("-gsplit-dwarf", SplitDwarf),
    take_arg!("-idirafter", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-iframework", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-imacros", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-imultilib", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-include", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-install_name", OsString, Separated, PassThrough),
    take_arg!("-iprefix", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-iquote", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-isysroot", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-isystem", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-iwithprefix", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-iwithprefixbefore", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    flag!("-nostdinc", PreprocessorArgumentFlag),
    flag!("-nostdinc++", PreprocessorArgumentFlag),
    take_arg!("-o", PathBuf, Separated, Output),
    flag!("-remap", PreprocessorArgumentFlag),
    flag!("-save-temps", TooHardFlag),
    take_arg!("-stdlib", OsString, Concatenated('='), PreprocessorArgument),
    flag!("-trigraphs", PreprocessorArgumentFlag),
    take_arg!("-u", OsString, CanBeSeparated, PassThrough),
    take_arg!("-x", OsString, CanBeSeparated, Language),
    take_arg!("@", OsString, Concatenated, TooHard),
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
pub fn parse_arguments<S>(
    arguments: &[OsString],
    cwd: &Path,
    arg_info: S,
) -> CompilerArguments<ParsedArguments>
where
    S: SearchableArgInfo<ArgData>,
{
    let mut output_arg = None;
    let mut input_arg = None;
    let mut dep_target = None;
    let mut common_args = vec!();
    let mut preprocessor_args = vec!();
    let mut compilation = false;
    let mut multiple_input = false;
    let mut split_dwarf = false;
    let mut need_explicit_dep_target = false;
    let mut language = None;
    let mut profile_generate = false;
    let mut outputs_gcno = false;

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let it = ExpandIncludeFile::new(cwd, arguments);

    for arg in ArgsIter::new(it, arg_info) {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        // Check if the value part of this argument begins with '@'. If so, we either
        // failed to expand it, or it was a concatenated argument - either way, bail.
        // We refuse to cache concatenated arguments (like "-include@foo") because they're a
        // mess. See https://github.com/mozilla/sccache/issues/150#issuecomment-318586953
        match arg {
            Argument::WithValue(_, ref v, ArgDisposition::Separated) |
            Argument::WithValue(_, ref v, ArgDisposition::CanBeConcatenated(_)) |
            Argument::WithValue(_, ref v, ArgDisposition::CanBeSeparated(_)) => {
                if v.clone().into_arg_os_string().starts_with("@") {
                    cannot_cache!("@");
                }
            },
            // Empirically, concatenated arguments appear not to interpret '@' as
            // an include directive, so just continue.
            Argument::WithValue(_, _, ArgDisposition::Concatenated(_)) |
            Argument::Raw(_) |
            Argument::UnknownFlag(_) |
            Argument::Flag(_, _) => {},
        }

        match arg.get_data() {
            Some(TooHardFlag) |
            Some(TooHard(_)) => {
                cannot_cache!(arg.flag_str().expect(
                    "Can't be Argument::Raw/UnknownFlag",
                ))
            }
            Some(SplitDwarf) => split_dwarf = true,
            Some(DoCompilation) => compilation = true,
            Some(ProfileGenerate) => profile_generate = true,
            Some(TestCoverage) => outputs_gcno = true,
            Some(Coverage) => {
                outputs_gcno = true;
                profile_generate = true;
            }
            Some(Output(p)) => output_arg = Some(p.clone()),
            Some(NeedDepTarget) => need_explicit_dep_target = true,
            Some(DepTarget(s)) => dep_target = Some(s.clone()),
            Some(PreprocessorArgumentFlag) |
            Some(PreprocessorArgument(_)) |
            Some(PreprocessorArgumentPath(_)) |
            Some(PassThrough(_)) |
            Some(PassThroughPath(_)) => {}
            Some(Language(lang)) => {
                language = match lang.to_string_lossy().as_ref() {
                    "c" => Some(Language::C),
                    "c++" => Some(Language::Cxx),
                    "objective-c" => Some(Language::ObjectiveC),
                    "objective-c++" => Some(Language::ObjectiveCxx),
                    _ => cannot_cache!("-x"),
                };
            }
            None => {
                match arg {
                    Argument::Raw(ref val) => {
                        if input_arg.is_some() {
                            multiple_input = true;
                        }
                        input_arg = Some(val.clone());
                    }
                    Argument::UnknownFlag(_) => {}
                    _ => unreachable!(),
                }
            }
        }
        let args = match arg.get_data() {
            Some(SplitDwarf) |
            Some(ProfileGenerate) |
            Some(TestCoverage) |
            Some(Coverage) |
            Some(PassThrough(_)) |
            Some(PassThroughPath(_)) => Some(&mut common_args),
            Some(PreprocessorArgumentFlag) |
            Some(PreprocessorArgument(_)) |
            Some(PreprocessorArgumentPath(_)) |
            Some(NeedDepTarget) => Some(&mut preprocessor_args),
            Some(DoCompilation) |
            Some(Language(_)) |
            Some(Output(_)) |
            Some(DepTarget(_)) => None,
            Some(TooHardFlag) |
            Some(TooHard(_)) => unreachable!(),
            None => {
                match arg {
                    Argument::Raw(_) => None,
                    Argument::UnknownFlag(_) => Some(&mut common_args),
                    _ => unreachable!(),
                }
            }
        };
        if let Some(args) = args {
            // Normalize attributes such as "-I foo", "-D FOO=bar", as
            // "-Ifoo", "-DFOO=bar", etc. and "-includefoo", "idirafterbar" as
            // "-include foo", "-idirafter bar", etc.
            let norm = match arg.flag_str() {
                Some(s) if s.len() == 2 => NormalizedDisposition::Concatenated,
                _ => NormalizedDisposition::Separated,
            };
            args.extend(arg.normalize(norm).iter_os_strings());
        };
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
    if language == None {
        language = Language::from_file_name(Path::new(&input));
    }
    let language = match language {
        Some(l) => l,
        None => cannot_cache!("unknown source language"),
    };
    let mut outputs = HashMap::new();
    let output = match output_arg {
        // We can't cache compilation that doesn't go to a file
        None => Path::new(&input).with_extension("o"),
        Some(o) =>  PathBuf::from(o),
    };
    if split_dwarf {
        let dwo = output.with_extension("dwo");
        outputs.insert("dwo", dwo);
    }
    if outputs_gcno {
        let gcno = output.with_extension("gcno");
        outputs.insert("gcno", gcno);
        profile_generate = true;
    }
    if need_explicit_dep_target {
        preprocessor_args.push("-MT".into());
        preprocessor_args.push(dep_target.unwrap_or_else(|| output.clone().into_os_string()));
    }
    outputs.insert("obj", output);

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        language: language,
        depfile: None,
        outputs: outputs,
        preprocessor_args: preprocessor_args,
        common_args: common_args,
        msvc_show_includes: false,
        profile_generate,
    })
}

pub fn preprocess<T>(creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     may_dist: bool)
                     -> SFuture<process::Output>
    where T: CommandCreatorSync
{
    trace!("preprocess");
    let language = match parsed_args.language {
        Language::C => "c",
        Language::Cxx => "c++",
        Language::ObjectiveC => "objective-c",
        Language::ObjectiveCxx => "objective-c++",
    };
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-x").arg(language)
        .arg("-E");
    // When performing distributed compilation, line number info is important for error
    // reporting and to not cause spurious compilation failure (e.g. no exceptions build
    // fails due to exceptions transitively included in the stdlib).
    // With -fprofile-generate line number information is important, so don't use -P.
    if !may_dist && !parsed_args.profile_generate {
        cmd.arg("-P");
    }
    cmd.arg(&parsed_args.input)
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);

    if log_enabled!(Trace) {
        trace!("preprocess: {:?}", cmd);
    }
    run_input_output(cmd, None)
}

pub fn generate_compile_commands(path_transformer: &mut dist::PathTransformer,
                                executable: &Path,
                                parsed_args: &ParsedArguments,
                                cwd: &Path,
                                env_vars: &[(OsString, OsString)])
                                -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>
{
    #[cfg(not(feature = "dist-client"))]
    let _ = path_transformer;

    trace!("compile");

    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => {
            return Err("Missing object file output".into())
        }
    };

    // Pass the language explicitly as we might have gotten it from the
    // command line.
    let language = match parsed_args.language {
        Language::C => "c",
        Language::Cxx => "c++",
        Language::ObjectiveC => "objective-c",
        Language::ObjectiveCxx => "objective-c++",
    };
    let mut arguments: Vec<OsString> = vec![
        "-x".into(), language.into(),
        "-c".into(),
        parsed_args.input.clone().into(),
        "-o".into(), out_file.into(),
    ];
    arguments.extend(parsed_args.preprocessor_args.clone());
    arguments.extend(parsed_args.common_args.clone());
    let command = CompileCommand {
        executable: executable.to_owned(),
        arguments: arguments,
        env_vars: env_vars.to_owned(),
        cwd: cwd.to_owned(),
    };

    #[cfg(not(feature = "dist-client"))]
    let dist_command = None;
    #[cfg(feature = "dist-client")]
    let dist_command = (|| {
        // https://gcc.gnu.org/onlinedocs/gcc-4.9.0/gcc/Overall-Options.html
        let language = match parsed_args.language {
            Language::C => "cpp-output",
            Language::Cxx => "c++-cpp-output",
            Language::ObjectiveC => "objective-c-cpp-output",
            Language::ObjectiveCxx => "objective-c++-cpp-output",
        };
        let mut arguments: Vec<String> = vec![
            "-x".into(), language.into(),
            "-c".into(),
            path_transformer.to_dist(&parsed_args.input)?,
            "-o".into(), path_transformer.to_dist(out_file)?,
        ];
        // We could do preprocessor_args here, but skip for consistency with msvc
        arguments.extend(dist::osstrings_to_strings(&parsed_args.common_args)?);
        Some(dist::CompileCommand {
            executable: path_transformer.to_dist(&executable)?,
            arguments: arguments,
            env_vars: dist::osstring_tuples_to_strings(env_vars)?,
            cwd: path_transformer.to_dist_assert_abs(cwd)?,
        })
    })();

    Ok((command, dist_command, Cacheable::Yes))
}

pub struct ExpandIncludeFile<'a> {
    cwd: &'a Path,
    stack: Vec<OsString>,
}

impl<'a> ExpandIncludeFile<'a> {
    pub fn new(cwd: &'a Path, args: &[OsString]) -> Self {
        ExpandIncludeFile {
            stack: args.iter().rev().map(|a| a.to_owned()).collect(),
            cwd: cwd,
        }
    }
}

impl<'a> Iterator for ExpandIncludeFile<'a> {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        loop {
            let arg = match self.stack.pop() {
                Some(arg) => arg,
                None => return None,
            };
            let file = match arg.split_prefix("@") {
                Some(arg) => self.cwd.join(&arg),
                None => return Some(arg),
            };

            // According to gcc [1], @file means:
            //
            //     Read command-line options from file. The options read are
            //     inserted in place of the original @file option. If file does
            //     not exist, or cannot be read, then the option will be
            //     treated literally, and not removed.
            //
            //     Options in file are separated by whitespace. A
            //     whitespace character may be included in an option by
            //     surrounding the entire option in either single or double
            //     quotes. Any character (including a backslash) may be
            //     included by prefixing the character to be included with
            //     a backslash. The file may itself contain additional
            //     @file options; any such options will be processed
            //     recursively.
            //
            // So here we interpret any I/O errors as "just return this
            // argument". Currently we don't implement handling of arguments
            // with quotes, so if those are encountered we just pass the option
            // through literally anyway.
            //
            // At this time we interpret all `@` arguments above as non
            // cacheable, so if we fail to interpret this we'll just call the
            // compiler anyway.
            //
            // [1]: https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html#Overall-Options
            let mut contents = String::new();
            let res = File::open(&file).and_then(|mut f| {
                f.read_to_string(&mut contents)
            });
            if let Err(e) = res {
                debug!("failed to read @-file `{}`: {}", file.display(), e);
                return Some(arg)
            }
            if contents.contains('"') || contents.contains('\'') {
                return Some(arg)
            }
            let new_args = contents.split_whitespace().collect::<Vec<_>>();
            self.stack.extend(new_args.iter().rev().map(|s| s.into()));
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;

    use super::*;
    use compiler::*;
    use futures::Future;
    use mock_command::*;
    use test::utils::*;
    use tempdir::TempDir;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments> {
        let args = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&args, ".".as_ref(), &ARGS[..])
    }

    #[test]
    fn test_parse_arguments_simple() {
        let args = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
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
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_split_dwarf() {
        let args = stringvec!["-gsplit-dwarf", "-c", "foo.cpp", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cpp"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(outputs,
                             ("obj", PathBuf::from("foo.o")),
                             ("dwo", PathBuf::from("foo.dwo")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(2, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-gsplit-dwarf"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_coverage_outputs_gcno() {
        let args = stringvec!["--coverage", "-c", "foo.cpp", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            profile_generate,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cpp"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(outputs,
                             ("obj", PathBuf::from("foo.o")),
                             ("gcno", PathBuf::from("foo.gcno")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(2, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["--coverage"], common_args);
        assert!(!msvc_show_includes);
        assert!(profile_generate);
    }

    #[test]
    fn test_parse_arguments_test_coverage_outputs_gcno() {
        let args = stringvec!["-ftest-coverage", "-c", "foo.cpp", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            profile_generate,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cpp"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(outputs,
                             ("obj", PathBuf::from("foo.o")),
                             ("gcno", PathBuf::from("foo.gcno")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(2, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-ftest-coverage"], common_args);
        assert!(!msvc_show_includes);
        assert!(profile_generate);
    }

    #[test]
    fn test_parse_arguments_profile_generate() {
        let args = stringvec!["-fprofile-generate", "-c", "foo.cpp", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            profile_generate,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cpp"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(outputs,
                             ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-fprofile-generate"], common_args);
        assert!(!msvc_show_includes);
        assert!(profile_generate);
    }

    #[test]
    fn test_parse_arguments_extra() {
        let args = stringvec!["-c", "foo.cc", "-fabc", "-o", "foo.o", "-mxyz"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cc"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-fabc", "-mxyz"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_values() {
        let args = stringvec!["-c", "foo.cxx", "-fabc", "-I", "include", "-o", "foo.o", "-include", "file"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cxx"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert_eq!(ovec!["-Iinclude", "-include", "file"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_preprocessor_args() {
        let args = stringvec!["-c", "foo.c", "-fabc", "-MF", "file", "-o", "foo.o", "-MQ", "abc"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert_eq!(ovec!["-MF", "file", "-MQ", "abc"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_explicit_dep_target() {
        let args = stringvec!["-c", "foo.c", "-MT", "depfile", "-fabc", "-MF", "file", "-o", "foo.o"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert_eq!(ovec!["-MF", "file"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_explicit_dep_target_needed() {
        let args = stringvec!["-c", "foo.c", "-MT", "depfile", "-fabc", "-MF", "file", "-o", "foo.o", "-MD"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert_eq!(ovec!["-MF", "file", "-MD", "-MT", "depfile"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_dep_target_needed() {
        let args = stringvec!["-c", "foo.c", "-fabc", "-MF", "file", "-o", "foo.o", "-MD"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert_eq!(ovec!["-MF", "file", "-MD", "-MT", "foo.o"], preprocessor_args);
        assert_eq!(ovec!["-fabc"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation,
                   _parse_arguments(&vec!()));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(CompilerArguments::NotCompilation,
                   _parse_arguments(&stringvec!["-o", "foo"]));
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(CompilerArguments::CannotCache("multiple input files", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_link() {
        assert_eq!(CompilerArguments::NotCompilation,
                   _parse_arguments(&stringvec!["-shared", "foo.o", "-o", "foo.so", "bar.o"]));
    }

    #[test]
    fn test_parse_arguments_pgo() {
        assert_eq!(CompilerArguments::CannotCache("-fprofile-use", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-fprofile-use", "-o", "foo.o"]));
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache("@", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "@foo", "-o", "foo.o"]));
        assert_eq!(CompilerArguments::CannotCache("@", None),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-o", "@foo"]));
    }

    #[test]
    fn at_signs() {
        let td = TempDir::new("sccache").unwrap();
        File::create(td.path().join("foo")).unwrap().write_all(b"\
            -c foo.c -o foo.o\
        ").unwrap();
        let arg = format!("@{}", td.path().join("foo").display());
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match _parse_arguments(&[arg]) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_compile_simple() {
        let creator = new_creator();
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            language: Language::C,
            depfile: None,
            outputs: vec![("obj", "foo.o".into())].into_iter().collect(),
            preprocessor_args: vec!(),
            common_args: vec!(),
            msvc_show_includes: false,
            profile_generate: false,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::new();
        let (command, _, cacheable) = generate_compile_commands(&mut path_transformer,
                                                                &compiler,
                                                                &parsed_args,
                                                                f.tempdir.path(),
                                                                &[]).unwrap();
        let _ = command.execute(&creator).wait();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
