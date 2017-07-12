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
};
use compiler::c::{CCompilerImpl, CCompilerKind, ParsedArguments};
use log::LogLevel::Trace;
use futures::future::Future;
use futures_cpupool::CpuPool;
use mock_command::{
    CommandCreatorSync,
    RunCommand,
};
use std::collections::HashMap;
use std::io::Read;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process;
use tempdir::TempDir;
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
        parse_arguments(arguments, cwd, argument_takes_value)
    }

    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     pool: &CpuPool)
                     -> SFuture<process::Output> where T: CommandCreatorSync
    {
        preprocess(creator, executable, parsed_args, cwd, env_vars, pool)
    }

    fn compile<T>(&self,
                  creator: &T,
                  executable: &Path,
                  preprocessor_result: process::Output,
                  parsed_args: &ParsedArguments,
                  cwd: &Path,
                  env_vars: &[(OsString, OsString)],
                  pool: &CpuPool)
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync
    {
        compile(creator, executable, preprocessor_result, parsed_args, cwd, env_vars, pool, None)
    }
}

/// Arguments that take a value. Shared with clang.
pub const ARGS_WITH_VALUE: &'static [&'static str] = &[
    "--param", "-A", "-D", "-F", "-G", "-I", "-L",
    "-U", "-V", "-Xassembler", "-Xlinker",
    "-Xpreprocessor", "-aux-info", "-b", "-idirafter",
    "-iframework", "-imacros", "-imultilib", "-include",
    "-install_name", "-iprefix", "-iquote", "-isysroot",
    "-isystem", "-iwithprefix", "-iwithprefixbefore",
    "-u", "-x", "-arch", "--sysroot"
    ];


/// Return true if `arg` is a GCC commandline argument that takes a value.
pub fn argument_takes_value(arg: &str) -> bool {
    ARGS_WITH_VALUE.contains(&arg)
}

/// Parse `arguments`, determining whether it is supported.
///
/// `argument_takes_value` should return `true` when called with
/// a compiler option that takes a value.
///
/// If any of the entries in `arguments` result in a compilation that
/// cannot be cached, return `CompilerArguments::CannotCache`.
/// If the commandline described by `arguments` is not compilation,
/// return `CompilerArguments::NotCompilation`.
/// Otherwise, return `CompilerArguments::Ok(ParsedArguments)`, with
/// the `ParsedArguments` struct containing information parsed from
/// `arguments`.
pub fn parse_arguments<F: Fn(&str) -> bool>(arguments: &[OsString],
                                            cwd: &Path,
                                            argument_takes_value: F)
                                            -> CompilerArguments<ParsedArguments> {
    _parse_arguments(arguments, cwd, &argument_takes_value)
}

fn _parse_arguments(arguments: &[OsString],
                    cwd: &Path,
                    argument_takes_value: &Fn(&str) -> bool) -> CompilerArguments<ParsedArguments> {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut dep_target = None;
    let mut common_args = vec!();
    let mut preprocessor_args = vec!();
    let mut compilation = false;
    let mut multiple_input = false;
    let mut split_dwarf = false;
    let mut need_explicit_dep_target = false;

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let mut it = ExpandIncludeFile {
        stack: arguments.iter().rev().map(|a| a.to_owned()).collect(),
        cwd: cwd,
    };
    while let Some(arg) = it.next() {
        if let Some(s) = arg.to_str() {
            let mut handled = true;
            match s {
                "-c" => compilation = true,
                "-o" => output_arg = it.next(),
                "-gsplit-dwarf" => {
                    split_dwarf = true;
                    common_args.push(arg.clone());
                }
                // Arguments that take a value.
                // -MF and -MQ are in this set but are handled separately
                // because they are also preprocessor options.
                a if argument_takes_value(a) => {
                    common_args.push(arg.clone());
                    if let Some(arg_val) = it.next() {
                        common_args.push(arg_val);
                    }
                },
                "-MF" |
                "-MQ" => {
                    preprocessor_args.push(arg.clone());
                    if let Some(arg_val) = it.next() {
                        preprocessor_args.push(arg_val);
                    }
                }
                "-MT" => dep_target = it.next(),
                // Can't cache Clang modules.
                "-fcxx-modules" => return CompilerArguments::CannotCache("clang modules"),
                "-fmodules" => return CompilerArguments::CannotCache("clang modules"),
                // Can't cache -fsyntax-only, it doesn't produce any output.
                "-fsyntax-only" => return CompilerArguments::CannotCache("-fsyntax-only"),
                // Can't cache PGO profiled output.
                "-fprofile-use" => return CompilerArguments::CannotCache("pgo"),
                // We already expanded `@` files we could through
                // `ExpandIncludeFile` above, so if one of those arguments now
                // makes it this far we won't understand it.
                v if v.starts_with('@') => return CompilerArguments::CannotCache("@file"),
                "-M" |
                "-MM" |
                "-MP" |
                "-MD" |
                "-MMD" => {
                    // If one of the above options is on the command line, we'll
                    // need -MT on the preprocessor command line, whether it's
                    // been passed already or not
                    need_explicit_dep_target = true;
                    preprocessor_args.push(arg.clone());
                }
                _ => handled = false,
            }
            if handled {
                continue
            }
        }

        if arg.starts_with("-") && arg.len() > 1 {
            common_args.push(arg);
        } else {
            // Anything else is an input file.
            if input_arg.is_some() || arg.as_os_str() == "-" {
                multiple_input = true;
            }
            input_arg = Some(arg);
        }
    }

    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    // Can't cache compilations with multiple inputs
    // or compilation from stdin.
    if multiple_input {
        return CompilerArguments::CannotCache("multiple input files");
    }
    let (input, extension) = match input_arg {
        Some(i) => {
            // When compiling from the preprocessed output given as stdin, we need
            // to explicitly pass its file type.
            match Path::new(&i).extension().and_then(|e| e.to_str()) {
                Some(e @ "c") | Some(e @ "cc") | Some(e @ "cpp") | Some(e @ "cxx") => (i.to_owned(), e.to_owned()),
                e => {
                    trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
                    return CompilerArguments::CannotCache("unknown source extension");
                }
            }
        }
        // We can't cache compilation without an input.
        None => return CompilerArguments::CannotCache("no input file"),
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
    if need_explicit_dep_target {
        preprocessor_args.push("-MT".into());
        preprocessor_args.push(dep_target.unwrap_or(output.clone().into_os_string()));
    }
    outputs.insert("obj", output);

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        extension: extension,
        depfile: None,
        outputs: outputs,
        preprocessor_args: preprocessor_args,
        common_args: common_args,
        msvc_show_includes: false,
    })
}

pub fn preprocess<T>(creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     _pool: &CpuPool)
                     -> SFuture<process::Output>
    where T: CommandCreatorSync
{
    trace!("preprocess");
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-E")
        .arg(&parsed_args.input)
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

pub fn compile<T>(creator: &T,
              executable: &Path,
              preprocessor_result: process::Output,
              parsed_args: &ParsedArguments,
              cwd: &Path,
              env_vars: &[(OsString, OsString)],
              pool: &CpuPool,
              pre: Option<SFuture<(Option<Vec<u8>>, Vec<String>, Option<TempDir>)>>)
              -> SFuture<(Cacheable, process::Output)>
    where T: CommandCreatorSync
{
    trace!("compile");

    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => {
            return f_err("Missing object file output")
        }
    };

    let mut attempt = creator.clone().new_command_sync(executable);
    attempt.arg("-c")
        .arg("-o").arg(&out_file)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);

    // When reading from stdin the language argument is needed
    let extension = parsed_args.extension.clone();
    let pre = pre.unwrap_or(Box::new(pool.spawn_fn(move || {
        let extension = match extension.as_ref() {
            "c" => "cpp-output".to_owned(),
            "cc" | "cpp" | "cxx" => "c++-cpp-output".to_owned(),
            e => {
                error!("gcc::compile: Got an unexpected file extension {}", e);
                return Err("Unexpected file extension".into())
            }
        };
        let args = vec!("-x".to_owned(), extension, "-".to_owned());
        Ok((Some(preprocessor_result.stdout), args, None))
    })));

    let output = pre.and_then(move |(stdin, args, tempdir)| {
            attempt.args(&args);
            run_input_output(attempt, stdin).map(|output| {
                    drop(tempdir);
                    (Cacheable::Yes, output)
                })
        });

    // gcc/clang may fail when compiling preprocessor output with -Werror,
    // so retry compilation from the original input file if it fails and
    // -Werror is in the commandline.
    //
    // Otherwise if -Werror is missing we can just use the first instance.
    if !parsed_args.common_args.iter().any(|a| a.starts_with("-Werror")) {
        return Box::new(output);
    }

    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-c")
        .arg(&parsed_args.input)
        .arg("-o").arg(&out_file)
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);
    Box::new(output.or_else(move |err| -> SFuture<_> {
        match err {
            Error(ErrorKind::ProcessError(_), _) => {
                Box::new(run_input_output(cmd, None).map(|output| {
                    (Cacheable::Yes, output)
                }))
            }
            e @ _ => f_err(e),
        }
    }))
}

struct ExpandIncludeFile<'a> {
    cwd: &'a Path,
    stack: Vec<OsString>,
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
    use ::compiler::*;
    use tempdir::TempDir;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments> {
        let args = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&args, ".".as_ref(), argument_takes_value)
    }

    #[test]
    fn test_parse_arguments_simple() {
        let args = stringvec!["-c", "foo.c", "-o", "foo.o"];
        let ParsedArguments {
            input,
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cpp"), input.to_str());
        assert_eq!("cpp", extension);
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
    fn test_parse_arguments_extra() {
        let args = stringvec!["-c", "foo.cc", "-fabc", "-o", "foo.o", "-mxyz"];
        let ParsedArguments {
            input,
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cc"), input.to_str());
        assert_eq!("cc", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.cxx"), input.to_str());
        assert_eq!("cxx", extension);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(ovec!["-fabc", "-I", "include", "-include", "file"], common_args);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_preprocessor_args() {
        let args = stringvec!["-c", "foo.c", "-fabc", "-MF", "file", "-o", "foo.o", "-MQ", "abc"];
        let ParsedArguments {
            input,
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
        assert_eq!(CompilerArguments::CannotCache("multiple input files"),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_clangmodules() {
        assert_eq!(CompilerArguments::CannotCache("clang modules"),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-fcxx-modules", "-o", "foo.o"]));
        assert_eq!(CompilerArguments::CannotCache("clang modules"),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-fmodules", "-o", "foo.o"]));
    }

    #[test]
    fn test_parse_arguments_pgo() {
        assert_eq!(CompilerArguments::CannotCache("pgo"),
                   _parse_arguments(&stringvec!["-c", "foo.c", "-fprofile-use", "-o", "foo.o"]));
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache("@file"),
                   _parse_arguments(&stringvec!["-c", "foo.c", "@foo", "-o", "foo.o"]));
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match _parse_arguments(&[arg]) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.o")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }
}
