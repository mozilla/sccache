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
    Compiler,
    CompilerArguments,
    ParsedArguments,
    run_input_output,
};
use log::LogLevel::Trace;
use mock_command::{
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{
    self,
    Error,
    ErrorKind,
    Write,
};
use std::path::Path;
use std::process;
use tempdir::TempDir;

pub fn parse_arguments(arguments: &[String]) -> CompilerArguments {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut common_args = vec!();
    let mut compilation = false;
    let mut debug_info = false;
    let mut pdb = None;

    //TODO: support arguments that start with / as well.
    let mut it = arguments.iter();
    loop {
        match it.next() {
            Some(arg) => {
                match arg.as_ref() {
                    //TODO: support -dep
                    "-c" => compilation = true,
                    v @ _ if v.starts_with("-Fo") => {
                        output_arg = Some(String::from(&v[3..]));
                    }
                    // Arguments that take a value.
                    "-FI" => {
                        common_args.push(arg.clone());
                        if let Some(arg_val) = it.next() {
                            common_args.push(arg_val.clone());
                        }
                    }
                    // Arguments we can't handle.
                    "-showIncludes" => return CompilerArguments::CannotCache,
                    a @ _ if a.starts_with('@') => return CompilerArguments::CannotCache,
                    // Arguments we can't handle because they output more files.
                    // TODO: support more multi-file outputs.
                    "-FA" | "-Fa" | "-Fe" | "-Fm" | "-Fp" | "-FR" | "-Fx" => return CompilerArguments::CannotCache,
                    "-Zi" => {
                        debug_info = true;
                        common_args.push(arg.clone());
                    }
                    v @ _ if v.starts_with("-Fd") => {
                        pdb = Some(String::from(&v[3..]));
                        common_args.push(arg.clone());
                    }
                    // Other options.
                    v @ _ if v.starts_with('-') && v.len() > 1 => {
                        common_args.push(arg.clone());
                    }
                    // Anything else is an input file.
                    v @ _ => {
                        if input_arg.is_some() {
                            // Can't cache compilations with multiple inputs.
                            return CompilerArguments::CannotCache;
                        }
                        input_arg = Some(v);
                    }
                }
            }
            None => break,
        }
    }
    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    let (input, extension) = match input_arg {
        Some(i) => {
            match Path::new(i).extension().and_then(|e| e.to_str()) {
                Some(e) => (i.to_owned(), e.to_owned()),
                _ => {
                    trace!("Bad or missing source extension: {:?}", i);
                    return CompilerArguments::CannotCache;
                }
            }
        }
        // We can't cache compilation without an input.
        None => return CompilerArguments::CannotCache,
    };
    let mut outputs = HashMap::new();
    match output_arg {
        // We can't cache compilation that doesn't go to a file
        None => return CompilerArguments::CannotCache,
        Some(o) => {
            outputs.insert("obj", o.to_owned());
            // -Fd is not taken into account unless -Zi is given
            if debug_info {
                match pdb {
                    Some(p) => outputs.insert("pdb", p.to_owned()),
                    None => {
                        // -Zi without -Fd defaults to vcxxx.pdb (where xxx depends on the
                        // MSVC version), and that's used for all compilations with the same
                        // working directory. We can't cache such a pdb.
                        return CompilerArguments::CannotCache;
                    }
                };
            }
        }
    }
    CompilerArguments::Ok(ParsedArguments {
        input: input,
        extension: extension,
        outputs: outputs,
        preprocessor_args: vec!(),
        common_args: common_args,
    })
}

pub fn preprocess<T : CommandCreatorSync>(mut creator: T, compiler: &Compiler, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
    trace!("preprocess");
    //TODO: support depfile by way of -showIncludes
    let mut cmd = creator.new_command_sync(&compiler.executable);
    cmd.arg("-E")
        .arg(&parsed_args.input)
        .arg("-nologo")
        .args(&parsed_args.common_args)
        .current_dir(cwd);

    if log_enabled!(Trace) {
        trace!("preprocess: {:?}", cmd);
    }

    run_input_output(cmd, None)
}

pub fn compile<T : CommandCreatorSync>(mut creator: T, compiler: &Compiler, preprocessor_output: Vec<u8>, parsed_args: &ParsedArguments, cwd: &str) -> io::Result<process::Output> {
    trace!("compile");
    let output = try!(parsed_args.outputs.get("obj").ok_or(Error::new(ErrorKind::Other, "Missing object file output")));
    //TODO: check for the presence of the pdb file, refuse to cache if present.
    // MSVC doesn't read anything from stdin, so it needs a temporary file
    // as input.
    let tempdir = try!(TempDir::new("sccache"));
    let filename = try!(Path::new(&parsed_args.input).file_name().ok_or(Error::new(ErrorKind::Other, "Missing input filename")));
    let input = tempdir.path().join(filename);
    {
        try!(File::create(&input)
             .and_then(|mut f| f.write_all(&preprocessor_output)))
    }

    let mut cmd = creator.new_command_sync(&compiler.executable);
    cmd.arg("-c")
        .arg(&input)
        .arg(&format!("-Fo{}", output))
        .args(&parsed_args.common_args)
        .current_dir(cwd);

    run_input_output(cmd, None)
}


#[cfg(test)]
mod test {
    use super::*;
    use ::compiler::*;

    #[test]
    fn test_parse_arguments_simple() {
        match parse_arguments(&stringvec!["-c", "foo.c", "-Fofoo.obj"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_eq!("c", extension);
                assert_map_contains!(outputs, ("obj", "foo.obj"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(1, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert!(common_args.is_empty());
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    #[test]
    fn test_parse_arguments_extra() {
        match parse_arguments(&stringvec!["-c", "foo.c", "-foo", "-Fofoo.obj", "-bar"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_eq!("c", extension);
                assert_map_contains!(outputs, ("obj", "foo.obj"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(1, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert_eq!(common_args, &["-foo", "-bar"]);
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    #[test]
    fn test_parse_arguments_values() {
        match parse_arguments(&stringvec!["-c", "foo.c", "-FI", "file", "-Fofoo.obj"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_eq!("c", extension);
                assert_map_contains!(outputs, ("obj", "foo.obj"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(1, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert_eq!(common_args, &["-FI", "file"]);
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    #[test]
    fn test_parse_arguments_pdb() {
        match parse_arguments(&stringvec!["-c", "foo.c", "-Zi", "-Fdfoo.pdb", "-Fofoo.obj"]) {
            CompilerArguments::Ok(ParsedArguments { input, extension, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_eq!("c", extension);
                assert_map_contains!(outputs, ("obj", "foo.obj"), ("pdb", "foo.pdb"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(2, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert_eq!(common_args, &["-Zi", "-Fdfoo.pdb"]);
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation,
                   parse_arguments(&vec!()));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(CompilerArguments::NotCompilation,
                   parse_arguments(&stringvec!["-Fofoo", "foo.c"]));
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "-Fofoo.obj", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_unsupported() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "-Fofoo.obj", "-FA"]));

        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-Fa", "-c", "foo.c", "-Fofoo.obj"]));

        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "-FR", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "@foo", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_missing_pdb() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "-Zi", "-Fofoo.obj"]));
    }
}
