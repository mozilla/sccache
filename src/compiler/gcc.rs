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
    CompilerArguments,
    ParsedArguments,
};
use std::collections::HashMap;
use std::path::Path;

pub fn parse_arguments(arguments : &[String]) -> CompilerArguments {
    trace!("gcc::parse_arguments");
    let mut output_arg = None;
    let mut input_arg = None;
    let mut dep_target = None;
    let mut common_args = vec!();
    let mut preprocessor_args = vec!();
    let mut compilation = false;
    let mut split_dwarf = false;
    let mut need_explicit_dep_target = false;

    let mut it = arguments.iter();
    loop {
        match it.next() {
            Some(arg) => {
                match arg.as_ref() {
                    "-c" => compilation = true,
                    "-o" => output_arg = it.next(),
                    "-gsplit-dwarf" => {
                        split_dwarf = true;
                        common_args.push(arg.clone());
                    }
                    // Arguments that take a value.
                    // -MF and -MQ are in this set but are handled separately
                    // because they are also preprocessor options.
                    "--param" | "-A" | "-D" | "-F" | "-G" | "-I" | "-L" |
                    "-U" | "-V" | "-Xassembler" | "-Xlinker" |
                    "-Xpreprocessor" | "-aux-info" | "-b" | "-idirafter" |
                    "-iframework" | "-imacros" | "-imultilib" | "-include" |
                    "-install_name" | "-iprefix" | "-iquote" | "-isysroot" |
                    "-isystem" | "-iwithprefix" | "-iwithprefixbefore" |
                    "-u" => {
                        common_args.push(arg.clone());
                        if let Some(arg_val) = it.next() {
                            common_args.push(arg_val.clone());
                        }
                    },
                    "-MF" | "-MQ" => {
                        preprocessor_args.push(arg.clone());
                        if let Some(arg_val) = it.next() {
                            preprocessor_args.push(arg_val.clone());
                        }
                    }
                    "-MT" => dep_target = it.next(),
                    // Can't cache PGO profiled output.
                    "-fprofile-use" => return CompilerArguments::CannotCache,
                    // Can't cache commandlines using a response file.
                    v @ _ if v.starts_with('@') => return CompilerArguments::CannotCache,
                    "-M" | "-MM" | "-MD" | "-MMD" => {
                        // If one of the above options is on the command line, we'll
                        // need -MT on the preprocessor command line, whether it's
                        // been passed already or not
                        need_explicit_dep_target = true;
                        preprocessor_args.push(arg.clone());
                    }
                    // Other options.
                    v @ _ if v.starts_with('-') && v.len() > 1 => {
                        common_args.push(arg.clone());
                    }
                    // Anything else is an input file.
                    v @ _ => {
                        if input_arg.is_some() || v == "-" {
                            // Can't cache compilations with multiple inputs
                            // or compilation from stdin.
                            return CompilerArguments::CannotCache;
                        }
                        input_arg = Some(v);
                    }
                };
            },
            None => break,
        }
    }
    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    let input = match input_arg {
        Some(i) => {
            // When compiling from the preprocessed output given as stdin, we need
            // to explicitly pass its file type.
            match Path::new(i).extension().and_then(|e| e.to_str()) {
                Some("c") | Some("cc") | Some("cpp") | Some("cxx") => i.to_owned(),
                e @ _ => {
                    trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
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
            if split_dwarf {
                Path::new(o)
                    .with_extension("dwo")
                    //TODO: should really be dealing with OsStr everywhere.
                    .to_str()
                    .and_then(|dwo| outputs.insert("dwo", dwo.to_owned()));
            }
            if need_explicit_dep_target {
                preprocessor_args.push(dep_target.unwrap_or(o).to_owned());
            }
        }
    }

    CompilerArguments::Ok(ParsedArguments {
        input: input,
        outputs: outputs,
        preprocessor_args: preprocessor_args,
        common_args: common_args,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use ::compiler::*;

    #[test]
    fn test_parse_arguments_simple() {
        match parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o"]) {
            CompilerArguments::Ok(ParsedArguments { input, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_map_contains!(outputs, ("obj", "foo.o"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(1, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert!(common_args.is_empty());
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    #[test]
    fn test_parse_arguments_split_dwarf() {
        match parse_arguments(&stringvec!["-gsplit-dwarf", "-c", "foo.c", "-o", "foo.o"]) {
            CompilerArguments::Ok(ParsedArguments { input, outputs, preprocessor_args, common_args }) => {
                assert!(true, "Parsed ok");
                assert_eq!("foo.c", input);
                assert_map_contains!(outputs, ("obj", "foo.o"), ("dwo", "foo.dwo"));
                //TODO: fix assert_map_contains to assert no extra keys!
                assert_eq!(2, outputs.len());
                assert!(preprocessor_args.is_empty());
                assert_eq!(stringvec!["-gsplit-dwarf"], common_args);
            }
            o @ _ => assert!(false, format!("Got unexpected parse result: {:?}", o)),
        }
    }

    //TODO:
    // * test that other args get persisted
    // * test that args with value get persisted with value
    // * test preprocessor_args
    // * test -MT

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation,
                   parse_arguments(&vec!()));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(CompilerArguments::NotCompilation,
                   parse_arguments(&stringvec!["-o", "foo"]));
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "-o", "foo.o", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_pgo() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "-fprofile-use", "-o", "foo.o"]));
    }


    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache,
                   parse_arguments(&stringvec!["-c", "foo.c", "@foo", "-o", "foo.o"]));
    }
}
