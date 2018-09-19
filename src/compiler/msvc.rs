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
    clang,
    gcc,
    Cacheable,
    CompilerArguments,
    CompileCommand,
    write_temp_file,
};
use compiler::args::*;
use compiler::c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments};
use dist;
use local_encoding::{Encoding, Encoder};
use log::Level::Debug;
use futures::future::Future;
use futures_cpupool::CpuPool;
use mock_command::{
    CommandCreatorSync,
    RunCommand,
};
use std::collections::{HashMap,HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{
    self,
    BufWriter,
    Write,
};
use std::path::{Path, PathBuf};
use std::process::{self,Stdio};
use util::{run_input_output, OsStrExt};

use errors::*;

/// A struct on which to implement `CCompilerImpl`.
///
/// Needs a little bit of state just to persist `includes_prefix`.
#[derive(Debug, PartialEq, Clone)]
pub struct MSVC {
    /// The prefix used in the output of `-showIncludes`.
    pub includes_prefix: String,
    pub is_clang: bool,
}

impl CCompilerImpl for MSVC {
    fn kind(&self) -> CCompilerKind { CCompilerKind::MSVC }
    fn parse_arguments(&self,
                       arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        parse_arguments(arguments, cwd, self.is_clang)
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
        preprocess(creator, executable, parsed_args, cwd, env_vars, may_dist, &self.includes_prefix)
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

fn from_local_codepage(bytes: &Vec<u8>) -> io::Result<String> {
    Encoding::OEM.to_string(bytes)
}

/// Detect the prefix included in the output of MSVC's -showIncludes output.
pub fn detect_showincludes_prefix<T>(creator: &T,
                                     exe: &OsStr,
                                     is_clang: bool,
                                     env: Vec<(OsString, OsString)>,
                                     pool: &CpuPool)
                                     -> SFuture<String>
    where T: CommandCreatorSync
{
    let write = write_temp_file(pool,
                                "test.c".as_ref(),
                                b"#include \"test.h\"\n".to_vec());

    let exe = exe.to_os_string();
    let mut creator = creator.clone();
    let pool = pool.clone();
    let write2 = write.and_then(move |(tempdir, input)| {
        let header = tempdir.path().join("test.h");
        pool.spawn_fn(move || -> Result<_> {
            let mut file = File::create(&header)?;
            file.write_all(b"/* empty */\n")?;
            Ok((tempdir, input))
        }).chain_err(|| {
            "failed to write temporary file"
        })
    });
    let output = write2.and_then(move |(tempdir, input)| {
        let mut cmd = creator.new_command_sync(&exe);
        // clang.exe on Windows reports the same set of built-in preprocessor defines as clang-cl,
        // but it doesn't accept MSVC commandline arguments unless you pass --driver-mode=cl.
        // clang-cl.exe will accept this argument as well, so always add it in this case.
        if is_clang {
            cmd.arg("--driver-mode=cl");
        }
        cmd.args(&["-nologo", "-showIncludes", "-c", "-Fonul", "-I."])
            .arg(&input)
            .current_dir(&tempdir.path())
        // The MSDN docs say the -showIncludes output goes to stderr,
        // but that's not true unless running with -E.
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        trace!("detect_showincludes_prefix: {:?}", cmd);

        run_input_output(cmd, None).map(|e| {
            // Keep the tempdir around so test.h still exists for the
            // checks below.
            (e, tempdir)
        })
    });

    Box::new(output.and_then(|(output, tempdir)| {
        if !output.status.success() {
            bail!("Failed to detect showIncludes prefix")
        }

        let process::Output { stdout: stdout_bytes, .. } = output;
        let stdout = from_local_codepage(&stdout_bytes)
            .chain_err(|| "Failed to convert compiler stdout while detecting showIncludes prefix")?;
        for line in stdout.lines() {
            if !line.ends_with("test.h") {
                continue
            }
            for (i, c) in line.char_indices().rev() {
                if c != ' ' {
                    continue
                }
                let path = tempdir.path().join(&line[i + 1..]);
                // See if the rest of this line is a full pathname.
                if path.exists() {
                    // Everything from the beginning of the line
                    // to this index is the prefix.
                    return Ok(line[..i+1].to_owned());
                }
            }
        }
        drop(tempdir);

        debug!("failed to detect showIncludes prefix with output: {}",
               stdout);

        bail!("Failed to detect showIncludes prefix")
    }))
}

#[cfg(unix)]
fn encode_path(dst: &mut Write, path: &Path) -> io::Result<()> {
    use std::os::unix::prelude::*;

    let bytes = path.as_os_str().as_bytes();
    dst.write_all(bytes)
}

#[cfg(windows)]
fn encode_path(dst: &mut Write, path: &Path) -> io::Result<()> {
    use std::os::windows::prelude::*;
    use local_encoding::windows::wide_char_to_multi_byte;
    use winapi::um::winnls::CP_OEMCP;

    let points = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let (bytes, _) = wide_char_to_multi_byte(CP_OEMCP,
                                             0,
                                             &points,
                                             None,    // default_char
                                             false)?; // use_default_char_flag
    dst.write_all(&bytes)
}

ArgData!{
    TooHardFlag,
    TooHard(OsString),
    TooHardPath(PathBuf),
    PreprocessorArgument(OsString),
    PreprocessorArgumentPath(PathBuf),
    DoCompilation,
    ShowIncludes,
    Output(PathBuf),
    DepFile(PathBuf),
    ProgramDatabase(PathBuf),
    DebugInfo,
    XClang(OsString),
}

use self::ArgData::*;

counted_array!(static ARGS: [ArgInfo<ArgData>; _] = [
    take_arg!("-D", OsString, Concatenated, PreprocessorArgument),
    take_arg!("-FA", OsString, Concatenated, TooHard),
    take_arg!("-FI", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-FR", PathBuf, Concatenated, TooHardPath),
    take_arg!("-Fa", PathBuf, Concatenated, TooHardPath),
    take_arg!("-Fd", PathBuf, Concatenated, ProgramDatabase),
    take_arg!("-Fe", PathBuf, Concatenated, TooHardPath),
    take_arg!("-Fi", PathBuf, Concatenated, TooHardPath),
    take_arg!("-Fm", PathBuf, Concatenated, TooHardPath),
    take_arg!("-Fo", PathBuf, Concatenated, Output),
    take_arg!("-Fp", PathBuf, Concatenated, TooHardPath),
    take_arg!("-Fr", PathBuf, Concatenated, TooHardPath),
    flag!("-Fx", TooHardFlag),
    take_arg!("-I", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    take_arg!("-U", OsString, Concatenated, PreprocessorArgument),
    take_arg!("-Xclang", OsString, Separated, XClang),
    flag!("-Zi", DebugInfo),
    flag!("-c", DoCompilation),
    take_arg!("-deps", PathBuf, Concatenated, DepFile),
    flag!("-fsyntax-only", TooHardFlag),
    take_arg!("-o", PathBuf, Separated, Output), // Deprecated but valid
    flag!("-showIncludes", ShowIncludes),
    take_arg!("@", PathBuf, Concatenated, TooHardPath),
]);

pub fn parse_arguments(arguments: &[OsString], cwd: &Path, is_clang: bool) -> CompilerArguments<ParsedArguments> {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut common_args = vec!();
    let mut preprocessor_args = vec!();
    let mut compilation = false;
    let mut debug_info = false;
    let mut pdb = None;
    let mut depfile = None;
    let mut show_includes = false;
    let mut xclangs: Vec<OsString> = vec![];

    // First convert all `/foo` arguments to `-foo` to accept both styles
    let it = arguments.iter().map(|i| {
        if let Some(arg) = i.split_prefix("/") {
            let mut dash = OsString::from("-");
            dash.push(&arg);
            dash
        } else {
            i.clone()
        }
    });

    for arg in ArgsIter::new(it, &ARGS[..]) {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        match arg.get_data() {
            Some(TooHardFlag) |
            Some(TooHard(_)) |
            Some(TooHardPath(_)) => {
                cannot_cache!(arg.flag_str().expect(
                    "Can't be Argument::Raw/UnknownFlag",
                ))
            }
            Some(DoCompilation) => compilation = true,
            Some(ShowIncludes) => show_includes = true,
            Some(Output(out)) => {
                output_arg = Some(out.clone());
                // Can't usefully cache output that goes to nul anyway,
                // and it breaks reading entries from cache.
                if out.as_os_str() == "nul" {
                    cannot_cache!("output to nul")
                }
            }
            Some(DepFile(p)) => depfile = Some(p.clone()),
            Some(ProgramDatabase(p)) => pdb = Some(p.clone()),
            Some(DebugInfo) => debug_info = true,
            Some(PreprocessorArgument(_)) |
            Some(PreprocessorArgumentPath(_)) => {}
            Some(XClang(s)) => xclangs.push(s.clone()),
            None => {
                match arg {
                    Argument::Raw(ref val) => {
                        if input_arg.is_some() {
                            // Can't cache compilations with multiple inputs.
                            cannot_cache!("multiple input files");
                        }
                        input_arg = Some(val.clone());
                    }
                    Argument::UnknownFlag(ref flag) => common_args.push(flag.clone()),
                    _ => unreachable!(),
                }
            }
        }
        match arg.get_data() {
            Some(PreprocessorArgument(_)) |
            Some(PreprocessorArgumentPath(_)) => {
                preprocessor_args.extend(arg.normalize(NormalizedDisposition::Concatenated).iter_os_strings())
            },
            Some(ProgramDatabase(_)) |
            Some(DebugInfo) => {
                common_args.extend(arg.normalize(NormalizedDisposition::Concatenated).iter_os_strings())
            },
            _ => {}
        }
    }

    // TODO: doing this here reorders the arguments, hopefully that doesn't affect the meaning
    let xclang_it = gcc::ExpandIncludeFile::new(cwd, &xclangs);
    for arg in ArgsIter::new(xclang_it, (&gcc::ARGS[..], &clang::ARGS[..])) {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        // Eagerly bail if it looks like we need to do more complicated work
        use compiler::gcc::ArgData::*;
        let args = match arg.get_data() {
            Some(SplitDwarf) |
            Some(ProfileGenerate) |
            Some(TestCoverage) |
            Some(Coverage) |
            Some(DoCompilation) |
            Some(Language(_)) |
            Some(Output(_)) |
            Some(TooHardFlag) |
            Some(TooHard(_)) => {
                cannot_cache!(arg.flag_str().unwrap_or(
                    "Can't handle complex arguments through clang",
                ))
            }
            None => {
                match arg {
                    Argument::Raw(_) |
                    Argument::UnknownFlag(_) => Some(&mut common_args),
                    _ => unreachable!(),
                }
            }
            Some(PassThrough(_)) |
            Some(PassThroughPath(_)) => Some(&mut common_args),
            Some(PreprocessorArgumentFlag) |
            Some(PreprocessorArgument(_)) |
            Some(PreprocessorArgumentPath(_)) |
            Some(DepTarget(_)) |
            Some(NeedDepTarget) => Some(&mut preprocessor_args),
        };
        if let Some(args) = args {
            // Normalize attributes such as "-I foo", "-D FOO=bar", as
            // "-Ifoo", "-DFOO=bar", etc. and "-includefoo", "idirafterbar" as
            // "-include foo", "-idirafter bar", etc.
            let norm = match arg.flag_str() {
                Some(s) if s.len() == 2 => NormalizedDisposition::Concatenated,
                _ => NormalizedDisposition::Separated,
            };
            for arg in arg.normalize(norm).iter_os_strings() {
                args.push("-Xclang".into());
                args.push(arg)
            }
        }
    }

    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    let (input, language) = match input_arg {
        Some(i) => {
            match Language::from_file_name(Path::new(&i)) {
                Some(l) => (i.to_owned(), l),
                None => cannot_cache!("unknown source language"),
            }
        }
        // We can't cache compilation without an input.
        None => cannot_cache!("no input file"),
    };
    let mut outputs = HashMap::new();
    match output_arg {
        // If output file name is not given, use default naming rule
        None => {
            outputs.insert("obj", Path::new(&input).with_extension("obj"));
        },
        Some(o) => {
            outputs.insert("obj", PathBuf::from(o));
        },
    }
    // -Fd is not taken into account unless -Zi is given
    // Clang is currently unable to generate PDB files
    if debug_info && !is_clang {
        match pdb {
            Some(p) => outputs.insert("pdb", p),
            None => {
                // -Zi without -Fd defaults to vcxxx.pdb (where xxx depends on the
                // MSVC version), and that's used for all compilations with the same
                // working directory. We can't cache such a pdb.
                cannot_cache!("shared pdb");
            }
        };
    }

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        language: language,
        depfile: depfile,
        outputs: outputs,
        preprocessor_args: preprocessor_args,
        common_args: common_args,
        msvc_show_includes: show_includes,
        profile_generate: false,
    })
}

#[cfg(windows)]
fn normpath(path: &str) -> String {
    use kernel32;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;
    use std::os::windows::io::AsRawHandle;
    File::open(path)
        .and_then(|f| {
            let handle = f.as_raw_handle();
            let size = unsafe { kernel32::GetFinalPathNameByHandleW(handle,
                                                         ptr::null_mut(),
                                                         0,
                                                         0)
            };
            if size == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut wchars = Vec::with_capacity(size as usize);
            wchars.resize(size as usize, 0);
            if unsafe { kernel32::GetFinalPathNameByHandleW(handle,
                                                            wchars.as_mut_ptr(),
                                                            wchars.len() as u32,
                                                            0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // The return value of GetFinalPathNameByHandleW uses the
            // '\\?\' prefix.
            let o = OsString::from_wide(&wchars[4..wchars.len() - 1]);
            o.into_string()
                .map(|s| s.replace('\\', "/"))
                .or(Err(io::Error::new(io::ErrorKind::Other, "Error converting string")))
        })
        .unwrap_or(path.replace('\\', "/"))
}

#[cfg(not(windows))]
fn normpath(path: &str) -> String {
    path.to_owned()
}

pub fn preprocess<T>(creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)],
                     _may_dist: bool,
                     includes_prefix: &str)
                     -> SFuture<process::Output>
    where T: CommandCreatorSync
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-E")
        .arg(&parsed_args.input)
        .arg("-nologo")
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);
    if parsed_args.depfile.is_some() || parsed_args.msvc_show_includes {
        cmd.arg("-showIncludes");
    }

    if log_enabled!(Debug) {
        debug!("preprocess: {:?}", cmd);
    }

    let parsed_args = parsed_args.clone();
    let includes_prefix = includes_prefix.to_string();
    let cwd = cwd.to_owned();

    Box::new(run_input_output(cmd, None).and_then(move |output| {
        let parsed_args = &parsed_args;
        if let (Some(ref objfile), &Some(ref depfile)) = (parsed_args.outputs.get("obj"), &parsed_args.depfile) {
            let f = File::create(cwd.join(depfile))?;
            let mut f = BufWriter::new(f);

            encode_path(&mut f, &objfile).chain_err(|| format!("Couldn't encode objfile filename: '{:?}'", objfile))?;
            write!(f, ": ")?;
            encode_path(&mut f, &parsed_args.input).chain_err(|| format!("Couldn't encode input filename: '{:?}'", objfile))?;
            write!(f, " ")?;
            let process::Output { status, stdout, stderr: stderr_bytes } = output;
            let stderr = from_local_codepage(&stderr_bytes).chain_err(|| "Failed to convert preprocessor stderr")?;
            let mut deps = HashSet::new();
            let mut stderr_bytes = vec!();
            for line in stderr.lines() {
                if line.starts_with(&includes_prefix) {
                    let dep = normpath(line[includes_prefix.len()..].trim());
                    trace!("included: {}", dep);
                    if deps.insert(dep.clone()) && !dep.contains(' ') {
                        write!(f, "{} ", dep)?;
                    }
                    if !parsed_args.msvc_show_includes {
                        continue
                    }
                }
                stderr_bytes.extend_from_slice(line.as_bytes());
                stderr_bytes.push(b'\n');
            }
            writeln!(f, "")?;
            // Write extra rules for each dependency to handle
            // removed files.
            encode_path(&mut f, &parsed_args.input).chain_err(|| format!("Couldn't encode filename: '{:?}'", parsed_args.input))?;
            writeln!(f, ":")?;
            let mut sorted = deps.into_iter().collect::<Vec<_>>();
            sorted.sort();
            for dep in sorted {
                if !dep.contains(' ') {
                    writeln!(f, "{}:", dep)?;
                }
            }
            Ok(process::Output { status: status, stdout: stdout, stderr: stderr_bytes })
        } else {
            Ok(output)
        }
    }))
}

fn generate_compile_commands(path_transformer: &mut dist::PathTransformer,
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

    // See if this compilation will produce a PDB.
    let cacheable = parsed_args.outputs.get("pdb")
        .map_or(Cacheable::Yes, |pdb| {
            // If the PDB exists, we don't know if it's shared with another
            // compilation. If it is, we can't cache.
            if Path::new(&cwd).join(pdb).exists() {
                Cacheable::No
            } else {
                Cacheable::Yes
            }
        });

    let mut fo = OsString::from("-Fo");
    fo.push(&out_file);

    let mut arguments: Vec<OsString> = vec![
        "-c".into(),
        parsed_args.input.clone().into(),
        fo,
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
        // http://releases.llvm.org/6.0.0/tools/clang/docs/UsersManual.html#clang-cl
        // TODO: Use /T... for language?
        let mut fo = String::from("-Fo");
        fo.push_str(&path_transformer.to_dist(out_file)?);

        let mut arguments: Vec<String> = vec![
            "-c".into(),
            path_transformer.to_dist(&parsed_args.input)?,
            fo,
        ];
        // It's important to avoid preprocessor_args because of things like /FI which
        // forcibly includes another file. This does mean we're potentially vulnerable
        // to misidentification of flags like -DYNAMICBASE (though in that specific
        // case we're safe as it only applies to link time, which sccache avoids).
        arguments.extend(dist::osstrings_to_strings(&parsed_args.common_args)?);

        Some(dist::CompileCommand {
            executable: path_transformer.to_dist(&executable)?,
            arguments: arguments,
            env_vars: dist::osstring_tuples_to_strings(env_vars)?,
            cwd: path_transformer.to_dist(cwd)?,
        })
    })();

    Ok((command, dist_command, cacheable))
}


#[cfg(test)]
mod test {
    use ::compiler::*;
    use env;
    use env_logger;
    use futures::Future;
    use futures_cpupool::CpuPool;
    use mock_command::*;
    use super::*;
    use test::utils::*;

    fn parse_arguments(arguments: &[OsString]) -> CompilerArguments<ParsedArguments> {
        super::parse_arguments(arguments, &env::current_dir().unwrap(), false)
    }

    #[test]
    fn test_detect_showincludes_prefix() {
        drop(env_logger::try_init());
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let srcfile = f.touch("test.h").unwrap();
        let mut s = srcfile.to_str().unwrap();
        if s.starts_with("\\\\?\\") {
            s = &s[4..];
        }
        let stdout = format!("blah: {}\r\n", s);
        let stderr = String::from("some\r\nstderr\r\n");
        next_command(&creator, Ok(MockChild::new(exit_status(0), &stdout, &stderr)));
        assert_eq!("blah: ", detect_showincludes_prefix(&creator, "cl.exe".as_ref(), false,
                                                        Vec::new(), &pool).wait().unwrap());
    }

    #[test]
    fn test_parse_arguments_simple() {
        let args = ovec!["-c", "foo.c", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_default_name() {
        let args = ovec!["-c", "foo.c"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn parse_argument_slashes() {
        let args = ovec!["-c", "foo.c", "/Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_extra() {
        let args = ovec!["-c", "foo.c", "-foo", "-Fofoo.obj", "-bar"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(common_args, ovec!["-foo", "-bar"]);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_values() {
        let args = ovec!["-c", "foo.c", "-FI", "file", "-Fofoo.obj", "/showIncludes"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert_eq!(preprocessor_args, ovec!["-FIfile"]);
        assert!(common_args.is_empty());
        assert!(msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_pdb() {
        let args = ovec!["-c", "foo.c", "-Zi", "-Fdfoo.pdb", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs,
                             ("obj", PathBuf::from("foo.obj")),
                             ("pdb", PathBuf::from("foo.pdb")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(2, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(common_args, ovec!["-Zi", "-Fdfoo.pdb"]);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation,
                   parse_arguments(&vec!()));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(CompilerArguments::NotCompilation,
                   parse_arguments(&ovec!["-Fofoo", "foo.c"]));
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(CompilerArguments::CannotCache("multiple input files", None),
                   parse_arguments(&ovec!["-c", "foo.c", "-Fofoo.obj", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_unsupported() {
        assert_eq!(CompilerArguments::CannotCache("-FA", None),
                   parse_arguments(&ovec!["-c", "foo.c", "-Fofoo.obj", "-FA"]));

        assert_eq!(CompilerArguments::CannotCache("-Fa", None),
                   parse_arguments(&ovec!["-Fa", "-c", "foo.c", "-Fofoo.obj"]));

        assert_eq!(CompilerArguments::CannotCache("-FR", None),
                   parse_arguments(&ovec!["-c", "foo.c", "-FR", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache("@", None),
                   parse_arguments(&ovec!["-c", "foo.c", "@foo", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_missing_pdb() {
        assert_eq!(CompilerArguments::CannotCache("shared pdb", None),
                   parse_arguments(&ovec!["-c", "foo.c", "-Zi", "-Fofoo.obj"]));
    }

    #[test]
    fn test_compile_simple() {
        let creator = new_creator();
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            language: Language::C,
            depfile: None,
            outputs: vec![("obj", "foo.obj".into())].into_iter().collect(),
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

    #[test]
    fn test_compile_not_cacheable_pdb() {
        let creator = new_creator();
        let f = TestFixture::new();
        let pdb = f.touch("foo.pdb").unwrap();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            language: Language::C,
            depfile: None,
            outputs: vec![("obj", "foo.obj".into()),
                          ("pdb", pdb.into())].into_iter().collect(),
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
        assert_eq!(Cacheable::No, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }
}
