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
    write_temp_file,
};
use compiler::c::{CCompilerImpl, CCompilerKind, ParsedArguments};
use local_encoding::{Encoding, Encoder};
use log::LogLevel::{Debug, Trace};
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
use std::mem;
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
}

impl CCompilerImpl for MSVC {
    fn kind(&self) -> CCompilerKind { CCompilerKind::MSVC }
    fn parse_arguments(&self,
                       arguments: &[OsString],
                       _cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        parse_arguments(arguments)
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
        preprocess(creator, executable, parsed_args, cwd, env_vars, &self.includes_prefix, pool)
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
        compile(creator, executable, preprocessor_result, parsed_args, cwd, env_vars, pool)
    }
}

fn from_local_codepage(bytes: &Vec<u8>) -> io::Result<String> {
    Encoding::OEM.to_string(bytes)
}

/// Detect the prefix included in the output of MSVC's -showIncludes output.
pub fn detect_showincludes_prefix<T>(creator: &T, exe: &OsStr, pool: &CpuPool)
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
        cmd.args(&["-nologo", "-showIncludes", "-c", "-Fonul", "-I."])
            .arg(&input)
            .current_dir(&tempdir.path())
        // The MSDN docs say the -showIncludes output goes to stderr,
        // but that's not true unless running with -E.
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        if log_enabled!(Trace) {
            trace!("detect_showincludes_prefix: {:?}", cmd);
        }

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
        let stdout = try!(from_local_codepage(&stdout_bytes));
        for line in stdout.lines() {
            if line.ends_with("test.h") {
                for (i, c) in line.char_indices().rev() {
                    if c == ' ' {
                        // See if the rest of this line is a full pathname.
                        if Path::new(&line[i+1..]).exists() {
                            // Everything from the beginning of the line
                            // to this index is the prefix.
                            return Ok(line[..i+1].to_owned());
                        }
                    }
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
    use winapi::{CP_OEMCP, DWORD};

    const WC_ERR_INVALID_CHARS: DWORD = 0x80;

    let points = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let (bytes, _) = wide_char_to_multi_byte(CP_OEMCP,
                                             WC_ERR_INVALID_CHARS,
                                             &points,
                                             None,    // default_char
                                             false)?; // use_default_char_flag
    dst.write_all(&bytes)
}

pub fn parse_arguments(arguments: &[OsString]) -> CompilerArguments<ParsedArguments> {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut common_args = vec!();
    let mut compilation = false;
    let mut debug_info = false;
    let mut pdb = None;
    let mut depfile = None;
    let mut show_includes = false;

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

    // Next split off arguments with a value, creating an iterator of tuples
    let mut it = it.map(|arg| {
        if let Some(arg) = arg.split_prefix("-Fo") {
            ("-Fo".into(), Some(arg))
        } else if let Some(arg) = arg.split_prefix("-deps") {
            ("-deps".into(), Some(arg))
        } else if let Some(p) = arg.split_prefix("-Fd") {
            ("-Fd".into(), Some(p))
        } else {
            (arg, None)
        }
    });

    while let Some((flag, mut arg)) = it.next() {
        if let Some(s) = flag.to_str() {
            let mut handled = true;
            match s {
                "-c" => compilation = true,
                "-FI" => {
                    common_args.push("-FI".into());
                    if let Some((arg_val, flag)) = it.next() {
                        if flag.is_some() {
                            return CompilerArguments::CannotCache("extra -FI arg")
                        }
                        common_args.push(arg_val);
                    }
                }
                "-showIncludes" => show_includes = true,
                "-Fo" => output_arg = arg.take(),
                "-deps" => depfile = arg.take(),
                "-Fd" => {
                    let mut common = OsString::from("-Fd");
                    let arg = arg.take().unwrap();
                    common.push(&arg);
                    pdb = Some(arg);
                    common_args.push(common);
                }
                // Arguments we can't handle because they output more files.
                // TODO: support more multi-file outputs.
                "-FA" |
                "-Fa" |
                "-Fe" |
                "-Fm" |
                "-Fp" |
                "-FR" |
                "-Fx" => return CompilerArguments::CannotCache("multi-file output"),
                "-Zi" => {
                    debug_info = true;
                    common_args.push("-Zi".into());
                }
                _ => handled = false,
            }
            if handled {
                continue
            }
        }
        assert!(arg.is_none());

        // Arguments we can't handle.
        if flag.starts_with("@") {
            return CompilerArguments::CannotCache("@file")
        }

        // Other options.
        if flag.starts_with("-") && flag.len() > 1 {
            common_args.push(flag);
        } else {
            // Anything else is an input file.
            if input_arg.is_some() {
                // Can't cache compilations with multiple inputs.
                return CompilerArguments::CannotCache("multiple input files")
            }
            input_arg = Some(flag);
        }
    }
    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    let (input, extension) = match input_arg {
        Some(i) => {
            match Path::new(&i).extension().and_then(|e| e.to_str()) {
                Some(e) => (i.to_owned(), e.to_owned()),
                _ => {
                    trace!("Bad or missing source extension: {:?}", i);
                    return CompilerArguments::CannotCache("unknown source extension");
                }
            }
        }
        // We can't cache compilation without an input.
        None => return CompilerArguments::CannotCache("no input file"),
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
    if debug_info {
        match pdb {
            Some(p) => outputs.insert("pdb", PathBuf::from(p)),
            None => {
                // -Zi without -Fd defaults to vcxxx.pdb (where xxx depends on the
                // MSVC version), and that's used for all compilations with the same
                // working directory. We can't cache such a pdb.
                return CompilerArguments::CannotCache("shared pdb");
            }
        };
    }
    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        extension: extension,
        depfile: depfile.map(|d| d.into()),
        outputs: outputs,
        preprocessor_args: vec!(),
        common_args: common_args,
        msvc_show_includes: show_includes,
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
                     includes_prefix: &str,
                     _pool: &CpuPool)
                     -> SFuture<process::Output>
    where T: CommandCreatorSync
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-E")
        .arg(&parsed_args.input)
        .arg("-nologo")
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

            encode_path(&mut f, &objfile)?;
            write!(f, ": ")?;
            encode_path(&mut f, &parsed_args.input)?;
            write!(f, " ")?;
            let process::Output { status, stdout, stderr: stderr_bytes } = output;
            let stderr = from_local_codepage(&stderr_bytes)?;
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
            encode_path(&mut f, &parsed_args.input)?;
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

fn compile<T>(creator: &T,
              executable: &Path,
              preprocessor_result: process::Output,
              parsed_args: &ParsedArguments,
              cwd: &Path,
              env_vars: &[(OsString, OsString)],
              pool: &CpuPool)
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

    // MSVC doesn't read anything from stdin, so it needs a temporary file
    // as input.
    let write = {
        let filename = match parsed_args.input.file_name() {
            Some(name) => name,
            None => return f_err("missing input filename"),
        };
        write_temp_file(pool, filename.as_ref(), preprocessor_result.stdout)
    };

    let mut fo = OsString::from("-Fo");
    fo.push(&out_file);

    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-c")
        .arg(&fo)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);
    let output = write.and_then(move |(tempdir, input)| {
        cmd.arg(input);
        debug!("compile: {:?}", cmd);
        run_input_output(cmd, None).map(move |e| {
            drop(tempdir);
            (cacheable, e)
        })
    });

    // Sometimes MSVC can't handle compiling from the preprocessed source,
    // so have a fallback path that compiles from the original input file.
    //
    // We may just throw away this `cmd` if our execution turns out to be
    // successful.
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-c")
        .arg(&parsed_args.input)
        .arg(&fo)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);
    let ret = output.or_else(move |err| -> SFuture<_> {
        match err {
            // If compiling from the preprocessed source failed, try
            // again from the original source.
            Error(ErrorKind::ProcessError(_), _) => {
                debug!("compile: {:?}", cmd);
                Box::new(run_input_output(cmd, None).map(move |output| {
                    (cacheable, output)
                }))
            }
            e @ _ => f_err(e),
        }
    });

    // If the `-showIncludes` command line option was originally passed we need
    // to be sure to ship the output from the preprocessor as the actual
    // result of this compilation.
    //
    // Note, though, that when we ran the preprocessor we passed `-E` which
    // means that the "show includes" business when to stderr. Normally, though,
    // the compiler emits `-showIncludes` output to stdout. To handle that we
    // take the stderr of the preprocessor and prepend it to the stdout of the
    // compilation.
    let mut extra_stdout = Vec::new();
    if parsed_args.msvc_show_includes {
        extra_stdout = preprocessor_result.stderr;
    }
    Box::new(ret.map(|(cacheable, mut output)| {
        let prev = mem::replace(&mut output.stdout, extra_stdout);
        output.stdout.extend(prev);
        (cacheable, output)
    }))
}


#[cfg(test)]
mod test {
    use ::compiler::*;
    use env_logger;
    use futures::Future;
    use futures_cpupool::CpuPool;
    use mock_command::*;
    use super::*;
    use test::utils::*;

    #[test]
    fn test_detect_showincludes_prefix() {
        drop(env_logger::init());
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
        assert_eq!("blah: ", detect_showincludes_prefix(&creator, "cl.exe".as_ref(), &pool).wait().unwrap());
    }

    #[test]
    fn test_parse_arguments_simple() {
        let args = ovec!["-c", "foo.c", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        //TODO: fix assert_map_contains to assert no extra keys!
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(common_args, ovec!["-FI", "file"]);
        assert!(msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_pdb() {
        let args = ovec!["-c", "foo.c", "-Zi", "-Fdfoo.pdb", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            extension,
            depfile: _,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
        } = match parse_arguments(&args) {
            CompilerArguments::Ok(args) => args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(true, "Parsed ok");
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!("c", extension);
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
        assert_eq!(CompilerArguments::CannotCache("multiple input files"),
                   parse_arguments(&ovec!["-c", "foo.c", "-Fofoo.obj", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_unsupported() {
        assert_eq!(CompilerArguments::CannotCache("multi-file output"),
                   parse_arguments(&ovec!["-c", "foo.c", "-Fofoo.obj", "-FA"]));

        assert_eq!(CompilerArguments::CannotCache("multi-file output"),
                   parse_arguments(&ovec!["-Fa", "-c", "foo.c", "-Fofoo.obj"]));

        assert_eq!(CompilerArguments::CannotCache("multi-file output"),
                   parse_arguments(&ovec!["-c", "foo.c", "-FR", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache("@file"),
                   parse_arguments(&ovec!["-c", "foo.c", "@foo", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_missing_pdb() {
        assert_eq!(CompilerArguments::CannotCache("shared pdb"),
                   parse_arguments(&ovec!["-c", "foo.c", "-Zi", "-Fofoo.obj"]));
    }

    #[test]
    fn test_compile_simple() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            extension: "c".into(),
            depfile: None,
            outputs: vec![("obj", "foo.obj".into())].into_iter().collect(),
            preprocessor_args: vec!(),
            common_args: vec!(),
            msvc_show_includes: false,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     empty_output(),
                                     &parsed_args,
                                     &f.tempdir.path(),
                                     &[],
                                     &pool).wait().unwrap();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn test_compile_not_cacheable_pdb() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let pdb = f.touch("foo.pdb").unwrap();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            extension: "c".into(),
            depfile: None,
            outputs: vec![("obj", "foo.obj".into()),
                          ("pdb", pdb.into())].into_iter().collect(),
            preprocessor_args: vec!(),
            common_args: vec!(),
            msvc_show_includes: false,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     empty_output(),
                                     &parsed_args,
                                     f.tempdir.path(),
                                     &[],
                                     &pool).wait().unwrap();
        assert_eq!(Cacheable::No, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn test_compile_preprocessed_fails() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            extension: "c".into(),
            depfile: None,
            outputs: vec![("obj", "foo.obj".into())].into_iter().collect(),
            preprocessor_args: vec!(),
            common_args: vec!(),
            msvc_show_includes: false,
        };
        let compiler = &f.bins[0];
        // First compiler invocation fails.
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        // Second compiler invocation succeeds.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     empty_output(),
                                     &parsed_args,
                                     f.tempdir.path(),
                                     &[],
                                     &pool).wait().unwrap();
        assert_eq!(Cacheable::Yes, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn preprocess_output_appended() {
        let creator = new_creator();
        let pool = CpuPool::new(1);
        let f = TestFixture::new();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            extension: "c".into(),
            depfile: None,
            outputs: vec![("obj", "foo.obj".into())].into_iter().collect(),
            preprocessor_args: vec!(),
            common_args: vec!(),
            msvc_show_includes: true,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "stdout1", "stderr1")));
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "")));
        let mut output = empty_output();
        output.stdout.extend(b"stdout2");
        output.stderr.extend(b"stderr2");
        let (_, output) = compile(&creator,
                                  &compiler,
                                  output,
                                  &parsed_args,
                                  f.tempdir.path(),
                                  &[],
                                  &pool).wait().unwrap();
        assert_eq!(0, creator.lock().unwrap().children.len());
        assert_eq!(output.stdout, b"stderr2stdout1");
        assert_eq!(output.stderr, b"stderr1");
    }
}
