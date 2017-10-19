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
use compiler::args::*;
use compiler::c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments};
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
    Read,
    Write,
};
use std::path::{Path, PathBuf};
use std::process::{self,Stdio};
use std::slice::from_raw_parts;
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
                       cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        parse_arguments(arguments, cwd)
    }

    fn preprocess<T>(&self,
                     creator: &T,
                     executable: &Path,
                     parsed_args: &ParsedArguments,
                     cwd: &Path,
                     env_vars: &[(OsString, OsString)])
                     -> SFuture<process::Output> where T: CommandCreatorSync
    {
        preprocess(creator, executable, parsed_args, cwd, env_vars, &self.includes_prefix)
    }

    fn compile<T>(&self,
                  creator: &T,
                  executable: &Path,
                  parsed_args: &ParsedArguments,
                  cwd: &Path,
                  env_vars: &[(OsString, OsString)])
                  -> SFuture<(Cacheable, process::Output)>
        where T: CommandCreatorSync
    {
        compile(creator, executable, parsed_args, cwd, env_vars)
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
        let stdout = from_local_codepage(&stdout_bytes)
            .chain_err(|| "Failed to convert compiler stdout while detecting showIncludes prefix")?;
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
    use winapi::CP_OEMCP;

    let points = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let (bytes, _) = wide_char_to_multi_byte(CP_OEMCP,
                                             0,
                                             &points,
                                             None,    // default_char
                                             false)?; // use_default_char_flag
    dst.write_all(&bytes)
}

#[derive(Clone, Debug)]
enum MSVCArgAttribute {
    TooHard,
    PreprocessorArgument,
    DoCompilation,
    ShowIncludes,
    Output,
    DepFile,
    ProgramDatabase,
    DebugInfo,
}

use self::MSVCArgAttribute::*;

static ARGS: [(ArgInfo, MSVCArgAttribute); 20] = [
    take_arg!("-D", String, Concatenated, PreprocessorArgument),
    take_arg!("-FA", String, Concatenated, TooHard),
    take_arg!("-FI", Path, CanBeSeparated, PreprocessorArgument),
    take_arg!("-FR", Path, Concatenated, TooHard),
    take_arg!("-Fa", Path, Concatenated, TooHard),
    take_arg!("-Fd", Path, Concatenated, ProgramDatabase),
    take_arg!("-Fe", Path, Concatenated, TooHard),
    take_arg!("-Fi", Path, Concatenated, TooHard),
    take_arg!("-Fm", Path, Concatenated, TooHard),
    take_arg!("-Fo", Path, Concatenated, Output),
    take_arg!("-Fp", Path, Concatenated, TooHard),
    take_arg!("-Fr", Path, Concatenated, TooHard),
    flag!("-Fx", TooHard),
    take_arg!("-I", Path, Concatenated, PreprocessorArgument),
    take_arg!("-U", String, Concatenated, PreprocessorArgument),
    flag!("-Zi", DebugInfo),
    flag!("-c", DoCompilation),
    take_arg!("-deps", Path, Concatenated, DepFile),
    flag!("-showIncludes", ShowIncludes),
    take_arg!("@", Path, Concatenated, TooHard),
];

pub fn parse_arguments(arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<ParsedArguments> {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut common_args = vec!();
    let mut compilation = false;
    let mut debug_info = false;
    let mut pdb = None;
    let mut depfile = None;
    let mut show_includes = false;

    // Expand @response file arguments.
    let it = ExpandedArgs::new(cwd, arguments.iter().map(|a| a.to_owned()));

    // Convert all `/foo` arguments to `-foo` to accept both styles. Note that
    // this must be done after response file expansion because the arguments
    // within response file also need to be normalized.
    let it = it.map(|i| {
        if let Some(arg) = i.split_prefix("/") {
            let mut dash = OsString::from("-");
            dash.push(&arg);
            dash
        } else {
            i.clone()
        }
    });

    for item in ArgsIter::new(it, &ARGS[..]) {
        match item.data {
            Some(TooHard) => {
                return CompilerArguments::CannotCache(item.arg.to_str().expect(
                    "Can't be Argument::Raw/UnknownFlag",
                ))
            }
            Some(DoCompilation) => compilation = true,
            Some(ShowIncludes) => show_includes = true,
            Some(Output) => {
                output_arg = item.arg.get_value().map(OsString::from);
                // Can't usefully cache output that goes to nul anyway,
                // and it breaks reading entries from cache.
                if let Some(ref out) = output_arg {
                    if out == "nul" {
                        return CompilerArguments::CannotCache("output to nul")
                    }
                }
            }
            Some(DepFile) => depfile = item.arg.get_value().map(|s| s.unwrap_path()),
            Some(ProgramDatabase) => pdb = item.arg.get_value().map(|s| s.unwrap_path()),
            Some(DebugInfo) => debug_info = true,
            Some(PreprocessorArgument) => {}
            None => {
                match item.arg {
                    Argument::Raw(ref val) => {
                        if input_arg.is_some() {
                            // Can't cache compilations with multiple inputs.
                            return CompilerArguments::CannotCache("multiple input files");
                        }
                        input_arg = Some(val.clone());
                    }
                    Argument::UnknownFlag(ref flag) => common_args.push(flag.clone()),
                    _ => unreachable!(),
                }
            }
        }
        match item.data {
            Some(PreprocessorArgument) |
            Some(ProgramDatabase) |
            Some(DebugInfo) => common_args.extend(item.arg.normalize(NormalizedDisposition::Concatenated)),
            _ => {}
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
                None => return CompilerArguments::CannotCache("unknown source language"),
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
            Some(p) => outputs.insert("pdb", p),
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
        language: language,
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
                     includes_prefix: &str)
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

fn compile<T>(creator: &T,
              executable: &Path,
              parsed_args: &ParsedArguments,
              cwd: &Path,
              env_vars: &[(OsString, OsString)])
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

    let mut fo = OsString::from("-Fo");
    fo.push(&out_file);

    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-c")
        .arg(&parsed_args.input)
        .arg(&fo)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);

    Box::new(run_input_output(cmd, None).map(move |output| {
        (cacheable, output)
    }))
}

/// Creates an iterator over the arguments in a Windows command line string.
fn split_args(s: &str) -> SplitArgs {
    SplitArgs { s: s }
}

/// An iterator over the arguments in a Windows command line.
///
/// This produces results identical to `CommandLineToArgvW` except in the
/// following cases:
///
///  1. When passed an empty string, CommandLineToArgvW returns the path to the
///     current executable file. Here, the iterator will simply be empty.
///  2. CommandLineToArgvW interprets the first argument differently than the
///     rest. Here, all arguments are treated in identical fashion.
///
/// Parsing rules:
///
///  - Arguments are delimited by whitespace (either a space or tab).
///  - A string surrounded by double quotes is interpreted as a single argument.
///  - Backslashes are interpreted literally unless followed by a double quote.
///  - 2n backslashes followed by a double quote reduce to n backslashes and we
///    enter the "in quote" state.
///  - 2n+1 backslashes followed by a double quote reduces to n backslashes,
///    we do *not* enter the "in quote" state, and the double quote is
///    interpreted literally.
///
/// References:
///  - https://msdn.microsoft.com/en-us/library/windows/desktop/bb776391(v=vs.85).aspx
///  - https://msdn.microsoft.com/en-us/library/windows/desktop/17w5ykft(v=vs.85).aspx
#[derive(Clone, Debug)]
struct SplitArgs<'a> {
    s: &'a str,
}

impl<'a> Iterator for SplitArgs<'a> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        // Current parsing state
        let mut in_quotes = false;
        let mut backslashes: usize = 0;

        // Skip initial whitespace
        self.s = self.s.trim_left_matches(|c| c == ' ' || c == '\t');

        if self.s.is_empty() {
            return None;
        }

        let mut arg = String::new();

        let mut chars = self.s.chars();

        for c in &mut chars {
            match c {
                ' ' | '\t' => {
                    // Flush out any backslashes.
                    while backslashes > 0 {
                        arg.push('\\');
                        backslashes -= 1;
                    }

                    if in_quotes {
                        arg.push(c);
                    } else {
                        // White space delimits the argument.
                        break;
                    }
                },

                // Count backslashes.
                '\\' => { backslashes += 1 },

                // Toggle quote state.
                '"' => {
                    // Flush out half the number of backslashes.
                    while backslashes > 1 {
                        arg.push('\\');
                        backslashes -= 2;
                    }

                    if backslashes == 0 {
                        // Even number or no backslashes. Toggle quotes.
                        in_quotes = !in_quotes;
                    } else {
                        // Discard extra backslash.
                        backslashes = 0;

                        // Interpret as literal quote.
                        arg.push('"');
                    }
                }

                _ => {
                    // Flush out any backslashes.
                    while backslashes > 0 {
                        arg.push('\\');
                        backslashes -= 1;
                    }

                    arg.push(c);
                }
            };
        }

        // Slide the window over.
        self.s = chars.as_str();

        Some(arg)
    }
}

fn read_utf16s<R>(reader: &mut R) -> io::Result<String>
    where R: Read
{
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let data: &[u16] = unsafe {
        from_raw_parts(buf.as_ptr() as *const u16, buf.len() / 2)
    };

    Ok(String::from_utf16(data).expect("invalid utf-16"))
}

/// Iterator that expands @response files in-place.
///
/// According to MSDN [1], @file means:
///
///     A text file containing compiler commands.
///
///     A response file can contain any commands that you would specify on the
///     command line. This can be useful if your command-line arguments exceed
///     127 characters.
///
///     It is not possible to specify the @ option from within a response file.
///     That is, a response file cannot embed another response file.
///
///     From the command line you can specify as many response file options (for
///     example, @respfile.1 @respfile.2) as you want.
///
/// Note that, in order to conform to the spec, response files are not
/// recursively expanded.
///
/// [1]: https://docs.microsoft.com/en-us/cpp/build/reference/at-specify-a-compiler-response-file
struct ExpandedArgs<'a, Iter>
{
    cwd: &'a Path,
    iter: Iter,
    stack: Vec<OsString>,
}

impl<'a, Iter> ExpandedArgs<'a, Iter>
{
    pub fn new(cwd: &'a Path, iter: Iter) -> ExpandedArgs<'a, Iter> {
        ExpandedArgs {
            cwd: cwd,
            iter: iter,
            stack: Vec::new(),
        }
    }
}

impl<'a, Iter> Iterator for ExpandedArgs<'a, Iter>
    where Iter: Iterator<Item=OsString>
{
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        loop {
            // Always pop elements off the stack until it is empty before
            // returning more from the iterator.
            if let Some(arg) = self.stack.pop() {
                return Some(arg);
            }

            // Get elements out of the iterator.
            if let Some(arg) = self.iter.next() {
                if let Some(file) = arg.split_prefix("@") {
                    // Argument is a response file.
                    let file = self.cwd.join(&file);

                    match File::open(&file).and_then(|mut f| read_utf16s(&mut f)) {
                        Ok(contents) => {
                            let new_args = split_args(&contents).collect::<Vec<_>>();
                            self.stack.extend(new_args.iter().rev().map(|s| s.into()));

                            // Continue on to the next iteration of the loop.
                            // There is no guarantee that this response file had
                            // any arguments in it.
                        }
                        Err(e) => {
                            debug!("failed to read @-file `{}`: {}", file.display(), e);
                            return Some(arg);
                        }
                    }
                } else {
                    return Some(arg);
                }
            } else {
                return None;
            }
        }
    }
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

    fn _parse_arguments(arguments: &[OsString]) -> CompilerArguments<ParsedArguments> {
        parse_arguments(arguments, ".".as_ref())
    }

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
            language,
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
        } = match _parse_arguments(&args) {
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
        } = match _parse_arguments(&args) {
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
        } = match _parse_arguments(&args) {
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
        } = match _parse_arguments(&args) {
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
        assert_eq!(common_args, ovec!["-FIfile"]);
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
        } = match _parse_arguments(&args) {
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
                   _parse_arguments(&vec!()));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(CompilerArguments::NotCompilation,
                   _parse_arguments(&ovec!["-Fofoo", "foo.c"]));
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(CompilerArguments::CannotCache("multiple input files"),
                   _parse_arguments(&ovec!["-c", "foo.c", "-Fofoo.obj", "bar.c"]));
    }

    #[test]
    fn test_parse_arguments_unsupported() {
        assert_eq!(CompilerArguments::CannotCache("-FA"),
                   _parse_arguments(&ovec!["-c", "foo.c", "-Fofoo.obj", "-FA"]));

        assert_eq!(CompilerArguments::CannotCache("-Fa"),
                   _parse_arguments(&ovec!["-Fa", "-c", "foo.c", "-Fofoo.obj"]));

        assert_eq!(CompilerArguments::CannotCache("-FR"),
                   _parse_arguments(&ovec!["-c", "foo.c", "-FR", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(CompilerArguments::CannotCache("@"),
                   _parse_arguments(&ovec!["-c", "foo.c", "@foo", "-Fofoo.obj"]));
    }

    #[test]
    fn test_parse_arguments_missing_pdb() {
        assert_eq!(CompilerArguments::CannotCache("shared pdb"),
                   _parse_arguments(&ovec!["-c", "foo.c", "-Zi", "-Fofoo.obj"]));
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
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     &parsed_args,
                                     &f.tempdir.path(),
                                     &[]).wait().unwrap();
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
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let (cacheable, _) = compile(&creator,
                                     &compiler,
                                     &parsed_args,
                                     f.tempdir.path(),
                                     &[]).wait().unwrap();
        assert_eq!(Cacheable::No, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn test_split_args() {
        fn test_split(cmdline: &str, expected: &[&str]) -> bool {
            let args = split_args(cmdline).collect::<Vec<_>>();

            args == expected.iter()
                            .map(|s| String::from(*s))
                            .collect::<Vec<_>>()
        }

        assert!(test_split("/c foo.cpp /o foo.obj",
                           &["/c", "foo.cpp", "/o", "foo.obj"]));
        assert!(test_split("/c foo.cpp \"/o foo.obj\"",
                           &["/c", "foo.cpp", "/o foo.obj"]));
        assert!(test_split("/c foo.cpp        /o foo.obj",
                           &["/c", "foo.cpp", "/o", "foo.obj"]));
        assert!(test_split("prog a\"b c\"d",
                           &["prog", "ab cd"]));
        assert!(test_split("prog 'hello there'",
                           &["prog", "'hello", "there'"]));
        assert!(test_split("prog \"hello\"there", &["prog", "hellothere"]));

        // Backslashes
        assert!(test_split(r"\\server\share path",
                           &[r"\\server\share", "path"]));
        assert!(test_split(r#""\\server\share path""#,
                           &[r"\\server\share path"]));
        assert!(test_split(r#"prog "\\as\\\\\df\\""#,
                           &["prog", r"\\as\\\\\df\"]));

        // Edge cases
        assert!(test_split("   ", &[]));
        assert!(test_split("prog    ", &["prog"]));
        assert!(test_split("    prog  arg  ", &["prog", "arg"]));

        assert!(test_split(r#""prog name" hello\"there"#,
                           &["prog name", "hello\"there"]));

        // Handling of whitespace characters
        assert!(test_split("prog \t hello \n there",
                           &["prog", "hello", "\n", "there"]));
        assert!(test_split("prog \t\t\thello \n\n\n there",
                           &["prog", "hello", "\n\n\n", "there"]));
        assert!(test_split("prog \t\t\thello\n\n\nthere",
                           &["prog", "hello\n\n\nthere"]));
        assert!(test_split("prog hello\tthere",
                           &["prog", "hello", "there"]));
        assert!(test_split("prog hello\t \t \t \t  there",
                           &["prog", "hello", "there"]));

        // No unicode whitespace handling.
        assert!(test_split("prog hello\u{A0}there",
                           &["prog", "hello\u{A0}there"]));

        // 2n backslashes followed by a quote produces n backslashes followed by
        // the quote.
        assert!(test_split(r#"prog "hello\\""#, &["prog", r"hello\"]));

        // 2n+1 backslashes followed by a quote produces n backslashes and
        // toggles the "in quotes" mode.
        assert!(test_split(r#"prog \\\\"in quotes\\\\""#,
                           &["prog", r"\\in quotes\\"]));
    }
}
