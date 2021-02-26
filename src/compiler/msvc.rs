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

use crate::compiler::args::*;
use crate::compiler::c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments};
use crate::compiler::{
    clang, gcc, write_temp_file, Cacheable, ColorMode, CompileCommand, CompilerArguments,
};
use crate::dist;
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::{run_input_output, SpawnExt};
use futures::future::Future;
use futures_03::executor::ThreadPool;
use local_encoding::{Encoder, Encoding};
use log::Level::Debug;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};

use crate::errors::*;

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
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::MSVC
    }
    fn plusplus(&self) -> bool {
        false
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
    ) -> CompilerArguments<ParsedArguments> {
        parse_arguments(arguments, cwd, self.is_clang)
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
            &self.includes_prefix,
            rewrite_includes_only,
            self.is_clang,
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

fn from_local_codepage(bytes: &[u8]) -> io::Result<String> {
    Encoding::OEM.to_string(bytes)
}

/// Detect the prefix included in the output of MSVC's -showIncludes output.
pub fn detect_showincludes_prefix<T>(
    creator: &T,
    exe: &OsStr,
    is_clang: bool,
    env: Vec<(OsString, OsString)>,
    pool: &ThreadPool,
) -> SFuture<String>
where
    T: CommandCreatorSync,
{
    let write = write_temp_file(pool, "test.c".as_ref(), b"#include \"test.h\"\n".to_vec());

    let exe = exe.to_os_string();
    let mut creator = creator.clone();
    let pool = pool.clone();
    let write2 = write.and_then(move |(tempdir, input)| {
        let header = tempdir.path().join("test.h");
        pool.spawn_fn(move || -> Result<_> {
            let mut file = File::create(&header)?;
            file.write_all(b"/* empty */\n")?;
            Ok((tempdir, input))
        })
        .fcontext("failed to write temporary file")
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

        let process::Output {
            stdout: stdout_bytes,
            ..
        } = output;
        let stdout = from_local_codepage(&stdout_bytes)
            .context("Failed to convert compiler stdout while detecting showIncludes prefix")?;
        for line in stdout.lines() {
            if !line.ends_with("test.h") {
                continue;
            }
            for (i, c) in line.char_indices().rev() {
                if c != ' ' {
                    continue;
                }
                let path = tempdir.path().join(&line[i + 1..]);
                // See if the rest of this line is a full pathname.
                if path.exists() {
                    // Everything from the beginning of the line
                    // to this index is the prefix.
                    return Ok(line[..=i].to_owned());
                }
            }
        }
        drop(tempdir);

        debug!(
            "failed to detect showIncludes prefix with output: {}",
            stdout
        );

        bail!("Failed to detect showIncludes prefix")
    }))
}

#[cfg(unix)]
fn encode_path(dst: &mut dyn Write, path: &Path) -> io::Result<()> {
    use std::os::unix::prelude::*;

    let bytes = path.as_os_str().as_bytes();
    dst.write_all(bytes)
}

#[cfg(windows)]
fn encode_path(dst: &mut dyn Write, path: &Path) -> io::Result<()> {
    use local_encoding::windows::wide_char_to_multi_byte;
    use std::os::windows::prelude::*;
    use winapi::um::winnls::CP_OEMCP;

    let points = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let (bytes, _) = wide_char_to_multi_byte(
        CP_OEMCP, 0, &points, None, // default_char
        false,
    )?; // use_default_char_flag
    dst.write_all(&bytes)
}

ArgData! {
    TooHardFlag,
    TooHard(OsString),
    TooHardPath(PathBuf),
    PreprocessorArgument(OsString),
    PreprocessorArgumentPath(PathBuf),
    SuppressCompilation,
    DoCompilation,
    ShowIncludes,
    Output(PathBuf),
    DepFile(PathBuf),
    ProgramDatabase(PathBuf),
    DebugInfo,
    PassThrough, // Miscellaneous flags that don't prevent caching.
    PassThroughWithPath(PathBuf), // As above, recognised by prefix.
    PassThroughWithSuffix(OsString), // As above, recognised by prefix.
    Ignore, // The flag is not passed to the compiler.
    IgnoreWithSuffix(OsString), // As above, recognized by prefix.
    ExtraHashFile(PathBuf),
    XClang(OsString), // -Xclang ...
    Clang(OsString), // -clang:...
    ExternalIncludePath(PathBuf),
}

use self::ArgData::*;

macro_rules! msvc_args {
    (static ARGS: [$t:ty; _] = [$($macro:ident ! ($($v:tt)*),)*]) => {
        counted_array!(static ARGS: [$t; _] = [$(msvc_args!(@one "-", $macro!($($v)*)),)*]);
        counted_array!(static SLASH_ARGS: [$t; _] = [$(msvc_args!(@one "/", $macro!($($v)*)),)*]);
    };
    (@one $prefix:expr, msvc_take_arg!($s:expr, $($t:tt)*)) => {
        take_arg!(concat!($prefix, $s), $($t)+)
    };
    (@one $prefix:expr, msvc_flag!($s:expr, $($t:tt)+)) => {
        flag!(concat!($prefix, $s), $($t)+)
    };
    (@one $prefix:expr, $other:expr) => { $other };
}

// Reference:
// https://docs.microsoft.com/en-us/cpp/build/reference/compiler-options-listed-alphabetically?view=vs-2019
msvc_args!(static ARGS: [ArgInfo<ArgData>; _] = [
    msvc_flag!("?", SuppressCompilation),
    msvc_flag!("C", PassThrough), // Ignored unless a preprocess-only flag is specified.
    msvc_take_arg!("D", OsString, CanBeSeparated, PreprocessorArgument),
    msvc_flag!("E", SuppressCompilation),
    msvc_take_arg!("EH", OsString, Concatenated, PassThroughWithSuffix), // /EH[acsr\-]+ - TODO: use a regex?
    msvc_flag!("EP", SuppressCompilation),
    msvc_take_arg!("F", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("FA", OsString, Concatenated, TooHard),
    msvc_flag!("FC", TooHardFlag), // Use absolute paths in error messages.
    msvc_take_arg!("FI", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    msvc_take_arg!("FR", PathBuf, Concatenated, TooHardPath),
    msvc_flag!("FS", Ignore),
    msvc_take_arg!("FU", PathBuf, CanBeSeparated, TooHardPath),
    msvc_take_arg!("Fa", PathBuf, Concatenated, TooHardPath),
    msvc_take_arg!("Fd", PathBuf, Concatenated, ProgramDatabase),
    msvc_take_arg!("Fe", PathBuf, Concatenated, TooHardPath),
    msvc_take_arg!("Fi", PathBuf, Concatenated, TooHardPath),
    msvc_take_arg!("Fm", PathBuf, Concatenated, PassThroughWithPath), // No effect if /c is specified.
    msvc_take_arg!("Fo", PathBuf, Concatenated, Output),
    msvc_take_arg!("Fp", PathBuf, Concatenated, TooHardPath),
    msvc_take_arg!("Fr", PathBuf, Concatenated, TooHardPath),
    msvc_flag!("Fx", TooHardFlag),
    msvc_flag!("GA", PassThrough),
    msvc_flag!("GF", PassThrough),
    msvc_flag!("GH", PassThrough),
    msvc_flag!("GL", PassThrough),
    msvc_flag!("GL-", PassThrough),
    msvc_flag!("GR", PassThrough),
    msvc_flag!("GR-", PassThrough),
    msvc_flag!("GS", PassThrough),
    msvc_flag!("GS-", PassThrough),
    msvc_flag!("GT", PassThrough),
    msvc_flag!("GX", PassThrough),
    msvc_flag!("GZ", PassThrough),
    msvc_flag!("Gd", PassThrough),
    msvc_flag!("Ge", PassThrough),
    msvc_flag!("Gh", PassThrough),
    msvc_flag!("Gm", TooHardFlag),
    msvc_flag!("Gr", PassThrough),
    msvc_take_arg!("Gs", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("Gv", PassThrough),
    msvc_flag!("Gw", PassThrough),
    msvc_flag!("Gw-", PassThrough),
    msvc_flag!("Gy", PassThrough),
    msvc_flag!("Gy-", PassThrough),
    msvc_flag!("Gz", PassThrough),
    msvc_take_arg!("H", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("HELP", SuppressCompilation),
    msvc_take_arg!("I", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    msvc_flag!("J", PassThrough),
    msvc_flag!("JMC", PassThrough),
    msvc_flag!("JMC-", PassThrough),
    msvc_flag!("LD", PassThrough),
    msvc_flag!("LDd", PassThrough),
    msvc_flag!("MD", PassThrough),
    msvc_flag!("MDd", PassThrough),
    msvc_take_arg!("MP", OsString, Concatenated, IgnoreWithSuffix),
    msvc_flag!("MT", PassThrough),
    msvc_flag!("MTd", PassThrough),
    msvc_flag!("O1", PassThrough),
    msvc_flag!("O2", PassThrough),
    msvc_flag!("Ob0", PassThrough),
    msvc_flag!("Ob1", PassThrough),
    msvc_flag!("Ob2", PassThrough),
    msvc_flag!("Ob3", PassThrough),
    msvc_flag!("Od", PassThrough),
    msvc_flag!("Og", PassThrough),
    msvc_flag!("Oi", PassThrough),
    msvc_flag!("Oi-", PassThrough),
    msvc_flag!("Os", PassThrough),
    msvc_flag!("Ot", PassThrough),
    msvc_flag!("Ox", PassThrough),
    msvc_flag!("Oy", PassThrough),
    msvc_flag!("Oy-", PassThrough),
    msvc_flag!("P", SuppressCompilation),
    msvc_flag!("QIfist", PassThrough),
    msvc_flag!("QIntel-jcc-erratum", PassThrough),
    msvc_flag!("Qfast_transcendentals", PassThrough),
    msvc_flag!("Qimprecise_fwaits", PassThrough),
    msvc_flag!("Qpar", PassThrough),
    msvc_flag!("Qsafe_fp_loads", PassThrough),
    msvc_flag!("Qspectre", PassThrough),
    msvc_flag!("Qspectre-load", PassThrough),
    msvc_flag!("Qspectre-load-cf", PassThrough),
    msvc_flag!("Qvec-report:1", PassThrough),
    msvc_flag!("Qvec-report:2", PassThrough),
    msvc_take_arg!("RTC", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("TC", PassThrough), // TODO: disable explicit language check, hope for the best for now? Also, handle /Tc & /Tp.
    msvc_flag!("TP", PassThrough), // As above.
    msvc_take_arg!("U", OsString, Concatenated, PreprocessorArgument),
    msvc_take_arg!("V", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("W0", PassThrough),
    msvc_flag!("W1", PassThrough),
    msvc_flag!("W2", PassThrough),
    msvc_flag!("W3", PassThrough),
    msvc_flag!("W4", PassThrough),
    msvc_flag!("WL", PassThrough),
    msvc_flag!("WX", PassThrough),
    msvc_flag!("Wall", PassThrough),
    msvc_take_arg!("Wv:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("X", PassThrough),
    msvc_take_arg!("Xclang", OsString, Separated, XClang),
    msvc_flag!("Yd", PassThrough),
    msvc_flag!("Z7", PassThrough), // Add debug info to .obj files.
    msvc_flag!("ZI", DebugInfo), // Implies /FC, which puts absolute paths in error messages -> TooHardFlag?
    msvc_flag!("ZW", PassThrough),
    msvc_flag!("Za", PassThrough),
    msvc_take_arg!("Zc:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("Ze", PassThrough),
    msvc_flag!("Zi", DebugInfo),
    msvc_flag!("Zo", PassThrough),
    msvc_flag!("Zo-", PassThrough),
    msvc_flag!("Zp1", PassThrough),
    msvc_flag!("Zp16", PassThrough),
    msvc_flag!("Zp2", PassThrough),
    msvc_flag!("Zp4", PassThrough),
    msvc_flag!("Zp8", PassThrough),
    msvc_flag!("Zs", SuppressCompilation),
    msvc_flag!("analyze-", PassThrough),
    msvc_take_arg!("analyze:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("arch:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("await", PassThrough),
    msvc_flag!("bigobj", PassThrough),
    msvc_flag!("c", DoCompilation),
    msvc_take_arg!("cgthreads", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("clang:", OsString, Concatenated, Clang),
    msvc_flag!("clr", PassThrough),
    msvc_take_arg!("clr:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("constexpr:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("deps", PathBuf, Concatenated, DepFile),
    msvc_take_arg!("diagnostics:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("doc", PathBuf, Concatenated, TooHardPath), // Creates an .xdc file.
    msvc_take_arg!("errorReport:", OsString, Concatenated, PassThroughWithSuffix), // Deprecated.
    msvc_take_arg!("execution-charset:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("experimental:module", TooHardFlag),
    msvc_flag!("experimental:module-", PassThrough), // Explicitly disabled modules.
    msvc_take_arg!("experimental:preprocessor", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("external:I", PathBuf, CanBeSeparated, ExternalIncludePath),
    msvc_take_arg!("favor:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("fp:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("fsanitize-blacklist", PathBuf, Concatenated('='), ExtraHashFile),
    msvc_flag!("fsyntax-only", SuppressCompilation),
    msvc_take_arg!("guard:cf", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("homeparams", PassThrough),
    msvc_flag!("hotpatch", PassThrough),
    msvc_flag!("kernel", PassThrough),
    msvc_flag!("kernel-", PassThrough),
    msvc_flag!("nologo", PassThrough),
    msvc_take_arg!("o", PathBuf, Separated, Output), // Deprecated but valid
    msvc_flag!("openmp", PassThrough),
    msvc_flag!("openmp:experimental", PassThrough),
    msvc_flag!("permissive-", PassThrough),
    msvc_flag!("sdl", PassThrough),
    msvc_flag!("sdl-", PassThrough),
    msvc_flag!("showIncludes", ShowIncludes),
    msvc_take_arg!("source-charset:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("std:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("u", PassThrough),
    msvc_flag!("utf-8", PassThrough),
    msvc_flag!("validate-charset", PassThrough),
    msvc_flag!("validate-charset-", PassThrough),
    msvc_flag!("vd0", PassThrough),
    msvc_flag!("vd1", PassThrough),
    msvc_flag!("vd2", PassThrough),
    msvc_flag!("vmb", PassThrough),
    msvc_flag!("vmg", PassThrough),
    msvc_flag!("vmm", PassThrough),
    msvc_flag!("vms", PassThrough),
    msvc_flag!("vmv", PassThrough),
    msvc_flag!("volatile:iso", PassThrough),
    msvc_flag!("volatile:ms", PassThrough),
    msvc_flag!("w", PassThrough),
    msvc_take_arg!("w1", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("w2", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("w3", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("w4", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("wd", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("we", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("wo", OsString, Concatenated, PassThroughWithSuffix),
    take_arg!("@", PathBuf, Concatenated, TooHardPath),
]);

// TODO: what do do with precompiled header flags? eg: /Y-, /Yc, /YI, /Yu, /Zf, /ZH, /Zm

pub fn parse_arguments(
    arguments: &[OsString],
    cwd: &Path,
    is_clang: bool,
) -> CompilerArguments<ParsedArguments> {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut common_args = vec![];
    let mut preprocessor_args = vec![];
    let mut dependency_args = vec![];
    let mut extra_hash_files = vec![];
    let mut compilation = false;
    let mut compilation_flag = OsString::new();
    let mut debug_info = false;
    let mut pdb = None;
    let mut depfile = None;
    let mut show_includes = false;
    let mut xclangs: Vec<OsString> = vec![];
    let mut clangs: Vec<OsString> = vec![];
    let mut profile_generate = false;

    for arg in ArgsIter::new(arguments.iter().cloned(), (&ARGS[..], &SLASH_ARGS[..])) {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        match arg.get_data() {
            Some(PassThrough) | Some(PassThroughWithPath(_)) | Some(PassThroughWithSuffix(_)) => {}
            Some(TooHardFlag) | Some(TooHard(_)) | Some(TooHardPath(_)) => {
                cannot_cache!(arg.flag_str().expect("Can't be Argument::Raw/UnknownFlag",))
            }
            Some(DoCompilation) => {
                compilation = true;
                compilation_flag =
                    OsString::from(arg.flag_str().expect("Compilation flag expected"));
            }
            Some(ShowIncludes) => {
                show_includes = true;
                dependency_args.push(arg.to_os_string());
            }
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
            Some(PreprocessorArgument(_))
            | Some(PreprocessorArgumentPath(_))
            | Some(ExtraHashFile(_))
            | Some(Ignore)
            | Some(IgnoreWithSuffix(_))
            | Some(ExternalIncludePath(_)) => {}
            Some(SuppressCompilation) => {
                return CompilerArguments::NotCompilation;
            }
            Some(XClang(s)) => xclangs.push(s.clone()),
            Some(Clang(s)) => clangs.push(s.clone()),
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
            Some(PreprocessorArgument(_)) | Some(PreprocessorArgumentPath(_)) => preprocessor_args
                .extend(
                    arg.normalize(NormalizedDisposition::Concatenated)
                        .iter_os_strings(),
                ),
            Some(ProgramDatabase(_))
            | Some(DebugInfo)
            | Some(PassThrough)
            | Some(PassThroughWithPath(_))
            | Some(PassThroughWithSuffix(_)) => common_args.extend(
                arg.normalize(NormalizedDisposition::Concatenated)
                    .iter_os_strings(),
            ),
            Some(ExtraHashFile(path)) => {
                extra_hash_files.push(cwd.join(path));
                common_args.extend(
                    arg.normalize(NormalizedDisposition::Concatenated)
                        .iter_os_strings(),
                )
            }
            Some(ExternalIncludePath(_)) => common_args.extend(
                arg.normalize(NormalizedDisposition::Separated)
                    .iter_os_strings(),
            ),
            // We ignore -MP and -FS and never pass them down to the compiler.
            //
            // -MP tells the compiler to build with multiple processes and is used
            // to spread multiple compilations when there are multiple inputs.
            // Either we have multiple inputs on the command line, and we're going
            // to bail out and not cache, or -MP is not going to be useful.
            // -MP also implies -FS.
            //
            // -FS forces synchronous access to PDB files via a MSPDBSRV process.
            // This option is only useful when multiple compiler invocations are going
            // to share the same PDB file, which is not supported by sccache. So either
            // -Fd was passed with a pdb that is not shared and sccache is going to
            // handle the compile, in which case -FS is not needed, or -Fd was not passed
            // and we're going to bail out and not cache.
            //
            // In both cases, the flag is not going to be useful if we are going to cache,
            // so we just skip them entirely. -FS may also have a side effect of creating
            // race conditions in which we may try to read the PDB before MSPDBSRC is done
            // writing it, so we're better off ignoring the flags.
            Some(Ignore) | Some(IgnoreWithSuffix(_)) => {}
            _ => {}
        }
    }

    // TODO: doing this here reorders the arguments, hopefully that doesn't affect the meaning
    fn xclang_append(arg: OsString, args: &mut Vec<OsString>) {
        args.push("-Xclang".into());
        args.push(arg);
    }

    fn dash_clang_append(arg: OsString, args: &mut Vec<OsString>) {
        let mut a = OsString::from("-clang:");
        a.push(arg);
        args.push(a);
    }

    for (args, append_fn) in Iterator::zip(
        [xclangs, clangs].iter(),
        &[xclang_append, dash_clang_append],
    ) {
        let it = gcc::ExpandIncludeFile::new(cwd, args);
        for arg in ArgsIter::new(it, (&gcc::ARGS[..], &clang::ARGS[..])) {
            let arg = try_or_cannot_cache!(arg, "argument parse");
            // Eagerly bail if it looks like we need to do more complicated work
            use crate::compiler::gcc::ArgData::*;
            let mut args = match arg.get_data() {
                Some(SplitDwarf) | Some(TestCoverage) | Some(Coverage) | Some(DoCompilation)
                | Some(Language(_)) | Some(Output(_)) | Some(TooHardFlag) | Some(XClang(_))
                | Some(TooHard(_)) => cannot_cache!(arg
                    .flag_str()
                    .unwrap_or("Can't handle complex arguments through clang",)),
                None => match arg {
                    Argument::Raw(_) | Argument::UnknownFlag(_) => &mut common_args,
                    _ => unreachable!(),
                },
                Some(DiagnosticsColor(_))
                | Some(DiagnosticsColorFlag)
                | Some(NoDiagnosticsColorFlag)
                | Some(Arch(_))
                | Some(PassThrough(_))
                | Some(PassThroughPath(_)) => &mut common_args,

                Some(ProfileGenerate) => {
                    profile_generate = true;
                    &mut common_args
                }
                Some(ExtraHashFile(path)) => {
                    extra_hash_files.push(cwd.join(path));
                    &mut common_args
                }
                Some(PreprocessorArgumentFlag)
                | Some(PreprocessorArgument(_))
                | Some(PreprocessorArgumentPath(_)) => &mut preprocessor_args,
                Some(DepArgumentPath(_)) | Some(DepTarget(_)) | Some(NeedDepTarget) => {
                    &mut dependency_args
                }
            };
            // Normalize attributes such as "-I foo", "-D FOO=bar", as
            // "-Ifoo", "-DFOO=bar", etc. and "-includefoo", "idirafterbar" as
            // "-include foo", "-idirafter bar", etc.
            let norm = match arg.flag_str() {
                Some(s) if s.len() == 2 => NormalizedDisposition::Concatenated,
                _ => NormalizedDisposition::Separated,
            };
            for arg in arg.normalize(norm).iter_os_strings() {
                append_fn(arg, &mut args);
            }
        }
    }

    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    let (input, language) = match input_arg {
        Some(i) => match Language::from_file_name(Path::new(&i)) {
            Some(l) => (i.to_owned(), l),
            None => cannot_cache!("unknown source language"),
        },
        // We can't cache compilation without an input.
        None => cannot_cache!("no input file"),
    };
    let mut outputs = HashMap::new();
    match output_arg {
        // If output file name is not given, use default naming rule
        None => {
            outputs.insert("obj", Path::new(&input).with_extension("obj"));
        }
        Some(o) => {
            outputs.insert("obj", o);
        }
    }
    // -Fd is not taken into account unless -Zi or -ZI are given
    // Clang is currently unable to generate PDB files
    if debug_info && !is_clang {
        match pdb {
            Some(p) => outputs.insert("pdb", p),
            None => {
                // -Zi and -ZI without -Fd defaults to vcxxx.pdb (where xxx depends on the
                // MSVC version), and that's used for all compilations with the same
                // working directory. We can't cache such a pdb.
                cannot_cache!("shared pdb");
            }
        };
    }

    CompilerArguments::Ok(ParsedArguments {
        input: input.into(),
        language,
        compilation_flag,
        depfile,
        outputs,
        dependency_args,
        preprocessor_args,
        common_args,
        extra_hash_files,
        msvc_show_includes: show_includes,
        profile_generate,
        // FIXME: implement color_mode for msvc.
        color_mode: ColorMode::Auto,
    })
}

#[cfg(windows)]
fn normpath(path: &str) -> String {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use winapi::um::fileapi::GetFinalPathNameByHandleW;
    File::open(path)
        .and_then(|f| {
            let handle = f.as_raw_handle();
            let size = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, 0) };
            if size == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut wchars = vec![0; size as usize];
            if unsafe {
                GetFinalPathNameByHandleW(handle, wchars.as_mut_ptr(), wchars.len() as u32, 0)
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // The return value of GetFinalPathNameByHandleW uses the
            // '\\?\' prefix.
            let o = OsString::from_wide(&wchars[4..wchars.len() - 1]);
            o.into_string()
                .map(|s| s.replace('\\', "/"))
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error converting string"))
        })
        .unwrap_or_else(|_| path.replace('\\', "/"))
}

#[cfg(not(windows))]
fn normpath(path: &str) -> String {
    path.to_owned()
}

#[allow(clippy::too_many_arguments)]
pub fn preprocess<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    may_dist: bool,
    includes_prefix: &str,
    rewrite_includes_only: bool,
    is_clang: bool,
) -> SFuture<process::Output>
where
    T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);

    // When performing distributed compilation, line number info is important for error
    // reporting and to not cause spurious compilation failure (e.g. no exceptions build
    // fails due to exceptions transitively included in the stdlib).
    // With -fprofile-generate line number information is important, so use -E.
    // Otherwise, use -EP to maximize cache hits (because no absolute file paths are
    // emitted) and improve performance.
    if may_dist || parsed_args.profile_generate {
        cmd.arg("-E");
    } else {
        cmd.arg("-EP");
    }

    cmd.arg(&parsed_args.input)
        .arg("-nologo")
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.dependency_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(&cwd);
    if parsed_args.depfile.is_some() && !parsed_args.msvc_show_includes {
        cmd.arg("-showIncludes");
    }
    if rewrite_includes_only && is_clang {
        cmd.arg("-clang:-frewrite-includes");
    }

    if log_enabled!(Debug) {
        debug!("preprocess: {:?}", cmd);
    }

    let parsed_args = parsed_args.clone();
    let includes_prefix = includes_prefix.to_string();
    let cwd = cwd.to_owned();

    Box::new(run_input_output(cmd, None).and_then(move |output| {
        let parsed_args = &parsed_args;
        if let (Some(ref objfile), &Some(ref depfile)) =
            (parsed_args.outputs.get("obj"), &parsed_args.depfile)
        {
            let f = File::create(cwd.join(depfile))?;
            let mut f = BufWriter::new(f);

            encode_path(&mut f, &objfile)
                .with_context(|| format!("Couldn't encode objfile filename: '{:?}'", objfile))?;
            write!(f, ": ")?;
            encode_path(&mut f, &parsed_args.input)
                .with_context(|| format!("Couldn't encode input filename: '{:?}'", objfile))?;
            write!(f, " ")?;
            let process::Output {
                status,
                stdout,
                stderr: stderr_bytes,
            } = output;
            let stderr = from_local_codepage(&stderr_bytes)
                .context("Failed to convert preprocessor stderr")?;
            let mut deps = HashSet::new();
            let mut stderr_bytes = vec![];
            for line in stderr.lines() {
                if line.starts_with(&includes_prefix) {
                    let dep = normpath(line[includes_prefix.len()..].trim());
                    trace!("included: {}", dep);
                    if deps.insert(dep.clone()) && !dep.contains(' ') {
                        write!(f, "{} ", dep)?;
                    }
                    if !parsed_args.msvc_show_includes {
                        continue;
                    }
                }
                stderr_bytes.extend_from_slice(line.as_bytes());
                stderr_bytes.push(b'\n');
            }
            writeln!(f)?;
            // Write extra rules for each dependency to handle
            // removed files.
            encode_path(&mut f, &parsed_args.input)
                .with_context(|| format!("Couldn't encode filename: '{:?}'", parsed_args.input))?;
            writeln!(f, ":")?;
            let mut sorted = deps.into_iter().collect::<Vec<_>>();
            sorted.sort();
            for dep in sorted {
                if !dep.contains(' ') {
                    writeln!(f, "{}:", dep)?;
                }
            }
            Ok(process::Output {
                status,
                stdout,
                stderr: stderr_bytes,
            })
        } else {
            Ok(output)
        }
    }))
}

fn generate_compile_commands(
    path_transformer: &mut dist::PathTransformer,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
    #[cfg(not(feature = "dist-client"))]
    let _ = path_transformer;

    trace!("compile");
    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => bail!("Missing object file output"),
    };

    // See if this compilation will produce a PDB.
    let cacheable = parsed_args
        .outputs
        .get("pdb")
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
        parsed_args.compilation_flag.clone(),
        parsed_args.input.clone().into(),
        fo,
    ];
    arguments.extend(parsed_args.preprocessor_args.clone());
    arguments.extend(parsed_args.dependency_args.clone());
    arguments.extend(parsed_args.common_args.clone());

    let command = CompileCommand {
        executable: executable.to_owned(),
        arguments,
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
        fo.push_str(&path_transformer.as_dist(out_file)?);

        let mut arguments: Vec<String> = vec![
            parsed_args.compilation_flag.clone().into_string().ok()?,
            path_transformer.as_dist(&parsed_args.input)?,
            fo,
        ];
        // It's important to avoid preprocessor_args because of things like /FI which
        // forcibly includes another file. This does mean we're potentially vulnerable
        // to misidentification of flags like -DYNAMICBASE (though in that specific
        // case we're safe as it only applies to link time, which sccache avoids).
        arguments.extend(dist::osstrings_to_strings(&parsed_args.common_args)?);

        Some(dist::CompileCommand {
            executable: path_transformer.as_dist(&executable)?,
            arguments,
            env_vars: dist::osstring_tuples_to_strings(env_vars)?,
            cwd: path_transformer.as_dist(cwd)?,
        })
    })();

    Ok((command, dist_command, cacheable))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::*;
    use crate::mock_command::*;
    use crate::test::utils::*;
    use futures::Future;
    use futures_03::executor::ThreadPool;

    fn parse_arguments(arguments: Vec<OsString>) -> CompilerArguments<ParsedArguments> {
        super::parse_arguments(&arguments, &std::env::current_dir().unwrap(), false)
    }

    #[test]
    fn test_detect_showincludes_prefix() {
        drop(env_logger::try_init());
        let creator = new_creator();
        let pool = ThreadPool::sized(1);
        let f = TestFixture::new();
        let srcfile = f.touch("test.h").unwrap();
        let mut s = srcfile.to_str().unwrap();
        if s.starts_with("\\\\?\\") {
            s = &s[4..];
        }
        let stdout = format!("blah: {}\r\n", s);
        let stderr = String::from("some\r\nstderr\r\n");
        next_command(
            &creator,
            Ok(MockChild::new(exit_status(0), &stdout, &stderr)),
        );
        assert_eq!(
            "blah: ",
            detect_showincludes_prefix(&creator, "cl.exe".as_ref(), false, Vec::new(), &pool)
                .wait()
                .unwrap()
        );
    }

    #[test]
    fn test_parse_arguments_simple() {
        let args = ovec!["-c", "foo.c", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            compilation_flag,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_eq!(Some("-c"), compilation_flag.to_str());
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_compile_flag() {
        let args = ovec!["/c", "foo.c", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            compilation_flag,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_eq!(Some("/c"), compilation_flag.to_str());
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
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
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
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
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_clang_passthrough() {
        let args = ovec![
            "-Fohost_dictionary.obj",
            "-c",
            "-Xclang",
            "-MP",
            "-Xclang",
            "-dependency-file",
            "-Xclang",
            ".deps/host_dictionary.obj.pp",
            "-Xclang",
            "-MT",
            "-Xclang",
            "host_dictionary.obj",
            "-clang:-fprofile-generate",
            "dictionary.c"
        ];
        let ParsedArguments {
            dependency_args,
            preprocessor_args,
            common_args,
            profile_generate,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert!(profile_generate);
        assert!(preprocessor_args.is_empty());
        assert_eq!(
            dependency_args,
            ovec!(
                "-Xclang",
                "-MP",
                "-Xclang",
                "-dependency-file",
                "-Xclang",
                ".deps/host_dictionary.obj.pp",
                "-Xclang",
                "-MT",
                "-Xclang",
                "host_dictionary.obj"
            )
        );
        assert_eq!(common_args, ovec!("-clang:-fprofile-generate"));
    }

    #[test]
    fn test_parse_arguments_extra() {
        let args = ovec!["-c", "foo.c", "-foo", "-Fofoo.obj", "-bar"];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
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
            outputs,
            preprocessor_args,
            dependency_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        assert_eq!(preprocessor_args, ovec!["-FIfile"]);
        assert_eq!(dependency_args, ovec!["/showIncludes"]);
        assert!(common_args.is_empty());
        assert!(msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_pdb() {
        let args = ovec!["-c", "foo.c", "-Zi", "-Fdfoo.pdb", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            ("obj", PathBuf::from("foo.obj")),
            ("pdb", PathBuf::from("foo.pdb"))
        );
        assert!(preprocessor_args.is_empty());
        assert_eq!(common_args, ovec!["-Zi", "-Fdfoo.pdb"]);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_external_include() {
        // Parsing -external:I relies on -experimental:external being parsed
        // and placed into common_args.
        let args = ovec![
            "-c",
            "foo.c",
            "-Fofoo.obj",
            "-experimental:external",
            "-external:templates-",
            "-external:I",
            "path/to/system/includes"
        ];
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(outputs, ("obj", PathBuf::from("foo.obj")));
        assert_eq!(1, outputs.len());
        assert!(preprocessor_args.is_empty());
        assert_eq!(
            common_args,
            ovec![
                "-experimental:external",
                "-external:templates-",
                "-external:I",
                "path/to/system/includes"
            ]
        );
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_empty_args() {
        assert_eq!(CompilerArguments::NotCompilation, parse_arguments(vec!()));
    }

    #[test]
    fn test_parse_arguments_not_compile() {
        assert_eq!(
            CompilerArguments::NotCompilation,
            parse_arguments(ovec!["-Fofoo", "foo.c"])
        );
    }

    #[test]
    fn test_parse_arguments_passthrough() {
        let args = ovec![
            "-Oy",
            "-Gw",
            "-EHa",
            "-Fmdictionary-map",
            "-c",
            "-Fohost_dictionary.obj",
            "dictionary.c"
        ];
        let ParsedArguments {
            input,
            common_args,
            dependency_args,
            preprocessor_args,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("dictionary.c"), input.to_str());
        assert!(preprocessor_args.is_empty());
        assert!(dependency_args.is_empty());
        assert!(!common_args.is_empty());
        assert_eq!(
            common_args,
            ovec!("-Oy", "-Gw", "-EHa", "-Fmdictionary-map")
        );
    }

    #[test]
    fn test_parse_arguments_too_many_inputs() {
        assert_eq!(
            CompilerArguments::CannotCache("multiple input files", None),
            parse_arguments(ovec!["-c", "foo.c", "-Fofoo.obj", "bar.c"])
        );
    }

    #[test]
    fn test_parse_arguments_unsupported() {
        assert_eq!(
            CompilerArguments::CannotCache("-FA", None),
            parse_arguments(ovec!["-c", "foo.c", "-Fofoo.obj", "-FA"])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-Fa", None),
            parse_arguments(ovec!["-Fa", "-c", "foo.c", "-Fofoo.obj"])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-FR", None),
            parse_arguments(ovec!["-c", "foo.c", "-FR", "-Fofoo.obj"])
        );
    }

    #[test]
    fn test_parse_arguments_response_file() {
        assert_eq!(
            CompilerArguments::CannotCache("@", None),
            parse_arguments(ovec!["-c", "foo.c", "@foo", "-Fofoo.obj"])
        );
    }

    #[test]
    fn test_parse_arguments_missing_pdb() {
        assert_eq!(
            CompilerArguments::CannotCache("shared pdb", None),
            parse_arguments(ovec!["-c", "foo.c", "-Zi", "-Fofoo.obj"])
        );
    }

    #[test]
    fn test_parse_arguments_missing_edit_and_continue_pdb() {
        assert_eq!(
            CompilerArguments::CannotCache("shared pdb", None),
            parse_arguments(ovec!["-c", "foo.c", "-ZI", "-Fofoo.obj"])
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
            outputs: vec![("obj", "foo.obj".into())].into_iter().collect(),
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
        let (command, dist_command, cacheable) = generate_compile_commands(
            &mut path_transformer,
            &compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
        )
        .unwrap();
        #[cfg(feature = "dist-client")]
        assert!(dist_command.is_some());
        #[cfg(not(feature = "dist-client"))]
        assert!(dist_command.is_none());
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
            compilation_flag: "/c".into(),
            depfile: None,
            outputs: vec![("obj", "foo.obj".into()), ("pdb", pdb)]
                .into_iter()
                .collect(),
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
        let (command, dist_command, cacheable) = generate_compile_commands(
            &mut path_transformer,
            &compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
        )
        .unwrap();
        #[cfg(feature = "dist-client")]
        assert!(dist_command.is_some());
        #[cfg(not(feature = "dist-client"))]
        assert!(dist_command.is_none());
        let _ = command.execute(&creator).wait();
        assert_eq!(Cacheable::No, cacheable);
        // Ensure that we ran all processes.
        assert_eq!(0, creator.lock().unwrap().children.len());
    }

    #[test]
    fn test_parse_fsanitize_blacklist() {
        let args = ovec![
            "-c",
            "foo.c",
            "-o",
            "foo.o",
            "-fsanitize-blacklist=list.txt"
        ];
        let ParsedArguments {
            common_args,
            extra_hash_files,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(ovec!["-fsanitize-blacklist=list.txt"], common_args);
        assert_eq!(
            ovec![std::env::current_dir().unwrap().join("list.txt")],
            extra_hash_files
        );
    }
}
