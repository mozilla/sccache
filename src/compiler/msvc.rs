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
use crate::compiler::c::{ArtifactDescriptor, CCompilerImpl, CCompilerKind, ParsedArguments};
use crate::compiler::{
    clang, gcc, write_temp_file, Cacheable, ColorMode, CompileCommand, CompilerArguments, Language,
};
use crate::mock_command::{CommandCreatorSync, RunCommand};
use crate::util::{encode_path, run_input_output, OsStrExt};
use crate::{counted_array, dist};
use async_trait::async_trait;
use fs::File;
use fs_err as fs;
use log::Level::Debug;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};

use crate::errors::*;

/// A struct on which to implement `CCompilerImpl`.
///
/// Needs a little bit of state just to persist `includes_prefix`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Msvc {
    /// The prefix used in the output of `-showIncludes`.
    pub includes_prefix: String,
    pub is_clang: bool,
    pub version: Option<String>,
}

#[async_trait]
impl CCompilerImpl for Msvc {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::Msvc
    }
    fn plusplus(&self) -> bool {
        false
    }
    fn version(&self) -> Option<String> {
        self.version.clone()
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
    ) -> CompilerArguments<ParsedArguments> {
        parse_arguments(arguments, cwd, self.is_clang)
    }

    #[allow(clippy::too_many_arguments)]
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
            &self.includes_prefix,
            rewrite_includes_only,
            self.is_clang,
        )
        .await
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

#[cfg(not(windows))]
fn from_local_codepage(multi_byte_str: &[u8]) -> io::Result<String> {
    String::from_utf8(multi_byte_str.to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

#[cfg(windows)]
pub fn from_local_codepage(multi_byte_str: &[u8]) -> io::Result<String> {
    use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP, MB_ERR_INVALID_CHARS};

    let codepage = CP_OEMCP;
    let flags = MB_ERR_INVALID_CHARS;

    // Empty string
    if multi_byte_str.is_empty() {
        return Ok(String::new());
    }
    unsafe {
        // Get length of UTF-16 string
        let len = MultiByteToWideChar(
            codepage,
            flags,
            multi_byte_str.as_ptr() as _,
            multi_byte_str.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if len > 0 {
            // Convert to UTF-16
            let mut wstr: Vec<u16> = Vec::with_capacity(len as usize);
            let len = MultiByteToWideChar(
                codepage,
                flags,
                multi_byte_str.as_ptr() as _,
                multi_byte_str.len() as i32,
                wstr.as_mut_ptr() as _,
                len,
            );
            if len > 0 {
                // wstr's contents have now been initialized
                wstr.set_len(len as usize);
                return String::from_utf16(&wstr[0..(len as usize)])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e));
            }
        }
        Err(io::Error::last_os_error())
    }
}

/// Detect the prefix included in the output of MSVC's -showIncludes output.
pub async fn detect_showincludes_prefix<T>(
    creator: &T,
    exe: &OsStr,
    is_clang: bool,
    env: Vec<(OsString, OsString)>,
    pool: &tokio::runtime::Handle,
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let (tempdir, input) =
        write_temp_file(pool, "test.c".as_ref(), b"#include \"test.h\"\n".to_vec()).await?;

    let exe = exe.to_os_string();
    let mut creator = creator.clone();
    let pool = pool.clone();

    let header = tempdir.path().join("test.h");
    let tempdir = pool
        .spawn_blocking(move || {
            let mut file = File::create(&header)?;
            file.write_all(b"/* empty */\n")?;
            Ok::<_, std::io::Error>(tempdir)
        })
        .await?
        .context("Failed to write temporary file")?;

    let mut cmd = creator.new_command_sync(&exe);
    // clang.exe on Windows reports the same set of built-in preprocessor defines as clang-cl,
    // but it doesn't accept MSVC commandline arguments unless you pass --driver-mode=cl.
    // clang-cl.exe will accept this argument as well, so always add it in this case.
    if is_clang {
        cmd.arg("--driver-mode=cl");
    }
    cmd.args(&["-nologo", "-showIncludes", "-c", "-Fonul", "-I."])
        .arg(&input)
        .current_dir(tempdir.path())
        // The MSDN docs say the -showIncludes output goes to stderr,
        // but that's not true unless running with -E.
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    trace!("detect_showincludes_prefix: {:?}", cmd);

    let output = run_input_output(cmd, None).await?;

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
    msvc_flag!("Brepro", PassThrough),
    msvc_flag!("C", PassThrough), // Ignored unless a preprocess-only flag is specified.
    msvc_take_arg!("D", OsString, CanBeSeparated, PreprocessorArgument),
    msvc_flag!("E", SuppressCompilation),
    msvc_take_arg!("EH", OsString, Concatenated, PassThroughWithSuffix), // /EH[acsr\-]+ - TODO: use a regex?
    msvc_flag!("EP", SuppressCompilation),
    msvc_take_arg!("F", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("FA", OsString, Concatenated, TooHard),
    msvc_flag!("FC", PassThrough), // Use absolute paths in error messages, does not affect caching, only the debug output of the build
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
    msvc_take_arg!("Fp", PathBuf, Concatenated, TooHardPath), // allows users to specify the name for a PCH (when using /Yu or /Yc), PCHs are not supported in sccache.
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
    msvc_flag!("Gm", TooHardFlag), // enable minimal rebuild, we do not support this
    msvc_flag!("Gm-", PassThrough), // disable minimal rebuild; we prefer no minimal rebuild, so marking it as disabled is fine
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
    msvc_flag!("Qpar-", PassThrough),
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
    msvc_flag!("WX-", PassThrough),
    msvc_flag!("Wall", PassThrough),
    msvc_take_arg!("Wv:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("X", PassThrough),
    msvc_take_arg!("Xclang", OsString, Separated, XClang),
    msvc_take_arg!("Yc", PathBuf, Concatenated, TooHardPath), // Compile PCH - not yet supported.
    msvc_flag!("Yd", PassThrough),
    msvc_flag!("Z7", PassThrough), // Add debug info to .obj files.
    msvc_take_arg!("ZH:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("ZI", DebugInfo), // Implies /FC, which puts absolute paths in error messages -> TooHardFlag?
    msvc_flag!("ZW", PassThrough),
    msvc_flag!("Za", PassThrough),
    msvc_take_arg!("Zc:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("Ze", PassThrough),
    msvc_flag!("Zi", DebugInfo),
    msvc_take_arg!("Zm", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("Zo", PassThrough),
    msvc_flag!("Zo-", PassThrough),
    msvc_flag!("Zp1", PassThrough),
    msvc_flag!("Zp16", PassThrough),
    msvc_flag!("Zp2", PassThrough),
    msvc_flag!("Zp4", PassThrough),
    msvc_flag!("Zp8", PassThrough),
    msvc_flag!("Zs", SuppressCompilation),
    msvc_flag!("analyze", PassThrough),
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
    msvc_flag!("experimental:deterministic", PassThrough),
    msvc_flag!("experimental:external", PassThrough),
    msvc_flag!("experimental:module", TooHardFlag),
    msvc_flag!("experimental:module-", PassThrough), // Explicitly disabled modules.
    msvc_take_arg!("experimental:preprocessor", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("external:I", PathBuf, CanBeSeparated, ExternalIncludePath),
    msvc_flag!("external:W0", PassThrough),
    msvc_flag!("external:W1", PassThrough),
    msvc_flag!("external:W2", PassThrough),
    msvc_flag!("external:W3", PassThrough),
    msvc_flag!("external:W4", PassThrough),
    msvc_flag!("external:anglebrackets", PassThrough),
    msvc_take_arg!("favor:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("fp:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("fsanitize-blacklist", PathBuf, Concatenated('='), ExtraHashFile),
    msvc_flag!("fsanitize=address", PassThrough),
    msvc_flag!("fsyntax-only", SuppressCompilation),
    msvc_take_arg!("guard:cf", OsString, Concatenated, PassThroughWithSuffix),
    msvc_flag!("homeparams", PassThrough),
    msvc_flag!("hotpatch", PassThrough),
    msvc_take_arg!("imsvc", PathBuf, CanBeSeparated, PreprocessorArgumentPath),
    msvc_flag!("kernel", PassThrough),
    msvc_flag!("kernel-", PassThrough),
    msvc_flag!("nologo", PassThrough),
    msvc_take_arg!("o", PathBuf, Separated, Output), // Deprecated but valid
    msvc_flag!("openmp", PassThrough),
    msvc_flag!("openmp-", PassThrough),
    msvc_flag!("openmp:experimental", PassThrough),
    msvc_flag!("permissive", PassThrough),
    msvc_flag!("permissive-", PassThrough),
    msvc_flag!("sdl", PassThrough),
    msvc_flag!("sdl-", PassThrough),
    msvc_flag!("showIncludes", ShowIncludes),
    msvc_take_arg!("source-charset:", OsString, Concatenated, PassThroughWithSuffix),
    msvc_take_arg!("sourceDependencies", PathBuf, CanBeSeparated, DepFile),
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
    msvc_take_arg!("winsysroot", PathBuf, CanBeSeparated, PassThroughWithPath),
    msvc_take_arg!("wo", OsString, Concatenated, PassThroughWithSuffix),
    take_arg!("@", PathBuf, Concatenated, TooHardPath),
]);

// TODO: what do do with precompiled header flags? eg: /Y-, /Yc, /YI, /Yu, /Zf, /Zm

pub fn parse_arguments(
    arguments: &[OsString],
    cwd: &Path,
    is_clang: bool,
) -> CompilerArguments<ParsedArguments> {
    let mut output_arg = None;
    let mut input_arg = None;
    let mut double_dash_input = false;
    let mut common_args = vec![];
    let mut unhashed_args = vec![];
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
    let mut multiple_input = false;
    let mut multiple_input_files = Vec::new();

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let it = ExpandIncludeFile::new(cwd, arguments);
    let mut it = ArgsIter::new(it, (&ARGS[..], &SLASH_ARGS[..]));
    if is_clang {
        it = it.with_double_dashes();
    }
    for arg in it {
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
                    Argument::Raw(ref val) if val == "--" => {
                        if input_arg.is_none() {
                            double_dash_input = true;
                        }
                    }
                    Argument::Raw(ref val) => {
                        if input_arg.is_some() {
                            // Can't cache compilations with multiple inputs.
                            multiple_input = true;
                            multiple_input_files.push(val.clone());
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
            let args = match arg.get_data() {
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
                | Some(PassThroughFlag)
                | Some(PassThrough(_))
                | Some(PassThroughPath(_))
                | Some(PedanticFlag)
                | Some(Standard(_)) => &mut common_args,
                Some(Unhashed(_)) => &mut unhashed_args,

                Some(ProfileGenerate) => {
                    profile_generate = true;
                    &mut common_args
                }

                Some(ClangProfileUse(path)) => {
                    extra_hash_files.push(clang::resolve_profile_use_path(path, cwd));
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
                append_fn(arg, args);
            }
        }
    }

    // We only support compilation.
    if !compilation {
        return CompilerArguments::NotCompilation;
    }
    // Can't cache compilations with multiple inputs.
    if multiple_input {
        cannot_cache!(
            "multiple input files",
            format!("{:?}", multiple_input_files)
        );
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
            outputs.insert(
                "obj",
                ArtifactDescriptor {
                    path: Path::new(&input).with_extension("obj"),
                    optional: false,
                },
            );
        }
        Some(o) => {
            if o.extension().is_none() && compilation {
                outputs.insert(
                    "obj",
                    ArtifactDescriptor {
                        path: o.with_extension("obj"),
                        optional: false,
                    },
                );
            } else {
                outputs.insert(
                    "obj",
                    ArtifactDescriptor {
                        path: o,
                        optional: false,
                    },
                );
            }
        }
    }
    if language == Language::Cxx {
        if let Some(obj) = outputs.get("obj") {
            // MSVC can produce "type library headers"[1], with the extensions "tlh" and "tli".
            // These files can be used in later compilation steps to interact with COM interfaces.
            //
            // These files are only created when the `#import` directive is used.
            // Figuring out if an import directive is used would require parsing C++, which would be a lot of work.
            // To avoid that problem, we just optionally cache these headers if they happen to be produced.
            // This isn't perfect, but it is easy!
            //
            // [1]: https://learn.microsoft.com/en-us/cpp/preprocessor/hash-import-directive-cpp?view=msvc-170#_predir_the_23import_directive_header_files_created_by_import
            let tlh = obj.path.with_extension("tlh");
            let tli = obj.path.with_extension("tli");

            // Primary type library header
            outputs.insert(
                "tlh",
                ArtifactDescriptor {
                    path: tlh,
                    optional: true,
                },
            );

            // Secondary type library header
            outputs.insert(
                "tli",
                ArtifactDescriptor {
                    path: tli,
                    optional: true,
                },
            );
        }
    }
    // -Fd is not taken into account unless -Zi or -ZI are given
    // Clang is currently unable to generate PDB files
    if debug_info && !is_clang {
        match pdb {
            Some(p) => outputs.insert(
                "pdb",
                ArtifactDescriptor {
                    path: p,
                    optional: false,
                },
            ),
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
        double_dash_input,
        language,
        compilation_flag,
        depfile,
        outputs,
        dependency_args,
        preprocessor_args,
        common_args,
        arch_args: vec![],
        unhashed_args,
        extra_hash_files,
        msvc_show_includes: show_includes,
        profile_generate,
        // FIXME: implement color_mode for msvc.
        color_mode: ColorMode::Auto,
        suppress_rewrite_includes_only: false,
        too_hard_for_preprocessor_cache_mode: None,
    })
}

#[cfg(windows)]
fn normpath(path: &str) -> String {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    File::open(path)
        .and_then(|f| {
            let handle = f.as_raw_handle() as _;
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
pub fn preprocess_cmd<T>(
    cmd: &mut T,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    may_dist: bool,
    rewrite_includes_only: bool,
    is_clang: bool,
) where
    T: RunCommand,
{
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

    cmd.arg("-nologo")
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.dependency_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.to_vec())
        .current_dir(cwd);

    if is_clang {
        if parsed_args.depfile.is_some() && !parsed_args.msvc_show_includes {
            cmd.arg("-showIncludes");
        }
    } else {
        // cl.exe can product the dep list itself, in a JSON format that some tools will be expecting.
        if let Some(ref depfile) = parsed_args.depfile {
            cmd.arg("/sourceDependencies");
            cmd.arg(depfile);
        }
        // Windows SDK generates C4668 during preprocessing, but compiles fine.
        // Read for more info: https://github.com/mozilla/sccache/issues/1725
        // And here: https://github.com/mozilla/sccache/issues/2250
        cmd.arg("/WX-");
    }

    if rewrite_includes_only && is_clang {
        cmd.arg("-clang:-frewrite-includes");
    }

    if parsed_args.double_dash_input {
        cmd.arg("--");
    }
    cmd.arg(&parsed_args.input);
}

#[allow(clippy::too_many_arguments)]
pub async fn preprocess<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    may_dist: bool,
    includes_prefix: &str,
    rewrite_includes_only: bool,
    is_clang: bool,
) -> Result<process::Output>
where
    T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    preprocess_cmd(
        &mut cmd,
        parsed_args,
        cwd,
        env_vars,
        may_dist,
        rewrite_includes_only,
        is_clang,
    );

    if log_enabled!(Debug) {
        debug!("preprocess: {:?}", cmd);
    }

    let parsed_args = parsed_args.clone();
    let includes_prefix = includes_prefix.to_string();
    let cwd = cwd.to_owned();

    let output = run_input_output(cmd, None).await?;

    if !is_clang {
        return Ok(output);
    }

    let parsed_args = &parsed_args;
    if let (Some(obj), Some(depfile)) = (parsed_args.outputs.get("obj"), &parsed_args.depfile) {
        let objfile = &obj.path;
        let f = File::create(cwd.join(depfile))?;
        let mut f = BufWriter::new(f);

        encode_path(&mut f, objfile)
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
        let stderr =
            from_local_codepage(&stderr_bytes).context("Failed to convert preprocessor stderr")?;
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
        Some(obj) => &obj.path,
        None => bail!("Missing object file output"),
    };

    // See if this compilation will produce a PDB.
    let cacheable = parsed_args
        .outputs
        .get("pdb")
        .map_or(Cacheable::Yes, |pdb| {
            // If the PDB exists, we don't know if it's shared with another
            // compilation. If it is, we can't cache.
            if Path::new(&cwd).join(pdb.path.clone()).exists() {
                Cacheable::No
            } else {
                Cacheable::Yes
            }
        });

    let mut fo = OsString::from("-Fo");
    fo.push(out_file);

    let mut arguments: Vec<OsString> = vec![parsed_args.compilation_flag.clone(), fo];
    arguments.extend_from_slice(&parsed_args.preprocessor_args);
    arguments.extend_from_slice(&parsed_args.dependency_args);
    arguments.extend_from_slice(&parsed_args.unhashed_args);
    arguments.extend_from_slice(&parsed_args.common_args);
    if parsed_args.double_dash_input {
        arguments.push("--".into());
    }
    arguments.push(parsed_args.input.clone().into());
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

        let mut arguments: Vec<String> =
            vec![parsed_args.compilation_flag.clone().into_string().ok()?, fo];
        // It's important to avoid preprocessor_args because of things like /FI which
        // forcibly includes another file. This does mean we're potentially vulnerable
        // to misidentification of flags like -DYNAMICBASE (though in that specific
        // case we're safe as it only applies to link time, which sccache avoids).
        arguments.extend(dist::osstrings_to_strings(&parsed_args.common_args)?);

        if parsed_args.double_dash_input {
            arguments.push("--".into());
        }
        arguments.push(path_transformer.as_dist(&parsed_args.input)?);

        Some(dist::CompileCommand {
            executable: path_transformer.as_dist(executable)?,
            arguments,
            env_vars: dist::osstring_tuples_to_strings(env_vars)?,
            cwd: path_transformer.as_dist(cwd)?,
        })
    })();

    Ok((command, dist_command, cacheable))
}

/// Iterator that expands @response files in-place.
///
/// According to MSDN [1], @file means:
///
/// ```text
///   A text file containing compiler commands.
///
///   A response file can contain any commands that you would specify on the
///   command line. This can be useful if your command-line arguments exceed
///   127 characters.
///
///   It is not possible to specify the @ option from within a response file.
///   That is, a response file cannot embed another response file.
///
///   From the command line you can specify as many response file options (for
///   example, @respfile.1 @respfile.2) as you want.
/// ```
///
/// Per Microsoft [2], response files are used by MSBuild:
///
/// ```text
///   Response (.rsp) files are text files that contain MSBuild.exe
///   command-line switches. Each switch can be on a separate line or all
///   switches can be on one line. Comment lines are prefaced with a # symbol.
///   The @ switch is used to pass another response file to MSBuild.exe.
///
///   The autoresponse file is a special .rsp file that MSBuild.exe automatically
///   uses when building a project. This file, MSBuild.rsp, must be in the same
///   directory as MSBuild.exe, otherwise it will not be found. You can edit
///   this file to specify default command-line switches to MSBuild.exe.
///   For example, if you use the same logger every time you build a project,
///   you can add the -logger switch to MSBuild.rsp, and MSBuild.exe will
///   use the logger every time a project is built.
/// ```
///
/// Note that, in order to conform to the spec, response files are not
/// recursively expanded.
///
/// [1]: https://docs.microsoft.com/en-us/cpp/build/reference/at-specify-a-compiler-response-file
/// [2]: https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-response-files?view=vs-2019
struct ExpandIncludeFile<'a> {
    cwd: &'a Path,
    /// Arguments provided during initialization, which may include response-file directives (@).
    /// Order is reversed from the iterator provided,
    /// so they can be visited in front-to-back order by popping from the end.
    args: Vec<OsString>,
    /// Arguments found in provided response-files.
    /// These are also reversed compared to the order in the response file,
    /// so they can be visited in front-to-back order by popping from the end.
    stack: Vec<OsString>,
}

impl<'a> ExpandIncludeFile<'a> {
    pub fn new(cwd: &'a Path, args: &[OsString]) -> Self {
        ExpandIncludeFile {
            // Reverse the provided iterator so we can pop from end to visit in the original order.
            args: args.iter().rev().map(|a| a.to_owned()).collect(),
            stack: Vec::new(),
            cwd,
        }
    }
}

impl<'a> Iterator for ExpandIncludeFile<'a> {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        loop {
            // Visit all arguments found in the most recently read response file.
            // Since response files are not recursive, we do not need to worry
            // about these containing additional @ directives.
            if let Some(response_file_arg) = self.stack.pop() {
                return Some(response_file_arg);
            }

            // Visit the next argument provided by the original command iterator.
            let arg = match self.args.pop() {
                Some(arg) => arg,
                None => return None,
            };
            let file_arg = match arg.split_prefix("@") {
                Some(file_arg) => file_arg,
                None => return Some(arg),
            };
            let file_path = self.cwd.join(file_arg);
            // Read the contents of the response file, accounting for non-utf8 encodings.
            let content = match File::open(&file_path).and_then(|mut file| read_text(&mut file)) {
                Ok(content) => content,
                Err(err) => {
                    debug!("failed to read @-file `{}`: {}", file_path.display(), err);
                    // If we failed to read the file content, return the original arg (including the `@` directive).
                    return Some(arg);
                }
            };

            trace!("Expanded response file {:?} to {:?}", file_path, content);

            // Parse the response file contents, taking into account quote-wrapped strings and new-line separators.
            // Special implementation to account for MSVC response file format.
            let resp_file_args = SplitMsvcResponseFileArgs::from(&content).collect::<Vec<_>>();
            // Pump arguments back to the stack, in reverse order so we can `Vec::pop` and visit in original front-to-back order.
            let rev_args = resp_file_args.iter().rev().map(|s| s.into());
            self.stack.extend(rev_args);
        }
    }
}

/// Reads the text stream as a unicode buffer, prioritizing UTF-8, UTF-16 (big and little endian), and falling back on ISO 8859-1.
fn read_text<R>(reader: &mut R) -> io::Result<String>
where
    R: Read,
{
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let (result, _, has_error) = encoding_rs::WINDOWS_1252.decode(&buf);

    if has_error {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to decode text",
        ))
    } else {
        Ok(result.to_string())
    }
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
struct SplitMsvcResponseFileArgs<'a> {
    /// String slice of the file content that is being parsed.
    /// Slice is mutated as this iterator is executed.
    file_content: &'a str,
}

impl<'a, T> From<&'a T> for SplitMsvcResponseFileArgs<'a>
where
    T: AsRef<str> + 'static,
{
    fn from(file_content: &'a T) -> Self {
        Self {
            file_content: file_content.as_ref(),
        }
    }
}

impl<'a> SplitMsvcResponseFileArgs<'a> {
    /// Appends backslashes to `target` by decrementing `count`.
    /// If `step` is >1, then `count` is decremented by `step`, resulting in 1 backslash appended for every `step`.
    fn append_backslashes_to(target: &mut String, count: &mut usize, step: usize) {
        while *count >= step {
            target.push('\\');
            *count -= step;
        }
    }
}

impl<'a> Iterator for SplitMsvcResponseFileArgs<'a> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut in_quotes = false;
        let mut backslash_count: usize = 0;

        // Strip any leading whitespace before relevant characters
        let is_whitespace = |c| matches!(c, ' ' | '\t' | '\n' | '\r');
        self.file_content = self.file_content.trim_start_matches(is_whitespace);

        if self.file_content.is_empty() {
            return None;
        }

        // The argument string to return, built by analyzing the current slice in the iterator.
        let mut arg = String::new();
        // All characters still in the string slice. Will be mutated by consuming
        // values until the current arg is built.
        let mut chars = self.file_content.chars();
        // Build the argument by evaluating each character in the string slice.
        for c in &mut chars {
            match c {
                // In order to handle the escape character based on the char(s) which come after it,
                // they are counted instead of appended literally, until a non-backslash character is encountered.
                '\\' => backslash_count += 1,
                // Either starting or ending a quoted argument, or appending a literal character (if the quote was escaped).
                '"' => {
                    // Only append half the number of backslashes encountered, because this is an escaped string.
                    // This will reduce `backslash_count` to either 0 or 1.
                    Self::append_backslashes_to(&mut arg, &mut backslash_count, 2);
                    match backslash_count == 0 {
                        // If there are no remaining encountered backslashes,
                        // then we have found either the start or end of a quoted argument.
                        true => in_quotes = !in_quotes,
                        // The quote character is escaped, so it is treated as a literal and appended to the arg string.
                        false => {
                            backslash_count = 0;
                            arg.push('"');
                        }
                    }
                }
                // If whitespace is encountered, only preserve it if we are currently in quotes.
                // Otherwise it marks the end of the current argument.
                ' ' | '\t' | '\n' | '\r' => {
                    Self::append_backslashes_to(&mut arg, &mut backslash_count, 1);
                    // If not in a quoted string, then this is the end of the argument.
                    if !in_quotes {
                        break;
                    }
                    // Otherwise, the whitespace must be preserved in the argument.
                    arg.push(c);
                }
                // All other characters treated as is
                _ => {
                    Self::append_backslashes_to(&mut arg, &mut backslash_count, 1);
                    arg.push(c);
                }
            }
        }

        // Flush any backslashes at the end of the string.
        Self::append_backslashes_to(&mut arg, &mut backslash_count, 1);
        // Save the current remaining characters for the next step in the iterator.
        self.file_content = chars.as_str();

        Some(arg)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::compiler::*;
    use crate::mock_command::*;
    use crate::test::utils::*;

    fn parse_arguments(arguments: Vec<OsString>) -> CompilerArguments<ParsedArguments> {
        super::parse_arguments(&arguments, &std::env::current_dir().unwrap(), false)
    }

    fn parse_arguments_clang(arguments: Vec<OsString>) -> CompilerArguments<ParsedArguments> {
        super::parse_arguments(&arguments, &std::env::current_dir().unwrap(), true)
    }

    #[test]
    fn test_detect_showincludes_prefix() {
        drop(env_logger::try_init());
        let creator = new_creator();
        let runtime = single_threaded_runtime();
        let pool = runtime.handle().clone();
        let f = TestFixture::new();
        let srcfile = f.touch("test.h").unwrap();
        let mut s = srcfile.to_str().unwrap();
        if s.starts_with("\\\\?\\") {
            s = &s[4..];
        }
        let stdout = format!("blah: {}\r\n", s);
        let stderr = String::from("some\r\nstderr\r\n");
        next_command(&creator, Ok(MockChild::new(exit_status(0), stdout, stderr)));
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_cpp_parse_arguments_collects_type_library_headers() {
        let args = ovec!["-c", "foo.cpp", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            outputs,
            ..
        } = match parse_arguments(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.cpp"), input.to_str());
        assert_eq!(Language::Cxx, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            ),
            (
                "tlh",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.tlh"),
                    optional: true
                }
            ),
            (
                "tli",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.tli"),
                    optional: true
                }
            )
        );
    }

    #[test]
    fn test_c_parse_arguments_does_not_collect_type_library_headers() {
        let args = ovec!["-c", "foo.c", "-Fofoo.obj"];
        let ParsedArguments {
            input,
            language,
            outputs,
            ..
        } = match parse_arguments(args) {
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
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_double_dash() {
        let args = ovec!["-c", "-Fofoo.obj", "--", "foo.c"];
        let ParsedArguments {
            input,
            double_dash_input,
            common_args,
            ..
        } = match parse_arguments(args.clone()) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        // MSVC doesn't support double dashes. If we got one, we'll pass them
        // through to MSVC for it to error out.
        assert!(!double_dash_input);
        assert_eq!(ovec!["--"], common_args);

        let ParsedArguments {
            input,
            double_dash_input,
            common_args,
            ..
        } = match parse_arguments_clang(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert!(double_dash_input);
        assert!(common_args.is_empty());

        let args = ovec!["-c", "-Fofoo.obj", "foo.c", "--"];
        let ParsedArguments {
            input,
            double_dash_input,
            common_args,
            ..
        } = match parse_arguments_clang(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        // Double dash after input file is ignored.
        assert!(!double_dash_input);
        assert!(common_args.is_empty());

        let args = ovec!["-c", "-Fofoo.obj", "foo.c", "--", "bar.c"];
        assert_eq!(
            CompilerArguments::CannotCache("multiple input files", Some("[\"bar.c\"]".to_string())),
            parse_arguments_clang(args)
        );

        let args = ovec!["-c", "-Fofoo.obj", "foo.c", "--", "-fPIC"];
        assert_eq!(
            CompilerArguments::CannotCache("multiple input files", Some("[\"-fPIC\"]".to_string())),
            parse_arguments_clang(args)
        );
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn parse_deps_arguments() {
        let arg_sets = vec![
            ovec!["-c", "foo.c", "/Fofoo.obj", "/depsfoo.obj.json"],
            ovec![
                "-c",
                "foo.c",
                "/Fofoo.obj",
                "/sourceDependenciesfoo.obj.json"
            ],
            ovec![
                "-c",
                "foo.c",
                "/Fofoo.obj",
                "/sourceDependencies",
                "foo.obj.json"
            ],
        ];

        for args in arg_sets {
            let ParsedArguments {
                input,
                language,
                outputs,
                preprocessor_args,
                msvc_show_includes,
                common_args,
                depfile,
                ..
            } = match parse_arguments(args) {
                CompilerArguments::Ok(args) => args,
                o => panic!("Got unexpected parse result: {:?}", o),
            };
            assert_eq!(Some("foo.c"), input.to_str());
            assert_eq!(Language::C, language);
            assert_eq!(Some(PathBuf::from_str("foo.obj.json").unwrap()), depfile);
            assert_map_contains!(
                outputs,
                (
                    "obj",
                    ArtifactDescriptor {
                        path: PathBuf::from("foo.obj"),
                        optional: false
                    }
                )
            );
            assert!(preprocessor_args.is_empty());
            assert!(common_args.is_empty());
            assert!(!msvc_show_includes);
        }
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
            "-clang:-fprofile-use=xyz.profdata",
            "dictionary.c"
        ];
        let ParsedArguments {
            dependency_args,
            preprocessor_args,
            common_args,
            profile_generate,
            extra_hash_files,
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
        assert_eq!(
            common_args,
            ovec!(
                "-clang:-fprofile-generate",
                "-clang:-fprofile-use=xyz.profdata"
            )
        );
        assert_eq!(
            extra_hash_files,
            ovec!(std::env::current_dir().unwrap().join("xyz.profdata"))
        );
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert_eq!(common_args, ovec!["-foo", "-bar"]);
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_parse_arguments_values() {
        let args = ovec![
            "-c",
            "foo.c",
            "-FI",
            "file",
            "-imsvc",
            "/a/b/c",
            "-Fofoo.obj",
            "/showIncludes",
            "/winsysroot../../some/dir"
        ];
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
        assert_eq!(preprocessor_args, ovec!["-FIfile", "-imsvc/a/b/c"]);
        assert_eq!(dependency_args, ovec!["/showIncludes"]);
        assert_eq!(common_args, ovec!["/winsysroot../../some/dir"]);
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
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            ),
            (
                "pdb",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.pdb"),
                    optional: false
                }
            )
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
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: PathBuf::from("foo.obj"),
                    optional: false
                }
            )
        );
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
    fn test_parse_arguments_external_warning_suppression_forward_slashes() {
        // Parsing /external:W relies on /experimental:external being parsed
        // and placed into common_args.
        for n in 0..5 {
            let args = ovec![
                "-c",
                "foo.c",
                "/Fofoo.obj",
                "/experimental:external",
                format!("/external:W{}", n)
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
            assert_map_contains!(
                outputs,
                (
                    "obj",
                    ArtifactDescriptor {
                        path: PathBuf::from("foo.obj"),
                        optional: false
                    }
                )
            );
            assert_eq!(1, outputs.len());
            assert!(preprocessor_args.is_empty());
            assert_eq!(
                common_args,
                ovec!["/experimental:external", format!("/external:W{}", n)]
            );
            assert!(!msvc_show_includes);
        }
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
            "-Qpar",
            "-Qpar-",
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
            ovec!("-Oy", "-Qpar", "-Qpar-", "-Gw", "-EHa", "-Fmdictionary-map")
        );
    }

    #[test]
    fn test_parse_arguments_too_many_inputs_single() {
        assert_eq!(
            CompilerArguments::CannotCache("multiple input files", Some("[\"bar.c\"]".to_string())),
            parse_arguments(ovec!["-c", "foo.c", "-Fofoo.obj", "bar.c"])
        );
    }

    #[test]
    fn test_parse_arguments_too_many_inputs_multiple() {
        assert_eq!(
            CompilerArguments::CannotCache(
                "multiple input files",
                Some("[\"bar.c\", \"baz.c\"]".to_string())
            ),
            parse_arguments(ovec!["-c", "foo.c", "-Fofoo.obj", "bar.c", "baz.c"])
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

        assert_eq!(
            CompilerArguments::CannotCache("-Fp", None),
            parse_arguments(ovec!["-c", "-Fpfoo.h", "foo.c"])
        );

        assert_eq!(
            CompilerArguments::CannotCache("-Yc", None),
            parse_arguments(ovec!["-c", "-Ycfoo.h", "foo.c"])
        );
    }

    #[test]
    fn test_responsefile_missing() {
        assert_eq!(
            CompilerArguments::CannotCache("@", None),
            parse_arguments(ovec!["-c", "foo.c", "@foo", "-Fofoo.obj"])
        );
    }

    #[test]
    fn test_responsefile_absolute_path() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let cmd_file_path = td.path().join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            let content = b"-c foo.c -o foo.o";
            file.write_all(content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_responsefile_relative_path() {
        // Generate the tempdir in the currentdir so we can use a relative path in this test.
        // MSVC allows relative paths to response files, so we must support that.
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir_in("./")
            .unwrap();
        let relative_to_tmp = td
            .path()
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap();
        let cmd_file_path = relative_to_tmp.join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            let content = b"-c foo.c -o foo.o";
            file.write_all(content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_responsefile_with_quotes() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let cmd_file_path = td.path().join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            let content = b"-c \"Foo Bar.c\" -o foo.o";
            file.write_all(content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("Foo Bar.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_responsefile_multiline() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let cmd_file_path = td.path().join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            let content = b"\n-c foo.c\n-o foo.o";
            file.write_all(content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_responsefile_multiline_cr() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let cmd_file_path = td.path().join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            let content = b"\r-c foo.c\r-o foo.o";
            file.write_all(content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("foo.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_responsefile_encoding_utf16le() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let cmd_file_path = td.path().join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            // pre-encoded with utf16le
            let content: [u8; 0x26] = [
                0xFF, 0xFE, // little endian BOM
                // `-c foo€.c -o foo.o`
                0x2D, 0x00, 0x63, 0x00, 0x20, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0xAC, 0x20,
                0x2E, 0x00, 0x63, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x6F, 0x00, 0x20, 0x00, 0x66, 0x00,
                0x6F, 0x00, 0x6F, 0x00, 0x2E, 0x00, 0x6F, 0x00,
            ];
            file.write_all(&content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("foo€.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
    }

    #[test]
    fn test_responsefile_encoding_win1252() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        let cmd_file_path = td.path().join("foo");
        {
            let mut file = File::create(&cmd_file_path).unwrap();
            // pre-encoded with Windows 1252
            let content: [u8; 0x12] = [
                // `-c foo€.c -o foo.o`
                // the euro symbol is 0x80 in Windows 1252 (and undefined in ISO-8859-1)
                0x2D, 0x63, 0x20, 0x66, 0x6F, 0x6F, 0x80, 0x2E, 0x63, 0x20, 0x2D, 0x6F, 0x20, 0x66,
                0x6F, 0x6F, 0x2E, 0x6F,
            ];
            file.write_all(&content).unwrap();
        }
        let arg = format!("@{}", cmd_file_path.display());
        let ParsedArguments {
            input,
            language,
            outputs,
            preprocessor_args,
            msvc_show_includes,
            common_args,
            ..
        } = match parse_arguments(ovec![arg]) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Failed to parse @-file, err: {:?}", o),
        };
        assert_eq!(Some("foo€.c"), input.to_str());
        assert_eq!(Language::C, language);
        assert_map_contains!(
            outputs,
            (
                "obj",
                ArtifactDescriptor {
                    path: "foo.o".into(),
                    optional: false
                }
            )
        );
        assert!(preprocessor_args.is_empty());
        assert!(common_args.is_empty());
        assert!(!msvc_show_includes);
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
    fn test_preprocess_double_dash_input() {
        let args = ovec!["-c", "-Fofoo.o.bj", "--", "foo.c"];
        let parsed_args = match parse_arguments_clang(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        let mut cmd = MockCommand {
            child: None,
            args: vec![],
        };
        preprocess_cmd(&mut cmd, &parsed_args, Path::new(""), &[], true, true, true);
        let expected_args = ovec!["-E", "-nologo", "-clang:-frewrite-includes", "--", "foo.c"];
        assert_eq!(cmd.args, expected_args);
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
                    path: "foo.obj".into(),
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
            extra_hash_files: vec![],
            msvc_show_includes: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::new();
        let (command, dist_command, cacheable) = generate_compile_commands(
            &mut path_transformer,
            compiler,
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
    fn test_compile_double_dash_input() {
        let args = ovec!["-c", "-Fofoo.obj", "--", "foo.c"];
        let parsed_args = match parse_arguments_clang(args) {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        let f = TestFixture::new();
        let compiler = &f.bins[0];
        let mut path_transformer = dist::PathTransformer::new();
        let (command, _, _) = generate_compile_commands(
            &mut path_transformer,
            compiler,
            &parsed_args,
            f.tempdir.path(),
            &[],
        )
        .unwrap();
        let expected_args = ovec!["-c", "-Fofoo.obj", "--", "foo.c"];
        assert_eq!(command.arguments, expected_args);
    }

    #[test]
    fn test_compile_not_cacheable_pdb() {
        let creator = new_creator();
        let f = TestFixture::new();
        let pdb = f.touch("foo.pdb").unwrap();
        let parsed_args = ParsedArguments {
            input: "foo.c".into(),
            double_dash_input: false,
            language: Language::C,
            compilation_flag: "/c".into(),
            depfile: None,
            outputs: vec![
                (
                    "obj",
                    ArtifactDescriptor {
                        path: "foo.obj".into(),
                        optional: false,
                    },
                ),
                (
                    "pdb",
                    ArtifactDescriptor {
                        path: pdb,
                        optional: false,
                    },
                ),
            ]
            .into_iter()
            .collect(),
            dependency_args: vec![],
            preprocessor_args: vec![],
            common_args: vec![],
            arch_args: vec![],
            unhashed_args: vec![],
            extra_hash_files: vec![],
            msvc_show_includes: false,
            profile_generate: false,
            color_mode: ColorMode::Auto,
            suppress_rewrite_includes_only: false,
            too_hard_for_preprocessor_cache_mode: None,
        };
        let compiler = &f.bins[0];
        // Compiler invocation.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "", "")));
        let mut path_transformer = dist::PathTransformer::new();
        let (command, dist_command, cacheable) = generate_compile_commands(
            &mut path_transformer,
            compiler,
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

    #[test]
    #[cfg(windows)]
    fn local_oem_codepage_conversions() {
        use crate::util::wide_char_to_multi_byte;
        use windows_sys::Win32::Globalization::GetOEMCP;

        let current_oemcp = unsafe { GetOEMCP() };
        // We don't control the local OEM codepage so test only if it is one of:
        // United Stats, Latin-1 and Latin-1 + euro symbol
        if current_oemcp == 437 || current_oemcp == 850 || current_oemcp == 858 {
            // Non-ASCII characters
            const INPUT_STRING: &str = "ÇüéâäàåçêëèïîìÄÅ";

            // The characters in INPUT_STRING encoded per the OEM codepage
            const INPUT_BYTES: [u8; 16] = [
                128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
            ];

            // Test the conversion from the OEM codepage to UTF-8
            assert_eq!(from_local_codepage(&INPUT_BYTES).unwrap(), INPUT_STRING);

            // The characters in INPUT_STRING encoded in UTF-16
            const INPUT_WORDS: [u16; 16] = [
                199, 252, 233, 226, 228, 224, 229, 231, 234, 235, 232, 239, 238, 236, 196, 197,
            ];

            // Test the conversion from UTF-16 to the OEM codepage
            assert_eq!(wide_char_to_multi_byte(&INPUT_WORDS).unwrap(), INPUT_BYTES);
        }
    }
}
