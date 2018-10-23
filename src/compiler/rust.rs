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

use compiler::{Cacheable, ColorMode, Compiler, CompilerArguments, CompileCommand, CompilerHasher, CompilerKind,
               Compilation, HashResult};
#[cfg(feature = "dist-client")]
use compiler::OutputsRewriter;
use compiler::args::*;
use dist;
#[cfg(feature = "dist-client")]
use dist::pkg;
use futures::{Future, future};
use futures_cpupool::CpuPool;
use log::Level::Trace;
#[cfg(feature = "dist-client")]
use lru_disk_cache::lru_cache;
use mock_command::{CommandCreatorSync, RunCommand};
#[cfg(feature = "dist-client")]
use regex;
#[cfg(feature = "dist-client")]
use std::borrow::Borrow;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
#[cfg(feature = "dist-client")]
use std::collections::hash_map::RandomState;
#[cfg(feature = "dist-client")]
use std::env::consts::{DLL_PREFIX, EXE_EXTENSION};
use std::env::consts::DLL_EXTENSION;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::hash::Hash;
#[cfg(feature = "dist-client")]
use std::io;
use std::io::Read;
use std::iter;
use std::path::{Path, PathBuf};
use std::process;
#[cfg(feature = "dist-client")]
use std::sync::{Arc, Mutex};
use std::time;
use tempdir::TempDir;
use util::{fmt_duration_as_secs, run_input_output, Digest};
use util::{HashToDigest, OsStrExt, ref_env};

use errors::*;

/// Can dylibs (like proc macros) be distributed on this platform?
#[cfg(all(feature = "dist-client", target_os = "linux", target_arch = "x86_64"))]
const CAN_DIST_DYLIBS: bool = true;
#[cfg(all(feature = "dist-client", not(all(target_os = "linux", target_arch = "x86_64"))))]
const CAN_DIST_DYLIBS: bool = false;

#[cfg(feature = "dist-client")]
const RLIB_PREFIX: &str = "lib";
#[cfg(feature = "dist-client")]
const RLIB_EXTENSION: &str = "rlib";

/// Directory in the sysroot containing binary to which rustc is linked.
#[cfg(feature = "dist-client")]
const BINS_DIR: &str = "bin";

/// Directory in the sysroot containing shared libraries to which rustc is linked.
#[cfg(not(windows))]
const LIBS_DIR: &str = "lib";

/// Directory in the sysroot containing shared libraries to which rustc is linked.
#[cfg(windows)]
const LIBS_DIR: &str = "bin";

/// A struct on which to hang a `Compiler` impl.
#[derive(Debug, Clone)]
pub struct Rust {
    /// The path to the rustc executable.
    executable: PathBuf,
    /// The host triple for this rustc.
    host: String,
    /// The path to the rustc sysroot.
    sysroot: PathBuf,
    /// The SHA-1 digests of all the shared libraries in rustc's $sysroot/lib (or /bin on Windows).
    compiler_shlibs_digests: Vec<String>,
    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
}

/// A struct on which to hang a `CompilerHasher` impl.
#[derive(Debug, Clone)]
pub struct RustHasher {
    /// The path to the rustc executable.
    executable: PathBuf,
    /// The host triple for this rustc.
    host: String,
    /// The path to the rustc sysroot.
    sysroot: PathBuf,
    /// The SHA-1 digests of all the shared libraries in rustc's $sysroot/lib (or /bin on Windows).
    compiler_shlibs_digests: Vec<String>,
    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// Parsed arguments from the rustc invocation
    parsed_args: ParsedArguments,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArguments {
    /// The full commandline, with all parsed aguments
    arguments: Vec<Argument<ArgData>>,
    /// The location of compiler outputs.
    output_dir: PathBuf,
    /// Paths to extern crates used in the compile.
    externs: Vec<PathBuf>,
    /// The directories searched for rlibs
    crate_link_paths: Vec<PathBuf>,
    /// Static libraries linked to in the compile.
    staticlibs: Vec<PathBuf>,
    /// The crate name passed to --crate-name.
    crate_name: String,
    /// The crate types that will be generated
    crate_types: CrateTypes,
    /// If dependency info is being emitted, the name of the dep info file.
    dep_info: Option<PathBuf>,
    /// rustc says that emits .rlib for --emit=metadata
    /// https://github.com/rust-lang/rust/issues/54852
    rename_rlib_to_rmeta: bool,
    /// The value of any `--color` option passed on the commandline.
    color_mode: ColorMode,
}

/// A struct on which to hang a `Compilation` impl.
#[derive(Debug, Clone)]
pub struct RustCompilation {
    /// The path to the rustc executable.
    executable: PathBuf,
    /// The host triple for this rustc.
    host: String,
    /// The sysroot for this rustc
    sysroot: PathBuf,
    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// All arguments passed to rustc
    arguments: Vec<Argument<ArgData>>,
    /// The compiler inputs.
    inputs: Vec<PathBuf>,
    /// The compiler outputs.
    outputs: HashMap<String, PathBuf>,
    /// The directories searched for rlibs
    crate_link_paths: Vec<PathBuf>,
    /// The crate name being compiled.
    crate_name: String,
    /// The crate types that will be generated
    crate_types: CrateTypes,
    /// If dependency info is being emitted, the name of the dep info file.
    dep_info: Option<PathBuf>,
    /// The current working directory
    cwd: PathBuf,
    /// The environment variables
    env_vars: Vec<(OsString, OsString)>,
}

// The selection of crate types for this compilation
#[derive(Debug, Clone, PartialEq)]
pub struct CrateTypes {
    rlib: bool,
    staticlib: bool,
}

lazy_static! {
    /// Emit types that we will cache.
    static ref ALLOWED_EMIT: HashSet<&'static str> = [
        "link",
        "metadata",
        "dep-info",
    ].iter().map(|s| *s).collect();
}

/// Version number for cache key.
const CACHE_VERSION: &[u8] = b"2";

/// Calculate the SHA-1 digest of each file in `files` on background threads
/// in `pool`.
fn hash_all(files: &[PathBuf], pool: &CpuPool) -> SFuture<Vec<String>>
{
    let start = time::Instant::now();
    let count = files.len();
    let pool = pool.clone();
    Box::new(future::join_all(files.into_iter().map(move |f| Digest::file(f, &pool)).collect::<Vec<_>>())
             .map(move |hashes| {
                 trace!("Hashed {} files in {}", count, fmt_duration_as_secs(&start.elapsed()));
                 hashes
             }))
}

/// Get absolute paths for all source files listed in rustc's dep-info output.
fn get_source_files<T>(creator: &T,
                        crate_name: &str,
                        executable: &Path,
                        arguments: &[OsString],
                        cwd: &Path,
                        env_vars: &[(OsString, OsString)],
                        pool: &CpuPool)
                        -> SFuture<Vec<PathBuf>>
    where T: CommandCreatorSync,
{
    let start = time::Instant::now();
    // Get the full list of source files from rustc's dep-info.
    let temp_dir = ftry!(TempDir::new("sccache").chain_err(|| "Failed to create temp dir"));
    let dep_file = temp_dir.path().join("deps.d");
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--emit", "dep-info"])
        .arg("-o")
        .arg(&dep_file)
        .env_clear()
        .envs(ref_env(env_vars))
        .current_dir(cwd);
    trace!("[{}]: get dep-info: {:?}", crate_name, cmd);
    let dep_info = run_input_output(cmd, None);
    // Parse the dep-info file, then hash the contents of those files.
    let pool = pool.clone();
    let cwd = cwd.to_owned();
    let crate_name = crate_name.to_owned();
    Box::new(dep_info.and_then(move |_| -> SFuture<_> {
        let name2 = crate_name.clone();
        let parsed = pool.spawn_fn(move || {
            parse_dep_file(&dep_file, &cwd).chain_err(|| {
                format!("Failed to parse dep info for {}", name2)
            })
        });
        Box::new(parsed.map(move |files| {
            trace!("[{}]: got {} source files from dep-info in {}", crate_name,
                   files.len(), fmt_duration_as_secs(&start.elapsed()));
            // Just to make sure we capture temp_dir.
            drop(temp_dir);
            files
        }))
    }))
}

/// Parse dependency info from `file` and return a Vec of files mentioned.
/// Treat paths as relative to `cwd`.
fn parse_dep_file<T, U>(file: T, cwd: U) -> Result<Vec<PathBuf>>
    where T: AsRef<Path>,
          U: AsRef<Path>,
{
    let mut f = fs::File::open(file)?;
    let mut deps = String::new();
    f.read_to_string(&mut deps)?;
    Ok(parse_dep_info(&deps, cwd))
}

fn parse_dep_info<T>(dep_info: &str, cwd: T) -> Vec<PathBuf>
    where T: AsRef<Path>
{
    let cwd = cwd.as_ref();
    // Just parse the first line, which should have the dep-info file and all
    // source files.
    let line = match dep_info.lines().next() {
        None => return vec![],
        Some(l) => l,
    };
    let pos = match line.find(": ") {
        None => return vec![],
        Some(p) => p,
    };
    let mut deps = line[pos + 2..]
        .split(' ')
        .map(|s| s.trim()).filter(|s| !s.is_empty())
        .map(|s| cwd.join(s))
        .collect::<Vec<_>>();
    deps.sort();
    deps
}

/// Run `rustc --print file-names` to get the outputs of compilation.
fn get_compiler_outputs<T>(creator: &T,
                           executable: &Path,
                           arguments: &[OsString],
                           cwd: &Path,
                           env_vars: &[(OsString, OsString)]) -> SFuture<Vec<String>>
    where T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--print", "file-names"])
        .env_clear()
        .envs(ref_env(env_vars))
        .current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("get_compiler_outputs: {:?}", cmd);
    }
    let outputs = run_input_output(cmd, None);
    Box::new(outputs.and_then(move |output| -> Result<_> {
        let outstr = String::from_utf8(output.stdout).chain_err(|| "Error parsing rustc output")?;
        Ok(outstr.lines().map(|l| l.to_owned()).collect())
    }))
}

impl Rust {
    /// Create a new Rust compiler instance, calculating the hashes of
    /// all the shared libraries in its sysroot.
    pub fn new<T>(mut creator: T,
                  executable: PathBuf,
                  env_vars: &[(OsString, OsString)],
                  rustc_verbose_version: &str,
                  pool: CpuPool) -> SFuture<Rust>
        where T: CommandCreatorSync,
    {
        // Taken from Cargo
        let host = ftry!(rustc_verbose_version
            .lines()
            .find(|l| l.starts_with("host: "))
            .map(|l| &l[6..])
            .ok_or_else(|| Error::from("rustc verbose version didn't have a line for `host:`")))
            .to_string();

        let mut cmd = creator.new_command_sync(&executable);
        cmd.stdout(process::Stdio::piped())
            .stderr(process::Stdio::null())
            .arg("--print=sysroot")
            .env_clear()
            .envs(ref_env(env_vars));
        let output = run_input_output(cmd, None);
        let sysroot_and_libs = output.and_then(move |output| -> Result<_> {
            //debug!("output.and_then: {}", output);
            let outstr = String::from_utf8(output.stdout).chain_err(|| "Error parsing sysroot")?;
            let sysroot = PathBuf::from(outstr.trim_right());
            let libs_path = sysroot.join(LIBS_DIR);
            let mut libs = fs::read_dir(&libs_path).chain_err(|| format!("Failed to list rustc sysroot: `{:?}`", libs_path))?.filter_map(|e| {
                e.ok().and_then(|e| {
                    e.file_type().ok().and_then(|t| {
                        let p = e.path();
                        if t.is_file() && p.extension().map(|e| e == DLL_EXTENSION).unwrap_or(false) {
                            Some(p)
                        } else {
                            None
                        }
                    })
                })
            }).collect::<Vec<_>>();
            libs.sort();
            Ok((sysroot, libs))
        });

        #[cfg(feature = "dist-client")]
        let rlib_dep_reader = {
            let executable = executable.clone();
            let env_vars = env_vars.to_owned();
            pool.spawn_fn(move || Ok(RlibDepReader::new_with_check(executable, &env_vars)))
        };

        #[cfg(feature = "dist-client")]
        return Box::new(sysroot_and_libs.join(rlib_dep_reader).and_then(move |((sysroot, libs), rlib_dep_reader)| {
            let rlib_dep_reader = match rlib_dep_reader {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    warn!("Failed to initialise RlibDepDecoder, distributed compiles will be inefficient: {}", e);
                    None
                },
            };
            hash_all(&libs, &pool).map(move |digests| {
                Rust {
                    executable: executable,
                    host,
                    sysroot,
                    compiler_shlibs_digests: digests,
                    rlib_dep_reader,
                }
            })
        }));

        #[cfg(not(feature = "dist-client"))]
        return Box::new(sysroot_and_libs.and_then(move |(sysroot, libs)| {
            hash_all(&libs, &pool).map(move |digests| {
                Rust {
                    executable: executable,
                    host,
                    sysroot,
                    compiler_shlibs_digests: digests,
                }
            })
        }));
    }
}

impl<T> Compiler<T> for Rust
    where T: CommandCreatorSync,
{
    fn kind(&self) -> CompilerKind { CompilerKind::Rust }
    #[cfg(feature = "dist-client")]
    fn get_toolchain_packager(&self) -> Box<pkg::ToolchainPackager> {
        Box::new(RustToolchainPackager { sysroot: self.sysroot.clone() })
    }
    /// Parse `arguments` as rustc command-line arguments, determine if
    /// we can cache the result of compilation. This is only intended to
    /// cover a subset of rustc invocations, primarily focused on those
    /// that will occur when cargo invokes rustc.
    ///
    /// Caveats:
    /// * We don't support compilation from stdin.
    /// * We require --emit.
    /// * We only support `link` and `dep-info` in --emit (and don't support *just* 'dep-info')
    /// * We require `--out-dir`.
    /// * We don't support `-o file`.
    fn parse_arguments(&self,
                       arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<Box<CompilerHasher<T> + 'static>>
    {
        match parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => {
                CompilerArguments::Ok(Box::new(RustHasher {
                    executable: self.executable.clone(),
                    host: self.host.clone(),
                    sysroot: self.sysroot.clone(),
                    compiler_shlibs_digests: self.compiler_shlibs_digests.clone(),
                    #[cfg(feature = "dist-client")]
                    rlib_dep_reader: self.rlib_dep_reader.clone(),
                    parsed_args: args,
                }))
            }
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
            CompilerArguments::CannotCache(why, extra_info) => CompilerArguments::CannotCache(why, extra_info),
        }
    }


    fn box_clone(&self) -> Box<Compiler<T>> {
        Box::new((*self).clone())
    }
}

macro_rules! make_os_string {
    ($( $v:expr ),*) => {{
        let mut s = OsString::new();
        $(
            s.push($v);
        )*
        s
    }};
}

#[derive(Clone, Debug, PartialEq)]
struct ArgCrateTypes {
    rlib: bool,
    staticlib: bool,
    others: HashSet<String>,
}
impl FromArg for ArgCrateTypes {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let arg = String::process(arg)?;
        let mut crate_types = ArgCrateTypes {
            rlib: false,
            staticlib: false,
            others: HashSet::new(),
        };
        for ty in arg.split(",") {
            match ty {
                // It is assumed that "lib" always refers to "rlib", which
                // is true right now but may not be in the future
                "lib" |
                "rlib" => crate_types.rlib = true,
                "staticlib" => crate_types.staticlib = true,
                other => { crate_types.others.insert(other.to_owned()); },
            }
        }
        Ok(crate_types)
    }
}
impl IntoArg for ArgCrateTypes {
    fn into_arg_os_string(self) -> OsString {
        let ArgCrateTypes { rlib, staticlib, others } = self;
        let mut types: Vec<_> = others.iter().map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None }).collect();
        types.sort();
        let types_string = types.join(",");
        types_string.into()
    }
    fn into_arg_string(self, _transformer: PathTransformerFn) -> ArgToStringResult {
        let ArgCrateTypes { rlib, staticlib, others } = self;
        let mut types: Vec<_> = others.iter().map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None }).collect();
        types.sort();
        let types_string = types.join(",");
        Ok(types_string)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkLibrary {
    kind: String,
    name: String,
}
impl FromArg for ArgLinkLibrary {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, name) = match split_os_string_arg(arg, "=")? {
            (kind, Some(name)) => (kind, name),
            // If no kind is specified, the default is dylib.
            (name, None) => ("dylib".to_owned(), name),
        };
        Ok(ArgLinkLibrary { kind, name })
    }
}
impl IntoArg for ArgLinkLibrary {
    fn into_arg_os_string(self) -> OsString {
        let ArgLinkLibrary { kind, name } = self;
        make_os_string!(kind, "=", name)
    }
    fn into_arg_string(self, _transformer: PathTransformerFn) -> ArgToStringResult {
        let ArgLinkLibrary { kind, name } = self;
        Ok(format!("{}={}", kind, name))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkPath {
    kind: String,
    path: PathBuf,
}
impl FromArg for ArgLinkPath {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, path) = match split_os_string_arg(arg, "=")? {
            (kind, Some(path)) => (kind, path),
            // If no kind is specified, the path is used to search for all kinds
            (path, None) => ("all".to_owned(), path),
        };
        Ok(ArgLinkPath { kind, path: path.into() })
    }
}
impl IntoArg for ArgLinkPath {
    fn into_arg_os_string(self) -> OsString {
        let ArgLinkPath { kind, path } = self;
        make_os_string!(kind, "=", path)
    }
    fn into_arg_string(self, transformer: PathTransformerFn) -> ArgToStringResult {
        let ArgLinkPath { kind, path } = self;
        Ok(format!("{}={}", kind, path.into_arg_string(transformer)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgCodegen {
    opt: String,
    value: Option<String>,
}
impl FromArg for ArgCodegen {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (opt, value) = split_os_string_arg(arg, "=")?;
        Ok(ArgCodegen { opt, value })
    }
}
impl IntoArg for ArgCodegen {
    fn into_arg_os_string(self) -> OsString {
        let ArgCodegen { opt, value } = self;
        if let Some(value) = value {
            make_os_string!(opt, "=", value)
        } else {
            make_os_string!(opt)
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn) -> ArgToStringResult {
        let ArgCodegen { opt, value } = self;
        Ok(if let Some(value) = value {
            format!("{}={}", opt, value.into_arg_string(transformer)?)
        } else {
            opt
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgExtern {
    name: String,
    path: PathBuf,
}
impl FromArg for ArgExtern {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        if let (name, Some(path)) = split_os_string_arg(arg, "=")? {
            Ok(ArgExtern { name, path: path.into() })
        } else {
            Err(ArgParseError::Other("no path for extern"))
        }
    }
}
impl IntoArg for ArgExtern {
    fn into_arg_os_string(self) -> OsString {
        let ArgExtern { name, path } = self;
        make_os_string!(name, "=", path)
    }
    fn into_arg_string(self, transformer: PathTransformerFn) -> ArgToStringResult {
        let ArgExtern { name, path } = self;
        Ok(format!("{}={}", name, path.into_arg_string(transformer)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ArgTarget {
    Name(String),
    Path(PathBuf),
    Unsure(OsString),
}
impl FromArg for ArgTarget {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        // Is it obviously a json file path?
        if Path::new(&arg).extension().map(|ext| ext == "json").unwrap_or(false) {
            return Ok(ArgTarget::Path(arg.into()))
        }
        // Time for clever detection - if we append .json (even if it's clearly
        // a directory, i.e. resulting in /my/dir/.json), does the path exist?
        let mut path = arg.clone();
        path.push(".json");
        if Path::new(&path).is_file() {
            // Unfortunately, we're now not sure what will happen without having
            // a list of all the built-in targets handy, as they don't get .json
            // auto-added for target json discovery
            return Ok(ArgTarget::Unsure(arg))
        }
        // The file doesn't exist so it can't be a path, safe to assume it's a name
        Ok(ArgTarget::Name(arg.into_string().map_err(ArgParseError::InvalidUnicode)?))
    }
}
impl IntoArg for ArgTarget {
    fn into_arg_os_string(self) -> OsString {
        match self {
            ArgTarget::Name(s) => s.into(),
            ArgTarget::Path(p) => p.into(),
            ArgTarget::Unsure(s) => s.into(),
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn) -> ArgToStringResult {
        Ok(match self {
            ArgTarget::Name(s) => s,
            ArgTarget::Path(p) => p.into_arg_string(transformer)?,
            ArgTarget::Unsure(s) => s.into_arg_string(transformer)?,
        })
    }
}

ArgData!{
    TooHardFlag,
    TooHard(OsString),
    TooHardPath(PathBuf),
    NotCompilationFlag,
    NotCompilation(OsString),
    LinkLibrary(ArgLinkLibrary),
    LinkPath(ArgLinkPath),
    Emit(String),
    Extern(ArgExtern),
    Color(String),
    CrateName(String),
    CrateType(ArgCrateTypes),
    OutDir(PathBuf),
    CodeGen(ArgCodegen),
    PassThrough(OsString),
    Target(ArgTarget),
}

use self::ArgData::*;

// These are taken from https://github.com/rust-lang/rust/blob/b671c32ddc8c36d50866428d83b7716233356721/src/librustc/session/config.rs#L1186
counted_array!(static ARGS: [ArgInfo<ArgData>; _] = [
    flag!("-", TooHardFlag),
    take_arg!("--allow", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("--cap-lints", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("--cfg", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("--codegen", ArgCodegen, CanBeSeparated('='), CodeGen),
    take_arg!("--color", String, CanBeSeparated('='), Color),
    take_arg!("--crate-name", String, CanBeSeparated('='), CrateName),
    take_arg!("--crate-type", ArgCrateTypes, CanBeSeparated('='), CrateType),
    take_arg!("--deny", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("--emit", String, CanBeSeparated('='), Emit),
    take_arg!("--error-format", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("--explain", OsString, CanBeSeparated('='), NotCompilation),
    take_arg!("--extern", ArgExtern, CanBeSeparated('='), Extern),
    take_arg!("--forbid", OsString, CanBeSeparated('='), PassThrough),
    flag!("--help", NotCompilationFlag),
    take_arg!("--out-dir", PathBuf, CanBeSeparated('='), OutDir),
    take_arg!("--pretty", OsString, CanBeSeparated('='), NotCompilation),
    take_arg!("--print", OsString, CanBeSeparated('='), NotCompilation),
    take_arg!("--remap-path-prefix", OsString, CanBeSeparated('='), TooHard),
    take_arg!("--sysroot", PathBuf, CanBeSeparated('='), TooHardPath),
    take_arg!("--target", ArgTarget, CanBeSeparated('='), Target),
    take_arg!("--unpretty", OsString, CanBeSeparated('='), NotCompilation),
    flag!("--version", NotCompilationFlag),
    take_arg!("--warn", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("-A", OsString, CanBeSeparated, PassThrough),
    take_arg!("-C", ArgCodegen, CanBeSeparated, CodeGen),
    take_arg!("-D", OsString, CanBeSeparated, PassThrough),
    take_arg!("-F", OsString, CanBeSeparated, PassThrough),
    take_arg!("-L", ArgLinkPath, CanBeSeparated, LinkPath),
    flag!("-V", NotCompilationFlag),
    take_arg!("-W", OsString, CanBeSeparated, PassThrough),
    take_arg!("-Z", OsString, CanBeSeparated, PassThrough),
    take_arg!("-l", ArgLinkLibrary, CanBeSeparated, LinkLibrary),
    take_arg!("-o", PathBuf, CanBeSeparated, TooHardPath),
]);

fn parse_arguments(arguments: &[OsString], cwd: &Path) -> CompilerArguments<ParsedArguments>
{
    let mut args = vec![];

    let mut emit: Option<HashSet<String>> = None;
    let mut input = None;
    let mut output_dir = None;
    let mut crate_name = None;
    let mut crate_types = CrateTypes { rlib: false, staticlib: false };
    let mut extra_filename = None;
    let mut externs = vec![];
    let mut crate_link_paths = vec![];
    let mut static_lib_names = vec![];
    let mut static_link_paths: Vec<PathBuf> = vec![];
    let mut color_mode = ColorMode::Auto;

    for arg in ArgsIter::new(arguments.iter().map(|s| s.clone()), &ARGS[..]) {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        match arg.get_data() {
            Some(TooHardFlag) |
            Some(TooHard(_)) |
            Some(TooHardPath(_)) => {
                cannot_cache!(arg.flag_str().expect(
                    "Can't be Argument::Raw/UnknownFlag",
                ))
            }
            Some(NotCompilationFlag) |
            Some(NotCompilation(_)) => return CompilerArguments::NotCompilation,
            Some(LinkLibrary(ArgLinkLibrary { kind, name })) => {
                if kind == "static" {
                    static_lib_names.push(name.to_owned())
                }
            },
            Some(LinkPath(ArgLinkPath { kind, path })) => {
                // "crate" is not typically necessary as cargo will normally
                // emit explicit --extern arguments
                if kind == "crate" || kind == "dependency" || kind == "all" {
                    crate_link_paths.push(cwd.join(path))
                }
                if kind == "native" || kind == "all" {
                    static_link_paths.push(cwd.join(path))
                }
            },
            Some(Emit(value)) => {
                if emit.is_some() {
                    // We don't support passing --emit more than once.
                    cannot_cache!("more than one --emit");
                }
                emit = Some(value.split(",").map(str::to_owned).collect())
            }
            Some(CrateType(ArgCrateTypes { rlib, staticlib, others })) => {
                // We can't cache non-rlib/staticlib crates, because rustc invokes the
                // system linker to link them, and we don't know about all the linker inputs.
                if !others.is_empty() {
                    let others: Vec<&str> = others.iter().map(String::as_str).collect();
                    let others_string = others.join(",");
                    cannot_cache!("crate-type", others_string)
                }
                crate_types.rlib |= rlib;
                crate_types.staticlib |= staticlib;
            }
            Some(CrateName(value)) => crate_name = Some(value.clone()),
            Some(OutDir(value)) => output_dir = Some(value.clone()),
            Some(Extern(ArgExtern { name: _, path })) => externs.push(path.clone()),
            Some(CodeGen(ArgCodegen { opt, value })) => {
                match (opt.as_ref(), value) {
                    ("extra-filename", Some(value)) => extra_filename = Some(value.to_owned()),
                    ("extra-filename", None) => cannot_cache!("extra-filename"),
                    // Incremental compilation makes a mess of sccache's entire world
                    // view. It produces additional compiler outputs that we don't cache,
                    // and just letting rustc do its work in incremental mode is likely
                    // to be faster than trying to fetch a result from cache anyway, so
                    // don't bother caching compiles where it's enabled currently.
                    // Longer-term we would like to figure out better integration between
                    // sccache and rustc in the incremental scenario:
                    // https://github.com/mozilla/sccache/issues/236
                    ("incremental", _) => cannot_cache!("incremental"),
                    (_, _) => (),
                }
            }
            Some(Color(value)) => {
                // We'll just assume the last specified value wins.
                color_mode = match value.as_ref() {
                    "always" => ColorMode::On,
                    "never" => ColorMode::Off,
                    _ => ColorMode::Auto,
                };
            }
            Some(PassThrough(_)) => (),
            Some(Target(target)) => {
                match target {
                    ArgTarget::Path(_) |
                    ArgTarget::Unsure(_) => cannot_cache!("target"),
                    ArgTarget::Name(_) => (),
                }
            }
            None => {
                match arg {
                    Argument::Raw(ref val) => {
                        if input.is_some() {
                            // Can't cache compilations with multiple inputs.
                            cannot_cache!("multiple input files");
                        }
                        input = Some(val.clone());
                    }
                    Argument::UnknownFlag(_) => {}
                    _ => unreachable!(),
                }
            }
        }
        // We'll drop --color arguments, we're going to pass --color=always and the client will
        // strip colors if necessary.
        match arg.get_data() {
            Some(Color(_)) => {}
            _ => args.push(arg.normalize(NormalizedDisposition::Separated)),
        }
    }

    // Unwrap required values.
    macro_rules! req {
        ($x:ident) => {
            let $x = if let Some($x) = $x {
                $x
            } else {
                debug!("Can't cache compilation, missing `{}`", stringify!($x));
                cannot_cache!(concat!("missing ", stringify!($x)));
            };
        }
    };
    // We don't actually save the input value, but there needs to be one.
    req!(input);
    drop(input);
    req!(output_dir);
    req!(emit);
    req!(crate_name);
    // We won't cache invocations that are not producing
    // binary output.
    if !emit.is_empty() && !emit.contains("link") && !emit.contains("metadata") {
        return CompilerArguments::NotCompilation;
    }
    // If it's not an rlib and not a staticlib then crate-type wasn't passed,
    // so it will usually be inferred as a binary, though the `#![crate_type`
    // annotation may dictate otherwise - either way, we don't know what to do.
    if let CrateTypes { rlib: false, staticlib: false } = crate_types {
        cannot_cache!("crate-type", "No crate-type passed".to_owned())
    }
    // We won't cache invocations that are outputting anything but
    // linker output and dep-info.
    if emit.iter().any(|e| !ALLOWED_EMIT.contains(e.as_str())) {
        cannot_cache!("unsupported --emit");
    }

    let rename_rlib_to_rmeta = emit.contains("metadata") && !emit.contains("link");

    // Figure out the dep-info filename, if emitting dep-info.
    let dep_info = if emit.contains("dep-info") {
        let mut dep_info = crate_name.clone();
        if let Some(extra_filename) = extra_filename {
            dep_info.push_str(&extra_filename[..]);
        }
        dep_info.push_str(".d");
        Some(dep_info)
    } else {
        None
    };
    // Locate all static libs specified on the commandline.
    let staticlibs = static_lib_names.into_iter().filter_map(|name| {
        for path in static_link_paths.iter() {
            for f in &[format_args!("lib{}.a", name), format_args!("{}.lib", name),
                         format_args!("{}.a", name)] {
                let lib_path = path.join(fmt::format(*f));
                if lib_path.exists() {
                    return Some(lib_path);
                }
            }
        }
        // rustc will just error if there's a missing static library, so don't worry about
        // it too much.
        None
    }).collect();
    // We'll figure out the source files and outputs later in
    // `generate_hash_key` where we can run rustc.
    // Cargo doesn't deterministically order --externs, and we need the hash inputs in a
    // deterministic order.
    externs.sort();
    CompilerArguments::Ok(ParsedArguments {
        arguments: args,
        output_dir: output_dir.into(),
        crate_types,
        externs: externs,
        crate_link_paths,
        staticlibs: staticlibs,
        crate_name: crate_name.to_string(),
        dep_info: dep_info.map(|s| s.into()),
        rename_rlib_to_rmeta,
        color_mode,
    })
}

impl<T> CompilerHasher<T> for RustHasher
    where T: CommandCreatorSync,
{
    fn generate_hash_key(self: Box<Self>,
                         creator: &T,
                         cwd: PathBuf,
                         env_vars: Vec<(OsString, OsString)>,
                         _may_dist: bool,
                         pool: &CpuPool)
                         -> SFuture<HashResult>
    {
        let me = *self;
        let RustHasher {
            executable,
            host,
            sysroot,
            compiler_shlibs_digests, #[cfg(feature = "dist-client")]
            rlib_dep_reader,
            parsed_args:
                ParsedArguments {
                    arguments,
                    output_dir,
                    externs,
                    crate_link_paths,
                    staticlibs,
                    crate_name,
                    crate_types,
                    dep_info,
                    rename_rlib_to_rmeta,
                    color_mode: _,
                },
        } = me;
        trace!("[{}]: generate_hash_key", crate_name);
        // TODO: this doesn't produce correct arguments if they should be concatenated - should use iter_os_strings
        let os_string_arguments: Vec<(OsString, Option<OsString>)> = arguments.iter()
            .map(|arg| (arg.to_os_string(), arg.get_data().cloned().map(IntoArg::into_arg_os_string))).collect();
        // `filtered_arguments` omits --emit and --out-dir arguments.
        // It's used for invoking rustc with `--emit=dep-info` to get the list of
        // source files for this crate.
        let filtered_arguments = os_string_arguments.iter()
            .filter_map(|&(ref arg, ref val)| {
                if arg == "--emit" || arg == "--out-dir" {
                    None
                } else {
                    Some((arg, val))
                }
            })
            .flat_map(|(arg, val)| Some(arg).into_iter().chain(val))
            .map(|a| a.clone())
            .collect::<Vec<_>>();
        // Find all the source files and hash them
        let source_hashes_pool = pool.clone();
        let source_files = get_source_files(creator, &crate_name, &executable, &filtered_arguments, &cwd, &env_vars, pool);
        let source_files_and_hashes = source_files
            .and_then(move |source_files| {
                hash_all(&source_files, &source_hashes_pool).map(|source_hashes| (source_files, source_hashes))
            });
        // Hash the contents of the externs listed on the commandline.
        trace!("[{}]: hashing {} externs", crate_name, externs.len());
        let abs_externs = externs.iter().map(|e| cwd.join(e)).collect::<Vec<_>>();
        let extern_hashes = hash_all(&abs_externs, pool);
        // Hash the contents of the staticlibs listed on the commandline.
        trace!("[{}]: hashing {} staticlibs", crate_name, staticlibs.len());
        let abs_staticlibs = staticlibs.iter().map(|s| cwd.join(s)).collect::<Vec<_>>();
        let staticlib_hashes = hash_all(&abs_staticlibs, pool);
        let creator = creator.clone();
        let hashes = source_files_and_hashes.join3(extern_hashes, staticlib_hashes);
        Box::new(hashes.and_then(move |((source_files, source_hashes), extern_hashes, staticlib_hashes)|
                                        -> SFuture<_> {
            // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
            let mut m = Digest::new();
            // Hash inputs:
            // 1. A version
            m.update(CACHE_VERSION);
            // 2. compiler_shlibs_digests
            for d in compiler_shlibs_digests {
                m.update(d.as_bytes());
            }
            let weak_toolchain_key = m.clone().finish();
            // 3. The full commandline (self.arguments)
            // TODO: there will be full paths here, it would be nice to
            // normalize them so we can get cross-machine cache hits.
            // A few argument types are not passed in a deterministic order
            // by cargo: --extern, -L, --cfg. We'll filter those out, sort them,
            // and append them to the rest of the arguments.
            let args = {
                let (mut sortables, rest): (Vec<_>, Vec<_>) = os_string_arguments.iter()
                    .partition(|&&(ref arg, _)| arg == "--extern" || arg == "-L" || arg == "--cfg");
                sortables.sort();
                rest.into_iter()
                    .chain(sortables)
                    .flat_map(|&(ref arg, ref val)| {
                        iter::once(arg).chain(val.as_ref())
                    })
                    .fold(OsString::new(), |mut a, b| {
                        a.push(b);
                        a
                    })
            };
            args.hash(&mut HashToDigest { digest: &mut m });
            // 4. The digest of all source files (this includes src file from cmdline).
            // 5. The digest of all files listed on the commandline (self.externs).
            // 6. The digest of all static libraries listed on the commandline (self.staticlibs).
            for h in source_hashes.into_iter().chain(extern_hashes).chain(staticlib_hashes) {
                m.update(h.as_bytes());
            }
            // 7. Environment variables. Ideally we'd use anything referenced
            // via env! in the program, but we don't have a way to determine that
            // currently, and hashing all environment variables is too much, so
            // we'll just hash the CARGO_ env vars and hope that's sufficient.
            // Upstream Rust issue tracking getting information about env! usage:
            // https://github.com/rust-lang/rust/issues/40364
            let mut env_vars: Vec<_> = env_vars.iter()
                // Filter out RUSTC_COLOR since we control color usage with command line flags.
                // rustc reports an error when both are present.
                .filter(|(ref k, _)| k != "RUSTC_COLOR")
                .cloned()
                .collect();
            env_vars.sort();
            for &(ref var, ref val) in env_vars.iter() {
                // CARGO_MAKEFLAGS will have jobserver info which is extremely non-cacheable.
                if var.starts_with("CARGO_") && var != "CARGO_MAKEFLAGS" {
                    var.hash(&mut HashToDigest { digest: &mut m });
                    m.update(b"=");
                    val.hash(&mut HashToDigest { digest: &mut m });
                }
            }
            // Turn arguments into a simple Vec<OsString> to calculate outputs.
            let flat_os_string_arguments: Vec<OsString> = os_string_arguments.into_iter()
                .flat_map(|(arg, val)| iter::once(arg).into_iter().chain(val))
                .collect();
            Box::new(get_compiler_outputs(&creator, &executable, &flat_os_string_arguments, &cwd, &env_vars).map(move |outputs| {
                let output_dir = PathBuf::from(output_dir);
                // Convert output files into a map of basename -> full path.
                let mut outputs = outputs.into_iter()
                    .map(|o| {
                        let p = output_dir.join(&o);
                        (o, p)
                    })
                    .collect::<HashMap<_, _>>();
                let dep_info = if let Some(dep_info) = dep_info {
                    let p = output_dir.join(&dep_info);
                    outputs.insert(dep_info.to_string_lossy().into_owned(), p.clone());
                    Some(p)
                } else {
                    None
                };
                let mut arguments = arguments;
                // Always request color output, the client will strip colors if needed.
                arguments.push(Argument::WithValue("--color", ArgData::Color("always".into()), ArgDisposition::Separated));
                let inputs = source_files.into_iter().chain(abs_externs).chain(abs_staticlibs).collect();

                if rename_rlib_to_rmeta {
                    for output in outputs.values_mut() {
                        if output.extension() == Some(OsStr::new("rlib")) {
                            output.set_extension("rmeta");
                        }
                    }
                }

                HashResult {
                    key: m.finish(),
                    compilation: Box::new(RustCompilation {
                        executable: executable,
                        host,
                        sysroot: sysroot,
                        arguments: arguments,
                        inputs: inputs,
                        outputs: outputs,
                        crate_link_paths,
                        crate_name,
                        crate_types,
                        dep_info,
                        cwd,
                        env_vars,
                        #[cfg(feature = "dist-client")]
                        rlib_dep_reader,
                    }),
                    weak_toolchain_key,
                }
            }))
        }))
    }

    fn color_mode(&self) -> ColorMode {
        self.parsed_args.color_mode
    }

    fn output_pretty(&self) -> Cow<str> {
        Cow::Borrowed(&self.parsed_args.crate_name)
    }

    fn box_clone(&self) -> Box<CompilerHasher<T>> {
        Box::new((*self).clone())
    }
}

impl Compilation for RustCompilation {
    fn generate_compile_commands(&self, path_transformer: &mut dist::PathTransformer)
                                -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)>
    {
        let RustCompilation { ref executable, ref arguments, ref crate_name, ref cwd, ref env_vars, #[cfg(feature = "dist-client")] ref host, #[cfg(feature = "dist-client")] ref sysroot, .. } = *self;
        #[cfg(not(feature = "dist-client"))]
        let _ = path_transformer;

        trace!("[{}]: compile", crate_name);

        let command = CompileCommand {
            executable: executable.to_owned(),
            arguments: arguments.iter().flat_map(|arg| arg.iter_os_strings()).collect(),
            env_vars: env_vars.to_owned(),
            cwd: cwd.to_owned(),
        };

        #[cfg(not(feature = "dist-client"))]
        let dist_command = None;
        #[cfg(feature = "dist-client")]
        let dist_command = (|| {
            macro_rules! try_string_arg {
                ($e:expr) => {
                    match $e {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Conversion failed for distributed compile argument: {}", e);
                            return None
                        },
                    }
                };
            }

            let mut dist_arguments = vec![];
            let mut saw_target = false;

            // flat_map would be nice but the lifetimes don't work out
            for argument in arguments.iter() {
                let path_transformer_fn = &mut |p: &Path| path_transformer.to_dist(p);
                if let Argument::Raw(input_path) = argument {
                    // Need to explicitly handle the input argument as it's not parsed as a path
                    let input_path = Path::new(input_path).to_owned();
                    dist_arguments.push(try_string_arg!(input_path.into_arg_string(path_transformer_fn)))
                } else {
                    if let Some(Target(_)) = argument.get_data() {
                        saw_target = true
                    }
                    for string_arg in argument.iter_strings(path_transformer_fn) {
                        dist_arguments.push(try_string_arg!(string_arg))
                    }
                }
            }

            // We can't rely on the packaged toolchain necessarily having the same default target triple
            // as us (typically host triple), so make sure to always explicitly specify a target.
            if !saw_target {
                dist_arguments.push(format!("--target={}", host))
            }

            // Convert the paths of some important environment variables
            let mut env_vars = dist::osstring_tuples_to_strings(env_vars)?;
            let mut changed_out_dir: Option<PathBuf> = None;
            for (k, v) in env_vars.iter_mut() {
                match k.as_str() {
                    // We round-tripped from path to string and back to path, but it should be lossless
                    "OUT_DIR" => {
                        let dist_out_dir = path_transformer.to_dist(Path::new(v))?;
                        if dist_out_dir != *v {
                            changed_out_dir = Some(v.to_owned().into());
                        }
                        *v = dist_out_dir
                    }
                    "CARGO" |
                    "CARGO_MANIFEST_DIR" => {
                        *v = path_transformer.to_dist(Path::new(v))?
                    },
                    _ => (),
                }
            }
            // OUT_DIR was changed during transformation, check if this compilation is relying on anything
            // inside it - if so, disallow distributed compilation (there are sometimes hardcoded paths present)
            if let Some(out_dir) = changed_out_dir {
                if self.inputs.iter().any(|input| input.starts_with(&out_dir)) {
                    return None
                }
            }

            // Add any necessary path transforms - although we haven't packaged up inputs yet, we've
            // probably seen all drives (e.g. on Windows), so let's just transform those rather than
            // trying to do every single path.
            let mut remapped_disks = HashSet::new();
            for (local_path, dist_path) in get_path_mappings(&path_transformer) {
                let local_path = local_path.to_str()?;
                // "The from=to parameter is scanned from right to left, so from may contain '=', but to may not."
                if local_path.contains('=') {
                    return None
                }
                if remapped_disks.contains(&dist_path) {
                    continue
                }
                dist_arguments.push(format!("--remap-path-prefix={}={}", &dist_path, local_path));
                remapped_disks.insert(dist_path);
            }

            let sysroot_executable = sysroot.join(BINS_DIR).join("rustc").with_extension(EXE_EXTENSION);

            Some(dist::CompileCommand {
                executable: path_transformer.to_dist(&sysroot_executable)?,
                arguments: dist_arguments,
                env_vars,
                cwd: path_transformer.to_dist_assert_abs(cwd)?,
            })
        })();

        Ok((command, dist_command, Cacheable::Yes))
    }

    #[cfg(feature = "dist-client")]
    fn into_dist_packagers(self: Box<Self>, path_transformer: dist::PathTransformer) -> Result<(Box<pkg::InputsPackager>, Box<pkg::ToolchainPackager>, Box<OutputsRewriter>)> {

        let RustCompilation { inputs, crate_link_paths, sysroot, crate_types, dep_info, rlib_dep_reader, env_vars, .. } = *{self};
        trace!("Dist inputs: inputs={:?} crate_link_paths={:?}", inputs, crate_link_paths);

        let inputs_packager = Box::new(RustInputsPackager { env_vars, crate_link_paths, crate_types, inputs, path_transformer, rlib_dep_reader });
        let toolchain_packager = Box::new(RustToolchainPackager { sysroot });
        let outputs_rewriter = Box::new(RustOutputsRewriter { dep_info });

        Ok((inputs_packager, toolchain_packager, outputs_rewriter))
    }

    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a Path)> + 'a> {
        Box::new(self.outputs.iter().map(|(k, v)| (k.as_str(), &**v)))
    }
}

// TODO: we do end up with slashes facing the wrong way, but Windows is agnostic so it's
// mostly ok. We currently don't get mappings for every single path because it means we need to
// figure out all prefixes and send them over the wire.
#[cfg(feature = "dist-client")]
fn get_path_mappings(path_transformer: &dist::PathTransformer) -> impl Iterator<Item=(PathBuf, String)> {
    path_transformer.disk_mappings()
}

#[cfg(feature = "dist-client")]
struct RustInputsPackager {
    env_vars: Vec<(OsString, OsString)>,
    crate_link_paths: Vec<PathBuf>,
    crate_types: CrateTypes,
    inputs: Vec<PathBuf>,
    path_transformer: dist::PathTransformer,
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
}

#[cfg(feature = "dist-client")]
impl pkg::InputsPackager for RustInputsPackager {
    fn write_inputs(self: Box<Self>, wtr: &mut io::Write) -> Result<dist::PathTransformer> {
        use ar;
        use tar;

        debug!("Packaging compile inputs for compile");
        let RustInputsPackager { crate_link_paths, crate_types, inputs, mut path_transformer, rlib_dep_reader, env_vars } = *{self};

        // If this is a cargo build, we can assume all immediate `extern crate` dependencies
        // have been passed on the command line, allowing us to scan them all and find the
        // complete list of crates we might need.
        // If it's not a cargo build, we can't to extract the `extern crate` statements and
        // so have no way to build a list of necessary crates - send all rlibs.
        let is_cargo = env_vars.iter().any(|(k, _)| k == "CARGO_PKG_NAME");
        let mut rlib_dep_reader_and_names = if is_cargo {
            rlib_dep_reader.map(|r| (r, HashSet::new()))
        } else {
            None
        };

        let mut tar_inputs = vec![];
        for input_path in inputs.into_iter() {
            let input_path = pkg::simplify_path(&input_path)?;
            if let Some(ext) = input_path.extension() {
                if !CAN_DIST_DYLIBS && ext == DLL_EXTENSION {
                    bail!("Cannot distribute dylib input {} on this platform", input_path.display())
                } else if ext == RLIB_EXTENSION {
                    if let Some((ref rlib_dep_reader, ref mut dep_crate_names)) = rlib_dep_reader_and_names {
                        dep_crate_names.extend(rlib_dep_reader.discover_rlib_deps(&env_vars, &input_path)
                            .chain_err(|| format!("Failed to read deps of {}", input_path.display()))?)
                    }
                }
            }
            let dist_input_path = path_transformer.to_dist(&input_path).unwrap();
            tar_inputs.push((input_path, dist_input_path))
        }

        if log_enabled!(Trace) {
            if let Some((_, ref dep_crate_names)) = rlib_dep_reader_and_names {
                trace!("Identified dependency crate names: {:?}", dep_crate_names)
            }
        }

        // Given the link paths, find the things we need to send over the wire to the remote machine. If
        // we've been able to use a dependency searcher then we can filter down just candidates for that
        // crate, otherwise we need to send everything.
        let mut tar_crate_libs = vec![];
        for crate_link_path in crate_link_paths.into_iter() {
            let crate_link_path = pkg::simplify_path(&crate_link_path)?;
            let dir_entries = match fs::read_dir(crate_link_path) {
                Ok(iter) => iter,
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::with_chain(e, "Failed to read dir entries in crate link path")),
            };
            for entry in dir_entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => return Err(Error::with_chain(e, "Error during iteration over crate link path")),
                };
                let path = entry.path();

                {
                    // Take a look at the path and see if it's something we care about
                    let libname: &str = match path.file_name().and_then(|s| s.to_str()) {
                        Some(name) => {
                            let mut rev_name_split = name.rsplitn(2, '-');
                            let _extra_filename_and_ext = rev_name_split.next();
                            let libname = if let Some(libname) = rev_name_split.next() {
                                libname
                            } else {
                                continue
                            };
                            assert!(rev_name_split.next().is_none());
                            libname
                        },
                        None => continue,
                    };
                    let (crate_name, ext): (&str, _) = match path.extension() {
                        Some(ext) if libname.starts_with(DLL_PREFIX) && ext == DLL_EXTENSION =>
                            (&libname[DLL_PREFIX.len()..], ext),
                        Some(ext) if libname.starts_with(RLIB_PREFIX) && ext == RLIB_EXTENSION =>
                            (&libname[RLIB_PREFIX.len()..], ext),
                        _ => continue,
                    };
                    if let Some((_, ref dep_crate_names)) = rlib_dep_reader_and_names {
                        // We have a list of crate names we care about, see if this lib is a candidate
                        if !dep_crate_names.contains(crate_name) {
                            continue
                        }
                    }
                    if !path.is_file() {
                        continue
                    } else if !CAN_DIST_DYLIBS && ext == DLL_EXTENSION {
                        bail!("Cannot distribute dylib input {} on this platform", path.display())
                    }
                }

                // This is a lib that may be of interest during compilation
                let dist_path = path_transformer.to_dist(&path).unwrap();
                tar_crate_libs.push((path, dist_path))
            }
        }

        let mut all_tar_inputs: Vec<_> = tar_inputs.into_iter().chain(tar_crate_libs).collect();
        all_tar_inputs.sort();
        // There are almost certainly duplicates from explicit externs also within the lib search paths
        all_tar_inputs.dedup();

        // If we're just creating an rlib then the only thing inspected inside dependency rlibs is the
        // metadata, in which case we can create a trimmed rlib (which is actually a .a) with the metadata
        let can_trim_rlibs = if let CrateTypes { rlib: true, staticlib: false } = crate_types { true } else { false };

        let mut builder = tar::Builder::new(wtr);

        for (input_path, dist_input_path) in all_tar_inputs.iter() {
            let mut file_header = pkg::make_tar_header(input_path, dist_input_path)?;
            let file = fs::File::open(input_path)?;
            if can_trim_rlibs && input_path.extension().map(|e| e == RLIB_EXTENSION).unwrap_or(false) {
                let mut archive = ar::Archive::new(file);

                while let Some(entry_result) = archive.next_entry() {
                    let mut entry = entry_result?;
                    if entry.header().identifier() != b"rust.metadata.bin" {
                        continue
                    }
                    let mut metadata = vec![];
                    io::copy(&mut entry, &mut metadata)?;
                    let mut metadata_ar = vec![];
                    {
                        let mut ar_builder = ar::Builder::new(&mut metadata_ar);
                        ar_builder.append(entry.header(), metadata.as_slice())?
                    }
                    file_header.set_size(metadata_ar.len() as u64);
                    file_header.set_cksum();
                    builder.append(&file_header, metadata_ar.as_slice())?;
                    break
                }
            } else {
                file_header.set_cksum();
                builder.append(&file_header, file)?
            }
        }

        // Finish archive
        let _ = builder.into_inner()?;
        Ok(path_transformer)
    }
}

#[cfg(feature = "dist-client")]
#[allow(unused)]
struct RustToolchainPackager {
    sysroot: PathBuf,
}

#[cfg(feature = "dist-client")]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl pkg::ToolchainPackager for RustToolchainPackager {
    fn write_pkg(self: Box<Self>, f: fs::File) -> Result<()> {
        use walkdir::WalkDir;

        info!("Packaging Rust compiler for sysroot {}", self.sysroot.display());
        let RustToolchainPackager { sysroot } = *self;

        let mut package_builder = pkg::ToolchainPackageBuilder::new();
        package_builder.add_common()?;

        let bins_path = sysroot.join(BINS_DIR);
        let sysroot_executable = bins_path.join("rustc").with_extension(EXE_EXTENSION);
        package_builder.add_executable_and_deps(sysroot_executable)?;

        // Although by not following symlinks we could break a custom constructed toolchain with
        // links everywhere, this is just a best-effort auto packaging
        fn walk_and_add(path: &Path, package_builder: &mut pkg::ToolchainPackageBuilder) -> Result<()> {
            for entry in WalkDir::new(path).follow_links(false) {
                let entry = entry?;
                let file_type = entry.file_type();
                if file_type.is_dir() {
                    continue
                } else if file_type.is_symlink() {
                    let metadata = fs::metadata(entry.path())?;
                    if !metadata.file_type().is_file() {
                        continue
                    }
                } else if !file_type.is_file() {
                    // Device or other oddity
                    continue
                }
                // It's either a file, or a symlink pointing to a file
                package_builder.add_file(entry.path().to_owned())?
            }
            Ok(())
        }

        walk_and_add(&bins_path, &mut package_builder)?;
        if BINS_DIR != LIBS_DIR {
            let libs_path = sysroot.join(LIBS_DIR);
            walk_and_add(&libs_path, &mut package_builder)?
        }

        package_builder.into_compressed_tar(f)
    }
}

#[cfg(feature = "dist-client")]
struct RustOutputsRewriter {
    dep_info: Option<PathBuf>,
}

#[cfg(feature = "dist-client")]
impl OutputsRewriter for RustOutputsRewriter {
    fn handle_outputs(self: Box<Self>, path_transformer: &dist::PathTransformer, output_paths: Vec<(String, PathBuf)>)
                      -> Result<()> {
        use std::io::{Seek, Write};

        // Outputs in dep files (the files at the beginning of lines) are untransformed - remap-path-prefix is documented
        // to only apply to 'inputs'.
        trace!("Pondering on rewriting dep file {:?}", self.dep_info);
        if let Some(dep_info) = self.dep_info {
            for (_dep_info_dist_path, dep_info_local_path) in output_paths {
                trace!("Comparing with {}", dep_info_local_path.display());
                if dep_info == dep_info_local_path {
                    error!("Replacing using the transformer {:?}", path_transformer);
                    // Found the dep info file
                    let mut f = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(dep_info)?;
                    let mut deps = String::new();
                    f.read_to_string(&mut deps)?;
                    for (local_path, dist_path) in get_path_mappings(path_transformer) {
                        let re_str = format!("(?m)^{}", regex::escape(&dist_path));
                        error!("RE replacing {} with {} in {}", re_str, local_path.to_str().unwrap(), deps);
                        let re = regex::Regex::new(&re_str).expect("Invalid regex");
                        deps = re.replace_all(&deps, local_path.to_str().unwrap()).into_owned();
                    }
                    f.seek(io::SeekFrom::Start(0))?;
                    f.write_all(deps.as_bytes())?;
                    f.set_len(deps.len() as u64)?;
                    return Ok(())
                }
            }
            // We expected there to be dep info, but none of the outputs matched
            bail!("No outputs matched dep info file {}", dep_info.display());
        }
        Ok(())
    }
}


#[cfg(feature = "dist-client")]
#[derive(Debug)]
struct RlibDepsDetail {
    deps: Vec<String>,
    mtime: time::SystemTime,
}

#[cfg(feature = "dist-client")]
struct DepsSize;
#[cfg(feature = "dist-client")]
impl lru_cache::Meter<PathBuf, RlibDepsDetail> for DepsSize {
    type Measure = usize;
    fn measure<Q: ?Sized>(&self, _k: &Q, v: &RlibDepsDetail) -> usize where PathBuf: Borrow<Q>
    {
        use std::mem;

        // TODO: unfortunately there is exactly nothing you can do with the k given the
        // current trait bounds. Just use some kind of sane value;
        //let k_size = mem::size_of::<PathBuf>() + k.capacity();
        let k_size = 3*8 + 100;

        let crate_names_size: usize = v.deps.iter().map(|s| s.capacity()).sum();
        let v_size: usize =
            mem::size_of::<RlibDepsDetail>() + // Systemtime and vec itself
            v.deps.capacity() * mem::size_of::<String>() + // Each string in the vec
            crate_names_size; // Contents of all strings

        k_size + v_size
    }
}

#[cfg(feature = "dist-client")]
#[derive(Debug)]
struct RlibDepReader {
    cache: Mutex<lru_cache::LruCache<PathBuf, RlibDepsDetail, RandomState, DepsSize>>,
    executable: PathBuf,
}

#[cfg(feature = "dist-client")]
impl RlibDepReader {
    fn new_with_check(executable: PathBuf, env_vars: &[(OsString, OsString)]) -> Result<Self> {
        let temp_dir = TempDir::new("sccache-rlibreader")
            .chain_err(|| "Could not create temporary directory for rlib output")?;
        let temp_rlib = temp_dir.path().join("x.rlib");

        let mut cmd = process::Command::new(&executable);
        cmd
            .arg("--crate-type=rlib")
            .arg("-o").arg(&temp_rlib)
            .arg("-")
            .env_clear()
            .envs(ref_env(env_vars));

        let process::Output { status, stdout, stderr } = cmd.output()?;

        if !status.success() {
            bail!("Failed to compile a minimal rlib with {}", executable.display())
        }
        if !stdout.is_empty() {
            bail!("rustc stdout non-empty when compiling a minimal rlib: {:?}", String::from_utf8_lossy(&stdout))
        }
        if !stderr.is_empty() {
            bail!("rustc stderr non-empty when compiling a minimal rlib: {:?}", String::from_utf8_lossy(&stderr))
        }

        // The goal of this cache is to avoid repeated lookups when building a single project. Let's budget 3MB.
        // Allowing for a 100 byte path, 50 dependecies per rlib and 20 characters per crate name, this roughly
        // approximates to `path_size + path + vec_size + num_deps * (systemtime_size + string_size + crate_name_len)`
        //                 `   3*8    +  100 +   3*8    +    50    * (      8         +     3*8     +       20      )`
        //                 `2748` bytes per crate
        // Allowing for possible overhead of up to double (for unused space in allocated memory), this means we
        // can cache information from about 570 rlibs - easily enough for a single project.
        const CACHE_SIZE: u64 = 3*1024*1024;
        let cache = lru_cache::LruCache::with_meter(CACHE_SIZE, DepsSize);

        let rlib_dep_reader = RlibDepReader { cache: Mutex::new(cache), executable };
        if let Err(e) = rlib_dep_reader.discover_rlib_deps(env_vars, &temp_rlib) {
            bail!("Failed to read deps from minimal rlib: {}", e)
        }

        Ok(rlib_dep_reader)
    }

    fn discover_rlib_deps(&self, env_vars: &[(OsString, OsString)], rlib: &Path) -> Result<Vec<String>> {
        let rlib_mtime = fs::metadata(&rlib).and_then(|m| m.modified()).chain_err(|| "Unable to get rlib modified time")?;

        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(deps_detail) = cache.get(rlib) {
                if rlib_mtime == deps_detail.mtime {
                    return Ok(deps_detail.deps.clone())
                }
            }
        }

        trace!("Discovering dependencies of {}", rlib.display());

        let mut cmd = process::Command::new(&self.executable);
        cmd.args(&["-Z", "ls"]).arg(&rlib)
            .env_clear()
            .envs(ref_env(env_vars))
            .env("RUSTC_BOOTSTRAP", "1"); // TODO: this is fairly naughty

        let process::Output { status, stdout, stderr } = cmd.output()?;

        if !status.success() {
            bail!(format!("Failed to list deps of {}", rlib.display()))
        }
        if !stderr.is_empty() {
            bail!("rustc -Z ls stderr non-empty: {:?}", String::from_utf8_lossy(&stderr))
        }

        let stdout = String::from_utf8(stdout).chain_err(|| "Error parsing rustc -Z ls output")?;
        let deps: Vec<_> = parse_rustc_z_ls(&stdout)
            .map(|deps| deps.into_iter().map(|dep| dep.to_owned()).collect())?;

        {
            // This will behave poorly if the rlib is changing under our feet, but in that case rustc
            // will also do the wrong thing, so the user has bigger issues to deal with.
            let mut cache = self.cache.lock().unwrap();
            cache.insert(rlib.to_owned(), RlibDepsDetail { deps: deps.clone(), mtime: rlib_mtime });
        }
        Ok(deps)
    }
}

// Parse output like the following:
//
// ```
// =External Dependencies=
// 1 std-08a5bd1ca58a28ee
// 2 core-ed31c38c1a60e6f9
// 3 compiler_builtins-6bd92a903b271497
// 4 alloc-5184f4fa2c87f835
// 5 alloc_system-7a70df28ae5ce6c3
// 6 libc-fb97b8e8c331f065
// 7 unwind-3fec89e45492b583
// 8 alloc_jemalloc-3e9fce05c4bf31e5
// 9 panic_unwind-376f1801255ba526
// 10 bitflags-f482823cbc05f4d7
// 11 cfg_if-cf72e166fff77ced
// ```
#[cfg(feature = "dist-client")]
fn parse_rustc_z_ls(stdout: &str) -> Result<Vec<&str>> {
    let mut lines = stdout.lines();
    match lines.next() {
        Some("=External Dependencies=") => {},
        Some(s) => bail!("Unknown first line from rustc -Z ls: {}", s),
        None => bail!("No output from rustc -Z ls"),
    }

    let mut dep_names = vec![];

    while let Some(line) = lines.next() {
        if line == "" {
            break
        }

        let mut line_splits = line.splitn(2, ' ');
        let num: usize = line_splits.next().expect("Zero strings from line split").parse()
            .chain_err(|| "Could not parse number from rustc -Z ls")?;
        let libstring = line_splits.next().ok_or_else(|| "No lib string on line from rustc -Z ls")?;
        if num != dep_names.len() + 1 {
            bail!("Unexpected numbering of {} in rustc -Z ls output", libstring)
        }
        assert!(line_splits.next().is_none());

        let mut libstring_splits = libstring.rsplitn(2, '-');
        // Rustc prints strict hash value (rather than extra filename as it likely should be)
        let _svh = libstring_splits.next().ok_or_else(|| "No hash in lib string from rustc -Z ls")?;
        let libname = libstring_splits.next().expect("Zero strings from libstring split");
        assert!(libstring_splits.next().is_none());

        dep_names.push(libname);
    }

    while let Some(line) = lines.next() {
        if line != "" {
            bail!("Trailing non-blank lines in rustc -Z ls output")
        }
    }

    Ok(dep_names)
}

#[cfg(test)]
mod test {
    use super::*;

    use compiler::*;
    use itertools::Itertools;
    use mock_command::*;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::Write;
    use std::sync::{Arc,Mutex};
    use test::utils::*;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments>
    {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&arguments, ".".as_ref())
    }

    macro_rules! parses {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(a) => a,
                o @ _ => panic!("Got unexpected parse result: {:?}", o),
            }
        }
    }

    macro_rules! fails {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(_) => panic!("Should not have parsed ok: `{}`", stringify!($( $s, )*)),

                o @ _ => o,
            }
        }
    }

    #[test]
    fn test_parse_arguments_simple() {
        let h = parses!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib");
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert!(h.dep_info.is_none());
        assert!(h.externs.is_empty());
        let h = parses!("--emit=link", "foo.rs", "--out-dir", "out", "--crate-name=foo", "--crate-type=lib");
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert!(h.dep_info.is_none());
        let h = parses!("--emit", "link", "foo.rs", "--out-dir=out", "--crate-name=foo", "--crate-type=lib");
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert_eq!(parses!("--emit", "link", "-C", "opt-level=1", "foo.rs",
                           "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib"),
                   parses!("--emit=link", "-Copt-level=1", "foo.rs",
                           "--out-dir=out", "--crate-name=foo", "--crate-type=lib"));
        let h = parses!("--emit", "link,dep-info", "foo.rs", "--out-dir", "out",
                        "--crate-name", "my_crate", "--crate-type", "lib",
                        "-C", "extra-filename=-abcxyz");
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert_eq!(h.dep_info.unwrap().to_str().unwrap(), "my_crate-abcxyz.d");
        fails!("--emit", "link", "--out-dir", "out", "--crate-name=foo", "--crate-type=lib");
        fails!("--emit", "link", "foo.rs", "--crate-name=foo", "--crate-type=lib");
        fails!("--emit", "asm", "foo.rs", "--out-dir", "out", "--crate-name=foo", "--crate-type=lib");
        fails!("--emit", "asm,link", "foo.rs", "--out-dir", "out", "--crate-name=foo", "--crate-type=lib");
        fails!("--emit", "asm,link,dep-info", "foo.rs", "--out-dir", "out", "--crate-name=foo", "--crate-type=lib");
        fails!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name=foo");
        fails!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-type=lib");
        // From an actual cargo compilation, with some args shortened:
        let h = parses!("--crate-name", "foo", "src/lib.rs",
                        "--crate-type", "lib", "--emit=dep-info,link",
                        "-C", "debuginfo=2", "-C", "metadata=d6ae26f5bcfb7733",
                        "-C", "extra-filename=-d6ae26f5bcfb7733",
                        "--out-dir", "/foo/target/debug/deps",
                        "-L", "dependency=/foo/target/debug/deps",
                        "--extern", "libc=/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
                        "--extern", "log=/foo/target/debug/deps/liblog-2f7366be74992849.rlib");
        assert_eq!(h.output_dir.to_str(), Some("/foo/target/debug/deps"));
        assert_eq!(h.crate_name, "foo");
        assert_eq!(h.dep_info.unwrap().to_str().unwrap(),
                   "foo-d6ae26f5bcfb7733.d");
        assert_eq!(h.externs, ovec!["/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib", "/foo/target/debug/deps/liblog-2f7366be74992849.rlib"]);
    }

    #[test]
    fn test_parse_arguments_incremental() {
        parses!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib");
        let r = fails!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib",
                       "-C", "incremental=/foo");
        assert_eq!(r, CompilerArguments::CannotCache("incremental", None))
    }

    #[test]
    fn test_parse_arguments_dep_info_no_extra_filename() {
        let h = parses!("--crate-name", "foo", "--crate-type", "lib", "src/lib.rs",
                        "--emit=dep-info,link",
                        "--out-dir", "/out");
        assert_eq!(h.dep_info, Some("foo.d".into()));
    }

    #[test]
    fn test_parse_arguments_native_libs() {
        parses!("--crate-name", "foo", "--crate-type", "lib,staticlib", "--emit", "link", "-l", "bar", "foo.rs",
                "--out-dir", "out");
        parses!("--crate-name", "foo", "--crate-type", "lib,staticlib", "--emit", "link", "-l", "static=bar", "foo.rs",
                "--out-dir", "out");
        parses!("--crate-name", "foo", "--crate-type", "lib,staticlib", "--emit", "link", "-l", "dylib=bar", "foo.rs",
                "--out-dir", "out");
    }

    #[test]
    fn test_parse_arguments_non_rlib_crate() {
        parses!("--crate-type", "rlib", "--emit", "link", "foo.rs", "--out-dir", "out",
                "--crate-name", "foo");
        parses!("--crate-type", "lib", "--emit", "link", "foo.rs", "--out-dir", "out",
                "--crate-name", "foo");
        parses!("--crate-type", "staticlib", "--emit", "link", "foo.rs", "--out-dir", "out",
                "--crate-name", "foo");
        parses!("--crate-type", "rlib,staticlib", "--emit", "link", "foo.rs", "--out-dir", "out",
                "--crate-name", "foo");
        fails!("--crate-type", "bin", "--emit", "link", "foo.rs", "--out-dir", "out",
               "--crate-name", "foo");
        fails!("--crate-type", "rlib,dylib", "--emit", "link", "foo.rs", "--out-dir", "out",
               "--crate-name", "foo");
    }

    #[test]
    fn test_parse_arguments_color() {
        let h = parses!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib");
        assert_eq!(h.color_mode, ColorMode::Auto);
        let h = parses!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib",
                        "--color=always");
        assert_eq!(h.color_mode, ColorMode::On);
        let h = parses!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib",
                        "--color=never");
        assert_eq!(h.color_mode, ColorMode::Off);
        let h = parses!("--emit", "link", "foo.rs", "--out-dir", "out", "--crate-name", "foo", "--crate-type", "lib",
                        "--color=auto");
        assert_eq!(h.color_mode, ColorMode::Auto);
    }

    #[test]
    fn test_get_compiler_outputs() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nbar\nbaz", "")));
        let outputs = get_compiler_outputs(&creator,
                                           "rustc".as_ref(),
                                           &ovec!("a", "b"),
                                           "cwd".as_ref(),
                                           &[]).wait().unwrap();
        assert_eq!(outputs, &["foo", "bar", "baz"]);
    }

    #[test]
    fn test_get_compiler_outputs_fail() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "error")));
        assert!(get_compiler_outputs(&creator,
                                     "rustc".as_ref(),
                                     &ovec!("a", "b"),
                                     "cwd".as_ref(),
                                     &[]).wait().is_err());
    }

    #[test]
    fn test_parse_dep_info() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(pathvec!["abc.rs", "bar.rs", "baz.rs"],
                   parse_dep_info(&deps, ""));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_parse_dep_info_cwd() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(pathvec!["foo/abc.rs", "foo/bar.rs", "foo/baz.rs"],
                   parse_dep_info(&deps, "foo/"));

        assert_eq!(pathvec!["/foo/bar/abc.rs", "/foo/bar/bar.rs", "/foo/bar/baz.rs"],
                   parse_dep_info(&deps, "/foo/bar/"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_parse_dep_info_abs_paths() {
        let deps = "/foo/foo: /foo/baz.rs /foo/abc.rs /foo/bar.rs

/foo/baz.rs:

/foo/abc.rs:

/foo/bar.rs:
";
        assert_eq!(pathvec!["/foo/abc.rs", "/foo/bar.rs", "/foo/baz.rs"],
                   parse_dep_info(&deps, "/bar/"));
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_dep_info_cwd() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(pathvec!["foo/abc.rs", "foo/bar.rs", "foo/baz.rs"],
                   parse_dep_info(&deps, "foo/"));

        assert_eq!(pathvec!["c:/foo/bar/abc.rs", "c:/foo/bar/bar.rs", "c:/foo/bar/baz.rs"],
                   parse_dep_info(&deps, "c:/foo/bar/"));
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_dep_info_abs_paths() {
        let deps = "c:/foo/foo: c:/foo/baz.rs c:/foo/abc.rs c:/foo/bar.rs

c:/foo/baz.rs: c:/foo/bar.rs
c:/foo/abc.rs:
c:/foo/bar.rs:
";
        assert_eq!(pathvec!["c:/foo/abc.rs", "c:/foo/bar.rs", "c:/foo/baz.rs"],
                   parse_dep_info(&deps, "c:/bar/"));
    }

    fn mock_dep_info(creator: &Arc<Mutex<MockCommandCreator>>, dep_srcs: &[&str])
    {
        // Mock the `rustc --emit=dep-info` process by writing
        // a dep-info file.
        let mut sorted_deps = dep_srcs.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        sorted_deps.sort();
        next_command_calls(creator, move |args| {
            let mut dep_info_path = None;
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if a == "-o" {
                    dep_info_path = it.next();
                    break;
                }
            }
            let dep_info_path = dep_info_path.unwrap();
            let mut f = File::create(dep_info_path)?;
            writeln!(f, "blah: {}", sorted_deps.iter().join(" "))?;
            for d in sorted_deps.iter() {
                writeln!(f, "{}:", d)?;
            }
            Ok(MockChild::new(exit_status(0), "", ""))
        });
    }

    fn mock_file_names(creator: &Arc<Mutex<MockCommandCreator>>, filenames: &[&str])
    {
        // Mock the `rustc --print=file-names` process output.
        next_command(&creator, Ok(MockChild::new(exit_status(0), filenames.iter().join("\n"), "")));
    }

    #[test]
    fn test_generate_hash_key() {
        use env_logger;
        drop(env_logger::try_init());
        let f = TestFixture::new();
        const FAKE_DIGEST: &'static str = "abcd1234";
        // We'll just use empty files for each of these.
        for s in ["foo.rs", "bar.rs", "bar.rlib", "libbaz.a"].iter() {
            f.touch(s).unwrap();
        }
        let hasher = Box::new(RustHasher {
            executable: "rustc".into(),
            host: "x86-64-unknown-unknown-unknown".to_owned(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![FAKE_DIGEST.to_owned()],
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            parsed_args: ParsedArguments {
                arguments: vec![
                    Argument::Raw("a".into()),
                    Argument::WithValue("--extern".into(),
                                        ArgData::Extern(ArgExtern::process("xyz=/xyz".into()).unwrap()),
                                        ArgDisposition::Separated),
                    Argument::Raw("b".into()),
                    Argument::WithValue("--extern".into(),
                                        ArgData::Extern(ArgExtern::process("abc=/abc".into()).unwrap()),
                                        ArgDisposition::Separated),
                ],
                output_dir: "foo/".into(),
                externs: vec!["bar.rlib".into()],
                crate_link_paths: vec![],
                staticlibs: vec![f.tempdir.path().join("libbaz.a")],
                crate_name: "foo".into(),
                crate_types: CrateTypes { rlib: true, staticlib: false },
                dep_info: None,
                rename_rlib_to_rmeta: false,
                color_mode: ColorMode::Auto,
            }
        });
        let creator = new_creator();
        mock_dep_info(&creator, &["foo.rs", "bar.rs"]);
        mock_file_names(&creator, &["foo.rlib", "foo.a"]);
        let pool = CpuPool::new(1);
        let res = hasher.generate_hash_key(&creator,
                                           f.tempdir.path().to_owned(),
                                           [(OsString::from("CARGO_PKG_NAME"), OsString::from("foo")),
                                            (OsString::from("FOO"), OsString::from("bar")),
                                            (OsString::from("CARGO_BLAH"), OsString::from("abc"))].to_vec(),
                                           false,
                                           &pool).wait().unwrap();
        let m = Digest::new();
        let empty_digest = m.finish();

        let mut m = Digest::new();
        // Version.
        m.update(CACHE_VERSION);
        // sysroot shlibs digests.
        m.update(FAKE_DIGEST.as_bytes());
        // Arguments, with externs sorted at the end.
        OsStr::new("ab--externabc=/abc--externxyz=/xyz").hash(&mut HashToDigest { digest: &mut m });
        // bar.rs (source file, from dep-info)
        m.update(empty_digest.as_bytes());
        // foo.rs (source file, from dep-info)
        m.update(empty_digest.as_bytes());
        // bar.rlib (extern crate, from externs)
        m.update(empty_digest.as_bytes());
        // libbaz.a (static library, from staticlibs)
        m.update(empty_digest.as_bytes());
        // Env vars
        OsStr::new("CARGO_BLAH").hash(&mut HashToDigest { digest: &mut m });
        m.update(b"=");
        OsStr::new("abc").hash(&mut HashToDigest { digest: &mut m });
        OsStr::new("CARGO_PKG_NAME").hash(&mut HashToDigest { digest: &mut m });
        m.update(b"=");
        OsStr::new("foo").hash(&mut HashToDigest { digest: &mut m });
        let digest = m.finish();
        assert_eq!(res.key, digest);
        let mut out = res.compilation.outputs().map(|(k, _)| k.to_owned()).collect::<Vec<_>>();
        out.sort();
        assert_eq!(out, vec!["foo.a", "foo.rlib"]);
    }

    fn hash_key<'a, F>(args: &[OsString], env_vars: &[(OsString, OsString)], pre_func: F)
                   -> String
        where F: Fn(&Path) -> Result<()>
    {
        let f = TestFixture::new();
        let parsed_args = match parse_arguments(args, &f.tempdir.path()) {
            CompilerArguments::Ok(parsed_args) => parsed_args,
            o @ _ => panic!("Got unexpected parse result: {:?}", o),
        };
        // Just use empty files for sources.
        for src in ["foo.rs"].iter() {
            let s = format!("Failed to create {}", src);
            f.touch(src).expect(&s);
        }
        // as well as externs
        for e in parsed_args.externs.iter() {
            let s = format!("Failed to create {:?}", e);
            f.touch(e.to_str().unwrap()).expect(&s);
        }
        pre_func(&f.tempdir.path()).expect("Failed to execute pre_func");
        let hasher = Box::new(RustHasher {
            executable: "rustc".into(),
            host: "x86-64-unknown-unknown-unknown".to_owned(),
            sysroot: f.tempdir.path().join("sysroot"),
            compiler_shlibs_digests: vec![],
            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            parsed_args: parsed_args,
        });

        let creator = new_creator();
        let pool = CpuPool::new(1);
        mock_dep_info(&creator, &["foo.rs"]);
        mock_file_names(&creator, &["foo.rlib"]);
        hasher.generate_hash_key(&creator, f.tempdir.path().to_owned(), env_vars.to_owned(), false, &pool)
            .wait().unwrap().key
    }

    fn nothing(_path: &Path) -> Result<()> { Ok(()) }

    #[test]
    fn test_equal_hashes_externs() {
        // Put some content in the extern rlibs so we can verify that the content hashes are
        // used in the right order.
        fn mk_files(tempdir: &Path) -> Result<()> {
            create_file(tempdir, "a.rlib", |mut f| f.write_all(b"this is a.rlib"))?;
            create_file(tempdir, "b.rlib", |mut f| f.write_all(b"this is b.rlib"))?;
            Ok(())
        }
        assert_eq!(hash_key(&ovec!["--emit", "link", "foo.rs", "--extern", "a=a.rlib", "--out-dir",
                                   "out", "--crate-name", "foo", "--crate-type", "lib",
                                   "--extern", "b=b.rlib"], &vec![],
                            &mk_files),
                   hash_key(&ovec!["--extern", "b=b.rlib", "--emit", "link", "--extern", "a=a.rlib",
                                   "foo.rs", "--out-dir", "out", "--crate-name", "foo",
                                   "--crate-type", "lib"], &vec![],
                            &mk_files));
    }

    #[test]
    fn test_equal_hashes_link_paths() {
        assert_eq!(hash_key(&ovec!["--emit", "link", "-L", "x=x", "foo.rs", "--out-dir", "out",
                                   "--crate-name", "foo", "--crate-type", "lib",
                                   "-L", "y=y"], &vec![], nothing),
                   hash_key(&ovec!["-L", "y=y", "--emit", "link", "-L", "x=x", "foo.rs",
                                   "--out-dir", "out", "--crate-name", "foo",
                                   "--crate-type", "lib"], &vec![], nothing));
    }

    #[test]
    fn test_equal_hashes_cfg_features() {
        assert_eq!(hash_key(&ovec!["--emit", "link", "--cfg", "feature=a", "foo.rs", "--out-dir",
                                   "out", "--crate-name", "foo", "--crate-type", "lib",
                                   "--cfg", "feature=b"], &vec![],
                            nothing),
                   hash_key(&ovec!["--cfg", "feature=b", "--emit", "link", "--cfg", "feature=a",
                                   "foo.rs", "--out-dir", "out", "--crate-name", "foo",
                                   "--crate-type", "lib"], &vec![],
                            nothing));
    }
}
