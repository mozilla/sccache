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

use compiler::{Cacheable, Compiler, CompilerArguments, CompilerHasher, CompilerKind, Compilation,
               HashResult, run_input_output};
use futures::{Future, future};
use futures_cpupool::CpuPool;
use log::LogLevel::Trace;
use mock_command::{CommandCreatorSync, RunCommand};
use sha1;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::env::consts::DLL_EXTENSION;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::slice;
use std::time::Instant;
use tempdir::TempDir;
use util::{fmt_duration_as_secs, os_str_bytes, sha1_digest};

use errors::*;

/// Directory in the sysroot containing shared libraries to which rustc is linked.
#[cfg(not(windows))]
const LIBS_DIR: &'static str = "lib";

/// Directory in the sysroot containing shared libraries to which rustc is linked.
#[cfg(windows)]
const LIBS_DIR: &'static str = "bin";

/// A struct on which to hang a `Compiler` impl.
#[derive(Debug, Clone)]
pub struct Rust {
    /// The path to the rustc executable.
    executable: String,
    /// The SHA-1 digests of all the shared libraries in rustc's $sysroot/lib (or /bin on Windows).
    compiler_shlibs_digests: Vec<String>,
}

/// A struct on which to hang a `CompilerHasher` impl.
#[derive(Debug, Clone)]
pub struct RustHasher {
    /// The path to the rustc executable.
    executable: String,
    /// The SHA-1 digests of all the shared libraries in rustc's $sysroot/lib (or /bin on Windows).
    compiler_shlibs_digests: Vec<String>,
    parsed_args: ParsedArguments,
}

#[derive(Debug, Clone)]
pub struct ParsedArguments {
    /// The full commandline, with arguments and their values as pairs.
    arguments: Vec<(String, Option<String>)>,
    /// The location of compiler outputs.
    output_dir: String,
    /// Paths to extern crates used in the compile.
    externs: Vec<String>,
    /// The crate name passed to --crate-name.
    crate_name: String,
    /// If dependency info is being emitted, the name of the dep info file.
    dep_info: Option<String>,
}

/// A struct on which to hang a `Compilation` impl.
#[derive(Debug, Clone)]
pub struct RustCompilation {
    /// The path to the rustc executable.
    executable: String,
    /// The full commandline.
    arguments: Vec<String>,
    /// The compiler outputs.
    outputs: HashMap<String, String>,
    /// The crate name being compiled.
    crate_name: String,
}

/// Arguments that take a value.
const ARGS_WITH_VALUE: &'static [&'static str] = &[
    // These are taken from https://github.com/rust-lang/rust/blob/b671c32ddc8c36d50866428d83b7716233356721/src/librustc/session/config.rs#L1186
    "--cfg",
    "-L",
    "-l",
    "--crate-type",
    "--crate-name",
    "--emit",
    "--print",
    "-o",
    "--out-dir",
    "--explain",
    "--target",
    "-W", "--warn",
    "-A", "--allow",
    "-D", "--deny",
    "-F", "--forbid",
    "--cap-lints",
    "-C", "--codegen",
    "--extern",
    "--sysroot",
    "-Z",
    "--error-format",
    "--color",
    "--pretty",
    "--unpretty",
];

/// Emit types that we will cache.
const ALLOWED_EMIT: &'static [&'static str] = &["link", "dep-info"];

/// Version number for cache key.
const CACHE_VERSION: &'static [u8] = b"1";

/// Return true if `arg` is in the set of arguments `set`.
fn arg_in(arg: &str, set: &HashSet<&str>) -> bool
{
    set.contains(arg) || set.iter().any(|a| arg.starts_with(a))
}

/// Calculate the SHA-1 digest of each file in `files` on background threads
/// in `pool`.
fn hash_all(files: Vec<String>, pool: &CpuPool) -> SFuture<Vec<String>>
{
    let start = Instant::now();
    let count = files.len();
    let pool = pool.clone();
    Box::new(future::join_all(files.into_iter().map(move |f| sha1_digest(f, &pool)))
             .map(move |hashes| {
                 trace!("Hashed {} files in {}", count, fmt_duration_as_secs(&start.elapsed()));
                 hashes
             }))
}

/// Calculate SHA-1 digests for all source files listed in rustc's dep-info output.
fn hash_source_files<T>(creator: &T, crate_name: &str, executable: &str, arguments: &[String],
                        cwd: &str, env_vars: &[(OsString, OsString)], pool: &CpuPool)
                        -> SFuture<Vec<String>>
    where T: CommandCreatorSync,
{
    let start = Instant::now();
    // Get the full list of source files from rustc's dep-info.
    let temp_dir = match TempDir::new("sccache") {
        Ok(d) => d,
        _ => return f_err("Failed to create temp dir"),
    };
    let dep_file = temp_dir.path().join("deps.d");
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--emit", "dep-info"])
        .arg("-o")
        .arg(&dep_file)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);
    trace!("[{}]: get dep-info: {:?}", crate_name, cmd);
    let dep_info = run_input_output(cmd, None);
    // Parse the dep-info file, then hash the contents of those files.
    let pool = pool.clone();
    let cwd = cwd.to_owned();
    let crate_name = crate_name.to_owned();
    Box::new(dep_info.and_then(move |output| -> SFuture<_> {
        if output.status.success() {
            let name2 = crate_name.clone();
            let parsed = pool.spawn_fn(move || {
                parse_dep_file(&dep_file, &cwd).chain_err(|| {
                    format!("Failed to parse dep info for {}", name2)
                })
            });
            Box::new(parsed.and_then(move |files| {
                trace!("[{}]: got {} source files from dep-info in {}", crate_name,
                       files.len(), fmt_duration_as_secs(&start.elapsed()));
                // Just to make sure we capture temp_dir.
                drop(temp_dir);
                hash_all(files, &pool)
            }))
        } else {
            f_err(format!("Failed run rustc --dep-info. rustc stderr: `{}`",
                          String::from_utf8_lossy(&output.stderr)))
        }
    }))
}

/// Parse dependency info from `file` and return a Vec of files mentioned.
/// Treat paths as relative to `cwd`.
fn parse_dep_file<T, U>(file: T, cwd: U) -> Result<Vec<String>>
    where T: AsRef<Path>,
          U: AsRef<Path>,
{
    let mut f = File::open(file)?;
    let mut deps = String::new();
    f.read_to_string(&mut deps)?;
    Ok(parse_dep_info(&deps, cwd))
}

fn parse_dep_info<T>(dep_info: &str, cwd: T) -> Vec<String>
    where T: AsRef<Path>
{
    let cwd = cwd.as_ref();
    let mut deps = dep_info.lines()
        // The first line is the dependencies on the dep file itself.
        .skip(1)
        .filter_map(|l| if l.is_empty() { None } else { l.split(":").next() })
        .map(|s| cwd.join(s).to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    deps.sort();
    deps
}

/// Run `rustc --print file-names` to get the outputs of compilation.
fn get_compiler_outputs<T>(creator: &T, executable: &str, arguments: &[String], cwd: &str,
                           env_vars: &[(OsString, OsString)]) -> SFuture<Vec<String>>
    where T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--print", "file-names"])
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("get_compiler_outputs: {:?}", cmd);
    }
    let outputs = run_input_output(cmd, None);
    Box::new(outputs.and_then(move |output| -> Result<_> {
        if output.status.success() {
            let outstr = String::from_utf8(output.stdout).chain_err(|| "Error parsing rustc output")?;
            Ok(outstr.lines().map(|l| l.to_owned()).collect())
        } else {
            bail!("Failed to run `rustc --print file-names`");
        }
    }))
}

impl Rust {
    /// Create a new Rust compiler instance, calculating the hashes of
    /// all the shared libraries in its sysroot.
    pub fn new<T>(mut creator: T, executable: String, pool: CpuPool) -> SFuture<Rust>
        where T: CommandCreatorSync,
    {
        let mut cmd = creator.new_command_sync(&executable);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::null())
            .arg("--print=sysroot");
        let output = run_input_output(cmd, None);
        let libs = output.and_then(move |output| -> Result<_> {
            if !output.status.success() {
                bail!("Failed to determine sysroot");
            }
            let outstr = String::from_utf8(output.stdout).chain_err(|| "Error parsing sysroot")?;
            let libs_path = Path::new(outstr.trim_right()).join(LIBS_DIR);
            let mut libs = fs::read_dir(&libs_path).chain_err(|| format!("Failed to list rustc sysroot: `{:?}`", libs_path))?.filter_map(|e| {
                e.ok().and_then(|e| {
                    e.file_type().ok().and_then(|t| {
                        let p = e.path();
                        if t.is_file() && p.extension().map(|e| e == DLL_EXTENSION).unwrap_or(false) {
                            p.into_os_string().into_string().ok()
                        } else {
                            None
                        }
                    })
                })
            }).collect::<Vec<_>>();
            libs.sort();
            Ok(libs)
        });
        Box::new(libs.and_then(move |libs| {
            hash_all(libs, &pool).map(move |digests| {
                Rust {
                    executable: executable,
                    compiler_shlibs_digests: digests,
                }
            })
        }))
    }
}

impl<T> Compiler<T> for Rust
    where T: CommandCreatorSync,
{
    fn kind(&self) -> CompilerKind { CompilerKind::Rust }
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
                       arguments: &[String],
                       cwd: &Path) -> CompilerArguments<Box<CompilerHasher<T> + 'static>>
    {
        match parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => {
                CompilerArguments::Ok(Box::new(RustHasher {
                    executable: self.executable.clone(),
                    compiler_shlibs_digests: self.compiler_shlibs_digests.clone(),
                    parsed_args: args,
                }))
            }
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
            CompilerArguments::CannotCache => CompilerArguments::CannotCache,
        }
    }


    fn box_clone(&self) -> Box<Compiler<T>> {
        Box::new((*self).clone())
    }
}

/// An iterator over (argument, argument value) pairs.
struct ArgsIter<'a> {
    arguments: slice::Iter<'a, String>,
    args_with_val: &'a HashSet<&'static str>,
}

impl<'a> ArgsIter<'a> {
    fn new(arguments: &'a [String], args_with_val: &'a HashSet<&'static str>) -> ArgsIter<'a> {
        ArgsIter {
            arguments: arguments.iter(),
            args_with_val: args_with_val,
        }
    }
}

impl<'a> Iterator for ArgsIter<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<(&'a str, Option<&'a str>)> {
        if let Some(arg) = self.arguments.next() {
            if arg_in(arg, &self.args_with_val) {
                if let Some(i) = arg.find('=') {
                    Some((&arg[..i], Some(&arg[i+1..])))
                } else {
                    Some((arg, self.arguments.next().map(|v| v.as_str())))
                }
            } else {
                Some((arg, None))
            }
        } else {
            None
        }
    }
}

fn parse_arguments(arguments: &[String], _cwd: &Path) -> CompilerArguments<ParsedArguments>
{
    //TODO: use lazy_static for this.
    let args_with_val: HashSet<&'static str> = HashSet::from_iter(ARGS_WITH_VALUE.iter().map(|v| *v));
    let mut emit: Option<HashSet<&str>> = None;
    let mut input = None;
    let mut output_dir = None;
    let mut crate_name = None;
    let mut extra_filename = None;
    let mut externs = vec![];

    let it = ArgsIter::new(arguments, &args_with_val);
    for (arg, val) in it {
        match arg {
            // Various non-compilation options.
            "--help" | "-V" | "--version" | "--print" | "--explain" | "--pretty" | "--unpretty" => return CompilerArguments::NotCompilation,
            // Could support `-o file` but it'd be more complicated.
            "-o" => return CompilerArguments::CannotCache,
            //TODO: support linking against native libraries. This
            // will require replicating the linker search strategy
            // so we can *find* them.
            // https://github.com/mozilla/sccache/issues/88
            "-l" => return CompilerArguments::CannotCache,
            "--emit" => {
                if emit.is_some() {
                    // We don't support passing --emit more than once.
                    return CompilerArguments::CannotCache;
                }
                emit = val.map(|a| a.split(",").collect());
            }
            "--out-dir" => {
                output_dir = val;
            }
            "--crate-name" => {
                crate_name = val;
            }
            "--extern" => {
                if let Some(val) = val {
                    if let Some(crate_file) = val.splitn(2, "=").nth(1) {
                        externs.push(crate_file.to_owned());
                    }
                }
            }
            "-C" | "--codegen" => {
                // We want to capture some info from codegen options.
                if let Some(codegen_arg) = val {
                    let mut split_it = codegen_arg.splitn(2, "=");
                    let name = split_it.next();
                    let val = split_it.next();
                    if let (Some(name), Some(val)) = (name, val) {
                        match name {
                            "extra-filename" => extra_filename = Some(val),
                            _ => {},
                        }
                    }
                }
            }
            // Can't cache compilation from stdin.
            "-" => return CompilerArguments::CannotCache,
            _ => {
                if !arg.starts_with("-") {
                    // Anything else is an input file.
                    if input.is_some() {
                        // Can't cache compilations with multiple inputs.
                        return CompilerArguments::CannotCache;
                    }
                    input = Some(arg);
                }
            }
        }
    }
    // Unwrap required values.
    macro_rules! req {
        ($x:ident) => {
            let $x = if let Some($x) = $x {
                $x
            } else {
                debug!("Can't cache compilation, missing `{}`", stringify!($x));
                return CompilerArguments::CannotCache;
            };
        }
    };
    // We don't actually save the input value, but there needs to be one.
    req!(input);
    drop(input);
    req!(output_dir);
    req!(emit);
    // We won't cache invocations that are not producing
    // binary output.
    if !emit.is_empty() && !emit.contains("link") {
        return CompilerArguments::NotCompilation;
    }
    // We won't cache invocations that are outputting anything but
    // linker output and dep-info.
    //TODO: use lazy_static for this.
    let allowed_emit = HashSet::from_iter(ALLOWED_EMIT.iter().map(|v| *v));
    let l = allowed_emit.len();
    if emit.union(&allowed_emit).count() > l {
        return CompilerArguments::CannotCache;
    }
    // Figure out the dep-info filename, if emitting dep-info.
    let dep_info = if emit.contains("dep-info") {
        if let (Some(crate_name), Some(extra_filename)) = (crate_name, extra_filename) {
            Some([crate_name, extra_filename, ".d"].iter().map(|s| *s).collect::<String>())
        } else {
            None
        }
    } else {
        None
    };
    let arguments = ArgsIter::new(arguments, &args_with_val)
        .map(|(arg, val)| (arg.to_owned(), val.map(|v| v.to_owned())))
        .collect::<Vec<_>>();
    // We'll figure out the source files and outputs later in
    // `generate_hash_key` where we can run rustc.
    CompilerArguments::Ok(ParsedArguments {
        arguments: arguments,
        output_dir: output_dir.to_owned(),
        externs: externs,
        crate_name: crate_name.unwrap_or("<unknown>").to_string(),
        dep_info: dep_info,
    })
}

impl<T> CompilerHasher<T> for RustHasher
    where T: CommandCreatorSync,
{
    fn generate_hash_key(self: Box<Self>,
                         creator: &T,
                         cwd: &str,
                         env_vars: &[(OsString, OsString)],
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>
    {
        let me = *self;
        let RustHasher { executable, compiler_shlibs_digests, parsed_args: ParsedArguments { arguments, output_dir, externs, crate_name, dep_info } } = me;
        trace!("[{}]: generate_hash_key", crate_name);
        // filtered_arguments omits --emit and --out-dir arguments.
        let filtered_arguments = arguments.iter()
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
        let source_hashes = hash_source_files(creator, &crate_name, &executable, &filtered_arguments, cwd, env_vars, pool);
        // Hash the contents of the externs listed on the commandline.
        let cwp = Path::new(cwd);
        trace!("[{}]: hashing {} externs", crate_name, externs.len());
        let extern_hashes = hash_all(externs.iter()
                                     .map(|e| cwp.join(e).to_string_lossy().into_owned())
                                     .collect(),
                                     &pool);
        let creator = creator.clone();
        let cwd = cwd.to_owned();
        let env_vars = env_vars.to_vec();
        let hashes = source_hashes.join(extern_hashes);
        Box::new(hashes.and_then(move |(source_hashes, extern_hashes)| -> SFuture<_> {
            // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
            let mut m = sha1::Sha1::new();
            // Hash inputs:
            // 1. A version
            m.update(CACHE_VERSION);
            // 2. compiler_shlibs_digests
            for d in compiler_shlibs_digests {
                m.update(d.as_bytes());
            }
            // 3. The full commandline (self.arguments)
            // TODO: there will be full paths here, it would be nice to
            // normalize them so we can get cross-machine cache hits.
            // Sort --extern args because cargo does not provide them in
            // a deterministic order.
            let args = {
                let (mut extern_args, rest): (Vec<_>, Vec<_>) = arguments.iter()
                    .partition(|&&(ref arg, ref _v)| arg == "--extern");
                extern_args.sort();
                rest.into_iter().chain(extern_args)
                    .flat_map(|&(ref arg, ref val)| Some(arg).into_iter().chain(val))
                    .map(|s| s.as_str()).collect::<String>()
            };
            m.update(args.as_bytes());
            // 4. The sha-1 digests of all source files (this includes src file from cmdline).
            // 5. The sha-1 digests of all files listed on the commandline (self.externs)
            for h in source_hashes.into_iter().chain(extern_hashes) {
                m.update(h.as_bytes());
            }
            // 6. Environment variables. Ideally we'd use anything referenced
            // via env! in the program, but we don't have a way to determine that
            // currently, and hashing all environment variables is too much, so
            // we'll just hash the CARGO_ env vars and hope that's sufficient.
            // Upstream Rust issue tracking getting information about env! usage:
            // https://github.com/rust-lang/rust/issues/40364
            let mut env_vars = env_vars.clone();
            env_vars.sort();
            for &(ref var, ref val) in env_vars.iter() {
                if var.to_str().map(|s| s.starts_with("CARGO_")).unwrap_or(false) {
                    m.update(os_str_bytes(var));
                    m.update(b"=");
                    m.update(os_str_bytes(val));
                }
            }
            // 7. TODO: native libraries being linked.
            // https://github.com/mozilla/sccache/issues/88
            // Turn arguments into a simple Vec<String> for compilation.
            let arguments = arguments.into_iter()
                .flat_map(|(arg, val)| Some(arg).into_iter().chain(val))
                .collect::<Vec<_>>();
            Box::new(get_compiler_outputs(&creator, &executable, &arguments, &cwd, &env_vars).map(move |outputs| {
                let output_dir = PathBuf::from(output_dir);
                // Convert output files into a map of basename -> full path.
                let mut outputs = outputs.into_iter()
                    .map(|o| {
                        let p = output_dir.join(&o).to_string_lossy().into_owned();
                        (o, p)
                    })
                    .collect::<HashMap<_, _>>();
                if let Some(dep_info) = dep_info {
                    let p = output_dir.join(&dep_info).to_string_lossy().into_owned();
                    outputs.insert(dep_info, p);
                }
                HashResult::Ok {
                    key: m.digest().to_string(),
                    compilation: Box::new(RustCompilation {
                        executable: executable,
                        arguments: arguments,
                        outputs: outputs,
                        crate_name: crate_name,
                    }),
                }
            }))
        }))
    }

    fn output_file(&self) -> Cow<str> {
        Cow::Borrowed(&self.parsed_args.crate_name)
    }

    fn box_clone(&self) -> Box<CompilerHasher<T>> {
        Box::new((*self).clone())
    }
}

impl<T> Compilation<T> for RustCompilation
    where T: CommandCreatorSync,
{
    fn compile(self: Box<Self>,
               creator: &T,
               cwd: &str,
               env_vars: &[(OsString, OsString)],
               _pool: &CpuPool)
               -> SFuture<(Cacheable, process::Output)>
    {
        let me = *self;
        let RustCompilation { executable, arguments, crate_name, .. } = me;
        trace!("[{}]: compile", crate_name);
        let mut cmd = creator.clone().new_command_sync(&executable);
        cmd.args(&arguments)
            .env_clear()
            .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
            .current_dir(cwd);
        trace!("compile: {:?}", cmd);
        Box::new(run_input_output(cmd, None).map(|output| {
            (Cacheable::Yes, output)
        }))
    }

    fn outputs<'a>(&'a self) -> Box<Iterator<Item=(&'a str, &'a String)> + 'a> {
        Box::new(self.outputs.iter().map(|(k, v)| (k.as_str(), v)))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ::compiler::*;
    use mock_command::*;
    use sha1;
    use std::fs::File;
    use std::io::Write;
    use test::utils::*;

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments>
    {
        parse_arguments(arguments, ".".as_ref())
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

                _ => {}
            }
        }
    }

    #[test]
    fn test_parse_arguments_simple() {
        let h = parses!("--emit", "link", "foo.rs", "--out-dir", "out");
        assert_eq!(h.output_dir, "out");
        assert!(h.dep_info.is_none());
        assert!(h.externs.is_empty());
        let h = parses!("--emit=link", "foo.rs", "--out-dir", "out");
        assert_eq!(h.output_dir, "out");
        assert!(h.dep_info.is_none());
        let h = parses!("--emit", "link", "foo.rs", "--out-dir=out");
        assert_eq!(h.output_dir, "out");
        let h = parses!("--emit", "link,dep-info", "foo.rs", "--out-dir", "out",
                        "--crate-name", "my_crate",
                        "-C", "extra-filename=-abcxyz");
        assert_eq!(h.output_dir, "out");
        assert_eq!(h.dep_info.unwrap(), "my_crate-abcxyz.d");
        fails!("--emit", "link", "--out-dir", "out");
        fails!("--emit", "link", "foo.rs");
        fails!("--emit", "asm", "foo.rs", "--out-dir", "out");
        fails!("--emit", "asm,link", "foo.rs", "--out-dir", "out");
        fails!("--emit", "asm,link,dep-info", "foo.rs", "--out-dir", "out");
        // From an actual cargo compilation, with some args shortened:
        let h = parses!("--crate-name", "foo", "src/lib.rs",
                        "--crate-type", "lib", "--emit=dep-info,link",
                        "-C", "debuginfo=2", "-C", "metadata=d6ae26f5bcfb7733",
                        "-C", "extra-filename=-d6ae26f5bcfb7733",
                        "--out-dir", "/foo/target/debug/deps",
                        "-L", "dependency=/foo/target/debug/deps",
                        "--extern", "libc=/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
                        "--extern", "log=/foo/target/debug/deps/liblog-2f7366be74992849.rlib");
        assert_eq!(h.output_dir, "/foo/target/debug/deps");
        assert_eq!(h.crate_name, "foo");
        assert_eq!(h.dep_info.unwrap(), "foo-d6ae26f5bcfb7733.d");
        assert_eq!(h.externs, &["/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib", "/foo/target/debug/deps/liblog-2f7366be74992849.rlib"]);
    }

    #[test]
    fn test_parse_arguments_native_libs() {
        //TODO: deal with native libs
        // https://github.com/mozilla/sccache/issues/88
        fails!("--emit", "link", "-l", "bar", "foo.rs", "--out-dir", "out");
    }

    #[test]
    fn test_args_iter() {
        let args_with_val: HashSet<&'static str> = HashSet::from_iter(ARGS_WITH_VALUE.iter().map(|v| *v));
        macro_rules! t {
            ( [ $( $s:expr ),* ], [ $( $t:expr ),* ] ) => {
                let v = vec!( $( $s.to_string(), )* );
                let it = ArgsIter::new(&v, &args_with_val);
                assert_eq!(it.collect::<Vec<_>>(),
                           vec!( $( $t, )* ));
            }
        }
        t!(["--emit", "link", "-g", "foo.rs", "--out-dir", "out"],
           [("--emit", Some("link")), ("-g", None), ("foo.rs", None), ("--out-dir", Some("out"))]);

        t!(["--emit=link", "-g", "foo.rs", "--out-dir=out"],
           [("--emit", Some("link")), ("-g", None), ("foo.rs", None), ("--out-dir", Some("out"))]);
    }

    #[test]
    fn test_arg_in() {
        let mut args: HashSet<&'static str> = HashSet::new();
        args.insert("--foo");
        args.insert("--bar");
        args.insert("--baz");
        assert!(arg_in("--foo", &args));
        assert!(arg_in("--foo=abc", &args));
        assert!(arg_in("--bar", &args));
        assert!(arg_in("--baz", &args));
        assert!(!arg_in("--xyz", &args));
        assert!(!arg_in("--xyz=123", &args));
    }

    #[test]
    fn test_get_compiler_outputs() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo\nbar\nbaz", "")));
        let outputs = get_compiler_outputs(&creator, "rustc", &stringvec!("a", "b"), "cwd", &[]).wait().unwrap();
        assert_eq!(outputs, &["foo", "bar", "baz"]);
    }

    #[test]
    fn test_get_compiler_outputs_fail() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "error")));
        assert!(get_compiler_outputs(&creator, "rustc", &stringvec!("a", "b"), "cwd", &[]).wait().is_err());
    }

    #[test]
    fn test_parse_dep_info() {
        let deps = "foo: baz.rs abc.rs bar.rs

baz.rs:

abc.rs:

bar.rs:
";
        assert_eq!(stringvec!["abc.rs", "bar.rs", "baz.rs"],
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
        assert_eq!(stringvec!["foo/abc.rs", "foo/bar.rs", "foo/baz.rs"],
                   parse_dep_info(&deps, "foo/"));

        assert_eq!(stringvec!["/foo/bar/abc.rs", "/foo/bar/bar.rs", "/foo/bar/baz.rs"],
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
        assert_eq!(stringvec!["/foo/abc.rs", "/foo/bar.rs", "/foo/baz.rs"],
                   parse_dep_info(&deps, "/bar/"));
    }

    #[test]
    fn test_generate_hash_key() {
        use env_logger;
        drop(env_logger::init());
        let f = TestFixture::new();
        // SHA-1 digest of an empty file.
        const EMPTY_DIGEST: &'static str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        const FAKE_DIGEST: &'static str = "abcd1234";
        // We'll just use empty files for each of these.
        for s in ["foo.rs", "bar.rs", "bar.rlib"].iter() {
            f.touch(s).unwrap();
        }
        let hasher = Box::new(RustHasher {
            executable: "rustc".to_owned(),
            compiler_shlibs_digests: vec![FAKE_DIGEST.to_owned()],
            parsed_args: ParsedArguments {
                arguments: vec![("a".to_string(), None),
                                ("--extern".to_string(), Some("xyz".to_string())),
                                ("b".to_string(), None),
                                ("--extern".to_string(), Some("abc".to_string())),
                                ],
                output_dir: "foo/".to_string(),
                externs: stringvec!["bar.rlib"],
                crate_name: "foo".to_string(),
                dep_info: None,
            }
        });
        let creator = new_creator();
        // Mock the `rustc --emit=dep-info` process by writing
        // a dep-info file.
        next_command_calls(&creator, |args| {
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
            f.write_all(b"blah: foo.rs bar.rs

foo.rs:
bar.rs:
")?;
            Ok(MockChild::new(exit_status(0), "", ""))
        });
        // Mock the `rustc --print=file-names` process output.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo.rlib\nfoo.a", "")));
        let pool = CpuPool::new(1);
        let res = hasher.generate_hash_key(&creator,
                                           &f.tempdir.path().to_string_lossy(),
                                           &[(OsString::from("CARGO_PKG_NAME"), OsString::from("foo")),
                                             (OsString::from("FOO"), OsString::from("bar")),
                                             (OsString::from("CARGO_BLAH"), OsString::from("abc"))],
                                           &pool).wait().unwrap();
        let mut m = sha1::Sha1::new();
        // Version.
        m.update(CACHE_VERSION);
        // sysroot shlibs digests.
        m.update(FAKE_DIGEST.as_bytes());
        // Arguments, with externs sorted at the end.
        m.update(b"ab--externabc--externxyz");
        // bar.rs (source file, from dep-info)
        m.update(EMPTY_DIGEST.as_bytes());
        // foo.rs (source file, from dep-info)
        m.update(EMPTY_DIGEST.as_bytes());
        // bar.rlib (extern crate, from externs)
        m.update(EMPTY_DIGEST.as_bytes());
        // Env vars
        m.update(b"CARGO_BLAH=abc");
        m.update(b"CARGO_PKG_NAME=foo");
        let digest = m.digest().to_string();
        match res {
            HashResult::Ok { key, compilation } => {
                assert_eq!(key, digest);
                let mut out = compilation.outputs().map(|(k, _)| k.to_owned()).collect::<Vec<_>>();
                out.sort();
                assert_eq!(out, vec!["foo.a", "foo.rlib"]);
            }
            _ => panic!("generate_hash_key returned Error!"),
        }
    }
}
