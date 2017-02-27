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
use std::fs::File;
use std::io::Read;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process;
use tempdir::TempDir;
use util::sha1_digest;

use errors::*;

/// A unit struct on which to hang a `Compiler` impl.
#[derive(Debug, Clone)]
pub struct Rust;

/// A struct on which to hang a `CompilerHasher` impl.
#[derive(Debug, Clone)]
pub struct RustHasher {
    /// The full commandline.
    arguments: Vec<String>,
    /// The commandline without any --emit or --out-dir arguments.
    filtered_arguments: Vec<String>,
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
    /// The full commandline.
    arguments: Vec<String>,
    /// The compiler outputs.
    outputs: HashMap<String, String>,
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

/// Parse the value passed to a commandline argument `arg`, either after
/// an '=' in `arg` or in the next argument from `it`.
fn arg_val<'a, 'b, T>(arg: &'a str, it: &'b mut T) -> Option<&'a str>
    where T: Iterator<Item=&'a String>,
{
    if let Some(i) = arg.find('=') {
        Some(&arg[i+1..])
    } else {
        it.next().map(|v| v.as_str())
    }
}

/// Return true if `arg` is in the set of arguments `set`.
fn arg_in(arg: &str, set: &HashSet<&str>) -> bool
{
    set.contains(arg) || set.iter().any(|a| arg.starts_with(a))
}

/// Calculate the SHA-1 digest of each file in `files` on background threads
/// in `pool`.
fn hash_all(files: Vec<String>, pool: &CpuPool) -> SFuture<Vec<String>>
{
    let pool = pool.clone();
    Box::new(future::join_all(files.into_iter().map(move |f| sha1_digest(f, &pool))))
}

/// Calculate SHA-1 digests for all source files listed in rustc's dep-info output.
fn hash_source_files<T>(creator: &T, executable: &str, arguments: &[String], cwd: &str, pool: &CpuPool) -> SFuture<Vec<String>>
    where T: CommandCreatorSync,
{
    // Get the full list of source files from rustc's dep-info.
    let temp_dir = match TempDir::new("sccache") {
        Ok(d) => d,
        _ => return Box::new(future::err("Failed to create temp dir".into())),
    };
    let dep_file = temp_dir.path().join("deps.d");
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--emit", "dep-info"])
        .arg("-o")
        .arg(&dep_file)
        .current_dir(cwd);
    if log_enabled!(Trace) {
        trace!("get dep-info: {:?}", cmd);
    }
    let dep_info = run_input_output(cmd, None);
    // Parse the dep-info file, then hash the contents of those files.
    let pool = pool.clone();
    let cwd = cwd.to_owned();
    Box::new(dep_info.and_then(move |output| -> SFuture<_> {
        if output.status.success() {
            match parse_dep_file(&dep_file, &cwd) {
                Ok(files) => {
                    // Just to make sure we capture temp_dir.
                    drop(temp_dir);
                    hash_all(files, &pool)
                }
                Err(e) => return Box::new(future::err(e)),
            }
        } else {
            Box::new(future::err("Failed run rustc --dep-info".into()))
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
    //TODO: sort files.
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
fn get_compiler_outputs<T>(creator: &T, executable: &str, arguments: &[String], cwd: &str) -> SFuture<Vec<String>>
    where T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.args(&arguments)
        .args(&["--print", "file-names"])
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
            CompilerArguments::Ok(h) => CompilerArguments::Ok(Box::new(h)),
            CompilerArguments::NotCompilation => CompilerArguments::NotCompilation,
            CompilerArguments::CannotCache => CompilerArguments::CannotCache,
        }
    }


    fn box_clone(&self) -> Box<Compiler<T>> {
        Box::new((*self).clone())
    }
}

fn parse_arguments(arguments: &[String], _cwd: &Path) -> CompilerArguments<RustHasher>
{
    //TODO: use lazy_static for this.
    let args_with_val: HashSet<&'static str> = HashSet::from_iter(ARGS_WITH_VALUE.iter().map(|v| *v));
    let mut emit: Option<HashSet<&str>> = None;
    let mut input = None;
    let mut output_dir = None;
    let mut crate_name = None;
    let mut extra_filename = None;
    let mut externs = vec![];
    let mut filtered_arguments = vec![];

    let mut it = arguments.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            // Various non-compilation options.
            "--help" | "-V" | "--version" => return CompilerArguments::NotCompilation,
            v if v.starts_with("--print") || v.starts_with("--explain") || v.starts_with("--pretty") || v.starts_with("--unpretty") => return CompilerArguments::NotCompilation,
            // Could support `-o file` but it'd be more complicated.
            "-o" => return CompilerArguments::CannotCache,
            //TODO: support linking against native libraries. This
            // will require replicating the linker search strategy
            // so we can *find* them.
            "-l" => return CompilerArguments::CannotCache,
            v if v.starts_with("--emit") => {
                //XXX: do we need to handle --emit specified more than once?
                emit = arg_val(v, &mut it).map(|a| a.split(",").collect());
            }
            v if v.starts_with("--out-dir") => {
                output_dir = arg_val(v, &mut it);
            }
            v if v.starts_with("--crate-name") => {
                filtered_arguments.push("--crate-name".to_owned());
                crate_name = arg_val(v, &mut it);
                if let Some(name) = crate_name {
                    filtered_arguments.push(name.to_owned());
                }
            }
            v if v.starts_with("--extern") => {
                if let Some(val) = arg_val(v, &mut it) {
                    filtered_arguments.push("--extern".to_owned());
                    filtered_arguments.push(val.to_owned());
                    if let Some(crate_file) = val.splitn(2, "=").nth(1) {
                        externs.push(crate_file.to_owned());
                    }
                }
            }
            "-C" => {
                // We want to capture some info from codegen options.
                filtered_arguments.push("-C".to_owned());
                if let Some(codegen_arg) = it.next() {
                    filtered_arguments.push(codegen_arg.to_owned());
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
            // Handle arguments that take a value.
            v if v.starts_with("-") && arg_in(v, &args_with_val) => {
                filtered_arguments.push(v.to_owned());
                if v.find('=').is_none() {
                    if let Some(a) = it.next() {
                        filtered_arguments.push(a.to_owned());
                    }
                }
            }
            // Other arguments that don't take a value can just be passed on.
            v if v.starts_with("-") && v != "-" => {
                filtered_arguments.push(v.to_owned());
            }
            // Anything else is an input file.
            _ => {
                if input.is_some() || arg == "-" {
                    // Can't cache compilations with multiple inputs
                    // or compilation from stdin.
                    return CompilerArguments::CannotCache;
                }
                filtered_arguments.push(arg.to_owned());
                input = Some(arg);
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
    // We'll figure out the source files and outputs later in
    // `generate_hash_key` where we can run rustc.
    CompilerArguments::Ok(RustHasher {
        arguments: arguments.to_owned(),
        filtered_arguments: filtered_arguments,
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
                         executable: &str,
                         executable_digest: &str,
                         cwd: &str,
                         pool: &CpuPool)
                         -> SFuture<HashResult<T>>
    {
        let me = *self;
        let RustHasher { arguments, filtered_arguments, output_dir, externs, dep_info, .. } = me;
        let source_hashes = hash_source_files(creator, executable, &filtered_arguments, cwd, pool);
        // Hash the contents of the externs listed on the commandline.
        let cwp = Path::new(cwd);
        let extern_hashes = hash_all(externs.iter()
                                     .map(|e| cwp.join(e).to_string_lossy().into_owned())
                                     .collect(),
                                     &pool);
        let creator = creator.clone();
        let executable_digest = executable_digest.to_owned();
        let executable = executable.to_owned();
        let cwd = cwd.to_owned();
        let hashes = source_hashes.join(extern_hashes);
        Box::new(hashes.and_then(move |(source_hashes, extern_hashes)| -> SFuture<_> {
            // If you change any of the inputs to the hash, you should change `CACHE_VERSION`.
            let mut m = sha1::Sha1::new();
            // Hash inputs:
            // 1. A version
            trace!("CACHE_VERSION: {:?}", CACHE_VERSION);
            m.update(CACHE_VERSION);
            // 2. The executable_digest
            trace!("executable_digest: {}", executable_digest);
            m.update(executable_digest.as_bytes());
            // 3. The full commandline (self.arguments)
            // TODO: there will be full paths here, it would be nice to
            // normalize them so we can get cross-machine cache hits.
            let args = arguments.iter().map(|s| s.as_str()).collect::<String>();
            trace!("args: {}", args);
            m.update(args.as_bytes());
            // 4. The sha-1 digests of all source files (this includes src file from cmdline).
            // 5. The sha-1 digests of all files listed on the commandline (self.externs)
            for h in source_hashes.into_iter().chain(extern_hashes) {
                trace!("file hash: {}", h);
                m.update(h.as_bytes());
            }
            // 6. TODO: Environment variables:
            //    RUSTFLAGS, maybe CARGO_PKG_*?
            // 7. TODO: native libraries being linked.
            Box::new(get_compiler_outputs(&creator, &executable, &arguments, &cwd).map(move |outputs| {
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
                        arguments: arguments,
                        outputs: outputs,
                    }),
                }
            }))
        }))
    }

    fn output_file(&self) -> Cow<str> {
        Cow::Borrowed(&self.crate_name)
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
               executable: &str,
               cwd: &str,
               _pool: &CpuPool)
               -> SFuture<(Cacheable, process::Output)>
    {
        let me = *self;
        let RustCompilation { arguments, .. } = me;
        let mut cmd = creator.clone().new_command_sync(executable);
        cmd.args(&arguments)
            .current_dir(cwd);
        if log_enabled!(Trace) {
            trace!("compile: {:?}", cmd);
        }
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

    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<RustHasher>
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
        assert_eq!(h.filtered_arguments, &["foo.rs"]);
        assert_eq!(h.output_dir, "out");
        assert!(h.dep_info.is_none());
        assert!(h.externs.is_empty());
        let h = parses!("--emit=link", "foo.rs", "--out-dir", "out");
        assert_eq!(h.filtered_arguments, &["foo.rs"]);
        assert_eq!(h.output_dir, "out");
        assert!(h.dep_info.is_none());
        let h = parses!("--emit", "link", "foo.rs", "--out-dir=out");
        assert_eq!(h.filtered_arguments, &["foo.rs"]);
        assert_eq!(h.output_dir, "out");
        let h = parses!("--emit", "link,dep-info", "foo.rs", "--out-dir", "out",
                        "--crate-name", "my_crate",
                        "-C", "extra-filename=-abcxyz");
        assert_eq!(h.filtered_arguments,
                   &["foo.rs", "--crate-name", "my_crate", "-C", "extra-filename=-abcxyz"]);
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
        assert_eq!(h.filtered_arguments,
                   &["--crate-name", "foo", "src/lib.rs", "--crate-type", "lib",
                     "-C", "debuginfo=2", "-C", "metadata=d6ae26f5bcfb7733",
                     "-C", "extra-filename=-d6ae26f5bcfb7733",
                     "-L", "dependency=/foo/target/debug/deps",
                     "--extern", "libc=/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
                     "--extern", "log=/foo/target/debug/deps/liblog-2f7366be74992849.rlib"]);
        assert_eq!(h.output_dir, "/foo/target/debug/deps");
        assert_eq!(h.crate_name, "foo");
        assert_eq!(h.dep_info.unwrap(), "foo-d6ae26f5bcfb7733.d");
        assert_eq!(h.externs, &["/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib", "/foo/target/debug/deps/liblog-2f7366be74992849.rlib"]);
    }

    #[test]
    fn test_parse_arguments_native_libs() {
        //TODO: deal with native libs
        fails!("--emit", "link", "-l", "bar", "foo.rs", "--out-dir", "out");
    }

    #[test]
    fn test_arg_val() {
        let a = stringvec!["a", "b", "c"];
        let mut it = a.iter();
        let first = it.next().unwrap();
        assert_eq!(arg_val(first, &mut it).unwrap(), "b");

        let a = stringvec!["a=x", "b", "c"];
        let mut it = a.iter();
        let first = it.next().unwrap();
        assert_eq!(arg_val(first, &mut it).unwrap(), "x");

        let a = stringvec!["a"];
        let mut it = a.iter();
        let first = it.next().unwrap();
        assert!(arg_val(first, &mut it).is_none());
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
        let outputs = get_compiler_outputs(&creator, "rustc", &stringvec!("a", "b"), "cwd").wait().unwrap();
        assert_eq!(outputs, &["foo", "bar", "baz"]);
    }

    #[test]
    fn test_get_compiler_outputs_fail() {
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(1), "", "error")));
        assert!(get_compiler_outputs(&creator, "rustc", &stringvec!("a", "b"), "cwd").wait().is_err());
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
        // We'll just use empty files for each of these.
        for s in ["foo.rs", "bar.rs", "bar.rlib"].iter() {
            f.touch(s).unwrap();
        }
        let hasher = Box::new(RustHasher {
            arguments: stringvec!["a", "b"],
            filtered_arguments: stringvec![],
            output_dir: "foo/".to_string(),
            externs: stringvec!["bar.rlib"],
            crate_name: "foo".to_string(),
            dep_info: None,
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
            trace!("dep_info_path: {:?}", dep_info_path.to_string_lossy());
            let mut f = File::create(dep_info_path)?;
            f.write_all(b"blah: foo.rs bar.rs

foo.rs:
bar.rs:
")?;
            Ok(MockChild::new(exit_status(0), "", ""))
        });
        // Mock the `rustc --print=file-names` process output.
        next_command(&creator, Ok(MockChild::new(exit_status(0), "foo.rlib\nfoo.a", "")));
        const RUSTC_DIGEST: &'static str = "1234abcd";
        // SHA-1 digest of an empty file.
        const EMPTY_DIGEST: &'static [u8] = b"da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let pool = CpuPool::new(1);
        let res = hasher.generate_hash_key(&creator, "rustc", RUSTC_DIGEST,
                                           &f.tempdir.path().to_string_lossy(),
                                           &pool).wait().unwrap();
        let mut m = sha1::Sha1::new();
        // Version.
        m.update(CACHE_VERSION);
        // Compiler digest.
        m.update(RUSTC_DIGEST.as_bytes());
        // Arguments.
        m.update(b"ab");
        // bar.rs (source file, from dep-info)
        m.update(EMPTY_DIGEST);
        // foo.rs (source file, from dep-info)
        m.update(EMPTY_DIGEST);
        // bar.rlib (extern crate, from externs)
        m.update(EMPTY_DIGEST);
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
