use fs_err as fs;
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

use serde::Serialize;

pub mod client;

#[cfg(feature = "dist-server")]
pub mod dist;

pub const TC_CACHE_SIZE: u64 = 1024 * 1024 * 1024; // 1 gig

pub fn init_cargo(path: &Path, cargo_name: &str) -> PathBuf {
    let cargo_path = path.join(cargo_name);
    let source_path = "src";
    fs::create_dir_all(cargo_path.join(source_path)).unwrap();
    cargo_path
}

// Prune any environment variables that could adversely affect test execution.
pub fn prune_command(mut cmd: Command) -> Command {
    use sccache::util::OsStrExt;

    for (var, _) in env::vars_os() {
        if var.starts_with("SCCACHE_") {
            cmd.env_remove(var);
        }
    }
    cmd
}

pub fn write_json_cfg<T: Serialize>(path: &Path, filename: &str, contents: &T) {
    let p = path.join(filename);
    let mut f = fs::File::create(p).unwrap();
    f.write_all(&serde_json::to_vec(contents).unwrap()).unwrap();
}

pub fn write_source(path: &Path, filename: &str, contents: &str) {
    let p = path.join(filename);
    let mut f = fs::File::create(p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}
