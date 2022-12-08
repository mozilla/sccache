#![cfg(unix)]

use assert_cmd::Command;
use tempfile::tempdir;

use std::{
    env::{consts::DLL_SUFFIX, var_os},
    ffi::OsString,
    fs::{self, create_dir, create_dir_all, remove_file, set_permissions, File},
    io::Write,
    os::unix::{
        fs::symlink,
        prelude::{OsStrExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

struct StopServer;
impl Drop for StopServer {
    fn drop(&mut self) {
        let _ = Command::cargo_bin("sccache")
            .unwrap()
            .arg("--stop-server")
            .ok();
    }
}

// (temp dir)
// ├── rust // symlinks to rust1 on the first run and rust2 on the second
// ├── rust1/
// │  ├── bin
// │  │  └── rustc
// │  ├── lib
// │  │  └── driver.so -> ../driver.so
// │  └── driver.so
// ├── rust2/
// │  ├── bin
// │  │  └── rustc
// │  ├── lib
// │  │  └── driver.so -> ../driver.so
// │  └── driver.so
// ├── sccache/
// ├── counter // increases by 1 for every compilation that is not cached
// ├── RUST_FILE // compile output copied from counter, same content means it was cached
// └── RUST_FILE.rs
#[test]
fn test_symlinks() {
    let root = tempdir().unwrap();
    let root = root.path();

    fs::write(root.join("counter"), b"0").unwrap();
    fs::write(root.join("RUST_FILE.rs"), []).unwrap();

    create_mock_rustc(root.join("rust1"));
    create_mock_rustc(root.join("rust2"));

    let rust = root.join("rust");
    let bin = rust.join("bin");
    let out_file = root.join("RUST_FILE");

    symlink(root.join("rust1"), &rust).unwrap();
    drop(StopServer);
    let _stop_server = StopServer;
    run_sccache(root, &bin);
    let output1 = fs::read(&out_file).unwrap();

    remove_file(&rust).unwrap();
    symlink(root.join("rust2"), &rust).unwrap();
    run_sccache(root, &bin);
    let output2 = fs::read(out_file).unwrap();

    assert_ne!(output1, output2);
}

fn create_mock_rustc(dir: PathBuf) {
    let bin = dir.join("bin");
    create_dir_all(&bin).unwrap();

    let dll_name = format!("driver{DLL_SUFFIX}");
    let dll = dir.join(&dll_name);
    fs::write(&dll, dir.as_os_str().as_bytes()).unwrap();

    let lib = dir.join("lib");
    create_dir(&lib).unwrap();
    symlink(dll, lib.join(&dll_name)).unwrap();

    let rustc = bin.join("rustc");
    write!(
        File::create(&rustc).unwrap(),
        r#"#!/usr/bin/env sh

set -e
build=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        -vV)
            echo rustc 1.0.0
            exec echo "host: unknown"
            ;;
        +stable)
            exit 1
            ;;
        --print=sysroot)
            exec echo {}
            ;;
        --print)
            shift
            if [ "$1" = file-names ]; then
                exec echo RUST_FILE.rs
            fi
            ;;
        --emit)
            shift
            if [ "$1" = dep-info ]; then
                echo "deps.d: RUST_FILE.rs" > "$3"
                exec echo "RUST_FILE.rs:" "$3"
            fi
            ;;
        RUST_FILE.rs)
            build=1
            ;;
    esac
    shift
done

if [ "$build" -eq 1 ]; then
    echo $(($(cat counter) + 1)) > counter
    cp counter RUST_FILE
fi
"#,
        dir.display(),
    )
    .unwrap();

    let mut perm = rustc.metadata().unwrap().permissions();
    perm.set_mode(0o755);
    set_permissions(&rustc, perm).unwrap();
}

fn run_sccache(root: &Path, path: &Path) {
    let mut paths: OsString = path.into();
    paths.push(":");
    paths.push(var_os("PATH").unwrap());

    Command::cargo_bin("sccache")
        .unwrap()
        .current_dir(root)
        .env("PATH", paths)
        .env("SCCACHE_DIR", root.join("sccache"))
        .arg("rustc")
        .arg("RUST_FILE.rs")
        .arg("--crate-name=sccache_rustc_tests")
        .arg("--crate-type=lib")
        .arg("--emit=link")
        .arg("--out-dir")
        .arg(root)
        .unwrap();
}
