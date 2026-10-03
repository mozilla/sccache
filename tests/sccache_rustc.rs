#![cfg(unix)]

use assert_cmd::Command;
use tempfile::tempdir;

use std::{
    env::{consts::DLL_SUFFIX, var_os},
    ffi::OsString,
    fs::{self, File, create_dir, create_dir_all, remove_file, set_permissions},
    io::Write,
    os::unix::{
        fs::symlink,
        prelude::{OsStrExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

struct StopServer(u16);
impl Drop for StopServer {
    fn drop(&mut self) {
        let _ = Command::from_std(std::process::Command::new(env!("CARGO_BIN_EXE_sccache")))
            .env("SCCACHE_SERVER_PORT", self.0.to_string())
            .env_remove("SCCACHE_SERVER_UDS")
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
    let port = 4321;
    drop(StopServer(port));
    let _stop_server = StopServer(port);
    run_sccache(root, &bin, port, false);
    let output1 = fs::read(&out_file).unwrap();

    remove_file(&rust).unwrap();
    symlink(root.join("rust2"), &rust).unwrap();
    run_sccache(root, &bin, port, false);
    let output2 = fs::read(out_file).unwrap();

    assert_ne!(output1, output2);
}

#[test]
fn test_rmeta_notification_delivery_on_miss_and_hit() {
    rmeta_notification_delivery_on_miss_and_hit(4322, false);
}

#[test]
fn test_rmeta_notification_delivery_on_miss_and_hit_client_side() {
    rmeta_notification_delivery_on_miss_and_hit(4323, true);
}

/// Runs the real sccache and checks the caller sees the `.rmeta`
/// notification exactly once on both the miss and the hit.
fn rmeta_notification_delivery_on_miss_and_hit(port: u16, client_side: bool) {
    let root = tempdir().unwrap();
    let root = root.path();

    fs::write(root.join("counter"), b"0").unwrap();
    fs::write(root.join("RUST_FILE.rs"), []).unwrap();
    create_mock_rustc(root.join("rust"));
    let bin = root.join("rust/bin");
    let out_file = root.join("RUST_FILE");

    drop(StopServer(port));
    let _stop_server = StopServer(port);

    let miss = run_sccache(root, &bin, port, client_side);
    let compiled_once = fs::read(&out_file).unwrap();
    let hit = run_sccache(root, &bin, port, client_side);
    assert_eq!(
        compiled_once,
        fs::read(&out_file).unwrap(),
        "second run was not a hit"
    );

    for (name, stderr) in [("miss", &miss.stderr), ("hit", &hit.stderr)] {
        let stderr = String::from_utf8_lossy(stderr);
        let notifications: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("\"artifact\""))
            .collect();
        assert_eq!(
            1,
            notifications
                .iter()
                .filter(|l| l.contains(".rmeta"))
                .count(),
            "{name}: .rmeta notification count in {stderr:?}"
        );
        assert_eq!(
            1,
            notifications.iter().filter(|l| l.contains(".rlib")).count(),
            "{name}: .rlib notification count in {stderr:?}"
        );
    }
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
    echo '{{"artifact":"'"$PWD"'/libsccache_rustc_tests.rmeta","emit":"metadata"}}' >&2
    echo $(($(cat counter) + 1)) > counter
    cp counter RUST_FILE
    echo '{{"artifact":"'"$PWD"'/libsccache_rustc_tests.rlib","emit":"link"}}' >&2
fi
"#,
        dir.display(),
    )
    .unwrap();

    let mut perm = rustc.metadata().unwrap().permissions();
    perm.set_mode(0o755);
    set_permissions(&rustc, perm).unwrap();
}

fn run_sccache(root: &Path, path: &Path, port: u16, client_side: bool) -> std::process::Output {
    let mut paths: OsString = path.into();
    paths.push(":");
    paths.push(var_os("PATH").unwrap());

    Command::cargo_bin("sccache")
        .unwrap()
        .current_dir(root)
        .env("PATH", paths)
        .env("SCCACHE_DIR", root.join("sccache"))
        .env("SCCACHE_SERVER_PORT", port.to_string())
        .env_remove("SCCACHE_SERVER_UDS")
        .envs(client_side.then_some(("SCCACHE_CLIENT_SIDE", "1")))
        .arg("rustc")
        .arg("RUST_FILE.rs")
        .arg("--crate-name=sccache_rustc_tests")
        .arg("--crate-type=lib")
        .arg("--emit=link")
        .arg("--out-dir")
        .arg(root)
        .assert()
        .success()
        .get_output()
        .clone()
}
