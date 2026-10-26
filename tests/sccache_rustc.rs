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

#[test]
fn test_in_process_compile_uses_cache_without_server() {
    let root = tempdir().unwrap();
    let root = root.path();

    fs::write(root.join("counter"), b"0").unwrap();
    fs::write(root.join("RUST_FILE.rs"), []).unwrap();
    create_mock_rustc(root.join("rust"));
    let bin = root.join("rust/bin");
    let out_file = root.join("RUST_FILE");

    let first = run_sccache_in_process(root, &bin);
    assert!(
        first.status.success(),
        "first compile failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let compiled_once = fs::read(&out_file).unwrap();
    let second = run_sccache_in_process(root, &bin);
    assert!(
        second.status.success(),
        "second compile failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(compiled_once, fs::read(out_file).unwrap());
    assert_eq!(b"1\n", fs::read(root.join("counter")).unwrap().as_slice());

    let stats =
        run_sccache_in_process_command(root, &["--show-stats", "--stats-format=json"], true);
    assert!(
        stats.status.success(),
        "show-stats failed: {}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["stats"]["compile_requests"], 2);
    assert_eq!(stats["stats"]["compilations"], 1);

    let default_mode_stats =
        run_sccache_in_process_command(root, &["--show-stats", "--stats-format=json"], false);
    assert!(default_mode_stats.status.success());
    let default_mode_stats: serde_json::Value =
        serde_json::from_slice(&default_mode_stats.stdout).unwrap();
    assert_eq!(default_mode_stats["stats"]["compile_requests"], 2);

    let zero_stats = run_sccache_in_process_command(root, &["--zero-stats"], true);
    assert!(
        zero_stats.status.success(),
        "zero-stats failed: {}",
        String::from_utf8_lossy(&zero_stats.stderr)
    );
    let reset_stats =
        run_sccache_in_process_command(root, &["--show-stats", "--stats-format=json"], false);
    assert!(reset_stats.status.success());
    let reset_stats: serde_json::Value = serde_json::from_slice(&reset_stats.stdout).unwrap();
    assert_eq!(reset_stats["stats"]["compile_requests"], 0);
    assert_eq!(reset_stats["stats"]["compilations"], 0);
}

#[test]
fn test_in_process_disk_cache_supports_concurrent_wrappers() {
    let root = tempdir().unwrap();
    let root = root.path();
    let cache_dir = root.join("sccache");

    let wrappers: Vec<_> = (0..4)
        .map(|worker| {
            let root = root.to_path_buf();
            let cache_dir = cache_dir.clone();
            std::thread::spawn(move || {
                let work_dir = root.join(format!("worker-{worker}"));
                create_dir_all(&work_dir).unwrap();
                fs::write(work_dir.join("counter"), b"0").unwrap();
                fs::write(work_dir.join("RUST_FILE.rs"), []).unwrap();
                create_mock_rustc(work_dir.join("rust"));
                run_sccache_in_process_with_cache(&work_dir, &work_dir.join("rust/bin"), &cache_dir)
            })
        })
        .collect();
    for wrapper in wrappers {
        let result = wrapper.join().unwrap();
        assert!(
            result.status.success(),
            "concurrent compile failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    let before =
        run_sccache_in_process_command(root, &["--show-stats", "--stats-format=json"], true);
    assert!(before.status.success());
    let before: serde_json::Value = serde_json::from_slice(&before.stdout).unwrap();
    assert_eq!(before["stats"]["compile_requests"], 4);
    let compilations_before = before["stats"]["compilations"].as_u64().unwrap();
    assert!(compilations_before >= 1);

    let first_work_dir = root.join("worker-0");
    let cached = run_sccache_in_process_with_cache(
        &first_work_dir,
        &first_work_dir.join("rust/bin"),
        &cache_dir,
    );
    assert!(cached.status.success());
    let after = run_sccache_in_process_command_with_cache(
        root,
        &cache_dir,
        &["--show-stats", "--stats-format=json"],
        true,
    );
    assert!(after.status.success());
    let after: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(after["stats"]["compilations"], compilations_before);
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
            echo {0}
            ;;
        --print=target-libdir)
            echo {0}/lib/rustlib/unknown/lib
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

fn run_sccache_in_process(root: &Path, path: &Path) -> std::process::Output {
    run_sccache_in_process_with_cache(root, path, &root.join("sccache"))
}

fn run_sccache_in_process_with_cache(
    root: &Path,
    path: &Path,
    cache_dir: &Path,
) -> std::process::Output {
    let mut paths: OsString = path.into();
    paths.push(":");
    paths.push(var_os("PATH").unwrap());

    Command::cargo_bin("sccache")
        .unwrap()
        .current_dir(root)
        .env("PATH", paths)
        .env("SCCACHE_DIR", cache_dir)
        .env("SCCACHE_IN_PROCESS", "1")
        .env("SCCACHE_SERVER_PORT", "invalid")
        .env_remove("SCCACHE_SERVER_UDS")
        .arg("rustc")
        .arg("RUST_FILE.rs")
        .arg("--crate-name=sccache_rustc_tests")
        .arg("--crate-type=lib")
        .arg("--emit=link")
        .arg("--out-dir")
        .arg(root)
        .output()
        .unwrap()
}

fn run_sccache_in_process_command(
    root: &Path,
    args: &[&str],
    in_process: bool,
) -> std::process::Output {
    run_sccache_in_process_command_with_cache(root, &root.join("sccache"), args, in_process)
}

fn run_sccache_in_process_command_with_cache(
    root: &Path,
    cache_dir: &Path,
    args: &[&str],
    in_process: bool,
) -> std::process::Output {
    let mut command = Command::cargo_bin("sccache").unwrap();
    command
        .current_dir(root)
        .env("SCCACHE_DIR", cache_dir)
        .env_remove("SCCACHE_SERVER_UDS");
    if in_process {
        command
            .env("SCCACHE_IN_PROCESS", "1")
            .env("SCCACHE_SERVER_PORT", "invalid");
    } else {
        command
            .env_remove("SCCACHE_IN_PROCESS")
            .env("SCCACHE_SERVER_PORT", "4324");
    }
    command.args(args).output().unwrap()
}
