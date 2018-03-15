use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

// Assumes running under linux

fn execute_builder(input: &[u8], cmd: &[&str], toolchain: &Path) -> Vec<u8> {
    panic!()
}

fn get_native_toolchain() -> PathBuf {
    panic!()
}

fn get_windows_toolchain() -> PathBuf {
    panic!()
}

fn get_macos_toolchain() -> PathBuf {
    panic!()
}

fn verify_symbols(obj: &[u8], names: &[&str]) {
    panic!()
}

fn verify_debuginfo(obj: &[u8]) {
    panic!()
}

#[test]
fn compile_c() {
    let mut input = vec![];
    File::open("test.c").unwrap().read_to_end(&mut input).unwrap();
    let symbols = &["sym1", "sym2"];
    let cmd = panic!();

    let nat_out = &execute_builder(&input, cmd, &get_native_toolchain());
    let win_out = &execute_builder(&input, cmd, &get_windows_toolchain());
    let mac_out = &execute_builder(&input, cmd, &get_macos_toolchain());
    verify_symbols(nat_out, symbols);
    verify_symbols(win_out, symbols);
    verify_symbols(mac_out, symbols);
    verify_debuginfo(nat_out);
    verify_debuginfo(win_out);
    verify_debuginfo(mac_out);
}

#[test]
fn compile_cpp() {
    panic!()
}

#[test]
fn compile_objc() {
    panic!()
}

#[test]
fn compile_rust() {
    panic!()
}
