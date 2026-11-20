#![cfg(target_env = "msvc")]
#[allow(dead_code, unused_imports)]
mod harness;

use assert_cmd::prelude::*;
use harness::ModuleCache;
use std::{fs, process::Command};
use test_case::test_case;

#[test_case(false)]
#[test_case(true)]
fn module_map_and_header_macros_invalidate_cache(direct: bool) {
    let cl = cc::Build::new()
        .host("x86_64-pc-windows-msvc")
        .target("x86_64-pc-windows-msvc")
        .opt_level(0)
        .get_compiler();
    let cache = ModuleCache::new(direct);
    let cwd = cache.dir.path();
    fs::create_dir(cwd.join("maps")).unwrap();
    fs::write(
        cwd.join("maps/module.toml"),
        "[[module]]\nname='m'\nifc='m.ifc'\n",
    )
    .unwrap();
    fs::write(
        cwd.join("use.cpp"),
        "import m;\nstatic_assert(answer == 11);\n",
    )
    .unwrap();
    let consumer = [
        "/nologo",
        "/std:c++20",
        "/c",
        "use.cpp",
        "/ifcMap",
        "maps/module.toml",
        "/Fouse.obj",
    ];
    for value in [11, 22] {
        fs::write(
            cwd.join("m.ixx"),
            format!("export module m;\nexport inline constexpr int answer = {value};\n"),
        )
        .unwrap();
        Command::new(cl.path())
            .envs(cl.env().iter().cloned())
            .current_dir(cwd)
            .args([
                "/nologo",
                "/std:c++20",
                "/c",
                "m.ixx",
                "/ifcOutput",
                "m.ifc",
                "/Fom.obj",
            ])
            .assert()
            .success();
        let mut cmd = cache.command();
        cmd.envs(cl.env().iter().cloned())
            .arg(cl.path())
            .args(consumer);
        if value == 11 {
            cmd.assert().success();
        } else {
            cmd.assert().failure();
        }
    }
    assert_eq!(cache.stats().stats.cache_hits.all(), 0);

    fs::write(cwd.join("mh.h"), "#include \"nested.h\"\n").unwrap();
    let producer = [
        "/nologo",
        "/std:c++20",
        "/c",
        "/exportHeader",
        "/TP",
        "mh.h",
        "/ifcOutput",
        "mh.ifc",
        "/Fomh.obj",
    ];
    for value in [11, 22] {
        fs::write(cwd.join("nested.h"), format!("#define ANSWER {value}\n")).unwrap();
        cache
            .command()
            .envs(cl.env().iter().cloned())
            .arg(cl.path())
            .args(producer)
            .assert()
            .success();
    }
    fs::write(
        cwd.join("mhuse.cpp"),
        "import \"mh.h\";\nstatic_assert(ANSWER == 22);\n",
    )
    .unwrap();
    Command::new(cl.path())
        .envs(cl.env().iter().cloned())
        .current_dir(cwd)
        .args([
            "/nologo",
            "/std:c++20",
            "/c",
            "/headerUnit:quote",
            "mh.h=mh.ifc",
            "mhuse.cpp",
            "/Fomhuse.obj",
        ])
        .assert()
        .success();
    cache
        .command()
        .envs(cl.env().iter().cloned())
        .arg(cl.path())
        .args(producer)
        .assert()
        .success();
    assert_eq!(cache.stats().stats.cache_hits.all(), 1);

    fs::create_dir(cwd.join("ifcs")).unwrap();
    let implicit = [
        "/nologo",
        "/std:c++20",
        "/c",
        "m.ixx",
        "/ifcOutput",
        "ifcs/",
        "/Fom.obj",
    ];
    for _ in 0..2 {
        cache
            .command()
            .envs(cl.env().iter().cloned())
            .arg(cl.path())
            .args(implicit)
            .assert()
            .success();
        assert!(cwd.join("ifcs/m.ifc").is_file());
        fs::remove_file(cwd.join("ifcs/m.ifc")).unwrap();
    }
}
