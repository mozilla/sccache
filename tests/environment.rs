mod util;

use std::env;
use std::ffi::OsString;
use std::process::Command;
use util::TestCommandExt;

#[test]
fn command_helpers_isolate_environment() {
    let mut inherited: Vec<(OsString, Option<OsString>)> = [
        ("SCCACHE_REDIS", "redis://invalid"),
        ("SCCACHE_NO_DAEMON", "1"),
        ("SCCACHE_LOG", "off"),
        ("SCCACHE_UNKNOWN_TEST_SETTING", "unknown"),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), Some(value.into())))
    .collect();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        inherited.push((
            OsString::from_vec(b"SCCACHE_\xff".to_vec()),
            Some("non-unicode".into()),
        ));
    }
    #[cfg(windows)]
    inherited.push((
        "sccache_lowercase_test".into(),
        Some("case-insensitive".into()),
    ));

    temp_env::with_vars(&inherited, || {
        let sccache = Command::sccache();
        assert_eq!(sccache.get_program(), env!("CARGO_BIN_EXE_sccache"));
        let cargo = Command::cargo();
        assert_eq!(
            cargo.get_program(),
            env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
        );
        let mut custom = Command::new("unused");
        custom
            .env("SCCACHE_CONFIGURED_TEST", "configured before clearing")
            .env("TEST_UNRELATED_ENV", "preserved");
        let custom = custom.clear_sccache_env_vars();
        assert!(custom.get_envs().any(|(name, value)| {
            name == "TEST_UNRELATED_ENV" && value == Some("preserved".as_ref())
        }));

        for (mut command, log) in [(sccache, Some("debug")), (cargo, None), (custom, None)] {
            for (name, _) in &inherited {
                let expected = if name == "SCCACHE_LOG" { log } else { None };
                assert_eq!(
                    command.get_envs().find(|(key, _)| *key == name),
                    Some((name.as_os_str(), expected.map(std::ffi::OsStr::new)))
                );
            }
            assert!(command.get_envs().all(|(name, value)| {
                value.is_none() || name == "SCCACHE_LOG" || name == "TEST_UNRELATED_ENV"
            }));
            for (name, value) in [("SCCACHE_DIR", "test-cache"), ("SCCACHE_LOG", "trace")] {
                command.env(name, value);
                assert!(command.get_envs().any(|(key, configured)| {
                    key == name && configured == Some(value.as_ref())
                }));
            }
        }

        assert_eq!(env::var("SCCACHE_REDIS").unwrap(), "redis://invalid");
    });
}
