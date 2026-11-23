use std::env;
use std::ffi::OsString;
use std::process::Command;
use std::sync::LazyLock;

#[allow(dead_code)] // Some integration-test crates never invoke Cargo.
static CARGO: LazyLock<OsString> =
    LazyLock::new(|| env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));

pub trait TestCommandExt {
    /// Construct an isolated `sccache` command with `SCCACHE_LOG=debug`.
    fn sccache() -> Self;

    /// Construct a `cargo` command without inherited `SCCACHE_*` settings.
    #[allow(dead_code)] // Some integration-test crates never invoke Cargo.
    fn cargo() -> Self;

    /// Remove inherited and explicitly configured `SCCACHE_*` variables.
    fn clear_sccache_env_vars(self) -> Self;
}

impl TestCommandExt for Command {
    fn sccache() -> Self {
        let mut command = Self::new(env!("CARGO_BIN_EXE_sccache")).clear_sccache_env_vars();
        command.env("SCCACHE_LOG", "debug");
        command
    }

    fn cargo() -> Self {
        Self::new(CARGO.as_os_str()).clear_sccache_env_vars()
    }

    fn clear_sccache_env_vars(mut self) -> Self {
        let names: Vec<_> = env::vars_os()
            .map(|(name, _)| name)
            .chain(self.get_envs().map(|(name, _)| name.to_owned()))
            .collect();
        for name in names {
            let prefix = b"SCCACHE_";
            let matches = name
                .as_encoded_bytes()
                .get(..prefix.len())
                .is_some_and(|name| {
                    if cfg!(windows) {
                        name.eq_ignore_ascii_case(prefix)
                    } else {
                        name == prefix
                    }
                });
            if matches {
                self.env_remove(name);
            }
        }
        self
    }
}
