pub use sccache_dist::{
    AllocJobResult, RunJobResult, SubmitToolchainResult,
    CompileCommand, Toolchain,
    Client,
    NoopClient,
};
pub mod http {
    pub use sccache_dist::http::Client;
}

use super::compiler;

// TODO: TryFrom
pub fn try_compile_command_to_dist(command: compiler::CompileCommand) -> Option<CompileCommand> {
    let compiler::CompileCommand {
        executable,
        arguments,
        env_vars,
        cwd,
    } = command;
    Some(CompileCommand {
        executable: executable.into_os_string().into_string().ok()?,
        arguments: arguments.into_iter().map(|arg| arg.into_string().ok()).collect::<Option<_>>()?,
        env_vars: env_vars.into_iter()
            .map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect::<Option<_>>()?,
        cwd: cwd.into_os_string().into_string().ok()?,
    })
}
