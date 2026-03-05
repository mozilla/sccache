
//! Client-side compiler detection.

use crate::compiler::{Compiler, get_compiler_info};
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use filetime::FileTime;
use fs::metadata;
use fs_err as fs;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Detect the compiler at the given path.
///
/// This function wraps the existing `get_compiler_info` to provide
/// a client-side interface for compiler detection.
pub async fn detect_compiler<C>(
    path: PathBuf,
    cwd: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<(Box<dyn Compiler<C>>, FileTime)>
where
    C: CommandCreatorSync + Send + 'static,
{
    // Get the modification time of the compiler executable
    let mtime = metadata(&path)
        .and_then(|attr| attr.modified())
        .ok()
        .map(FileTime::from_system_time)
        .unwrap_or_else(|| FileTime::zero());

    // Use the existing compiler detection logic
    let compiler = get_compiler_info(
        path.as_ref(),
        cwd,
        args,
        env,
        None, // pool - not needed for client-side detection
        None, // dist_archive - not used on client
    )
    .await?;

    Ok((compiler, mtime))
}
