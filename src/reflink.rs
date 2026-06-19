// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Filesystem reflink (copy-on-write) helpers for the `file_clone` disk cache mode.

use std::fs;
use std::io;
use std::path::Path;

#[cfg(target_os = "linux")]
use std::fs::File;

use tempfile::NamedTempFile;

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex};

/// Whether a file was reflinked (shared blocks) or copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflinkOutcome {
    Reflinked,
    Copied(u64),
}

impl ReflinkOutcome {
    /// `true` when the data was reflinked rather than copied.
    pub fn reflinked(self) -> bool {
        matches!(self, ReflinkOutcome::Reflinked)
    }
}

/// Probe whether the filesystem backing `dir` supports reflinking.
pub fn is_reflink_supported(dir: &Path) -> bool {
    let Ok(temp_dir) = tempfile::tempdir_in(dir) else {
        return false;
    };
    let src = temp_dir.path().join("reflink_probe_src");
    let dst = temp_dir.path().join("reflink_probe_dst");
    if fs::write(&src, b"sccache reflink probe").is_err() {
        return false;
    }
    reflink_copy::reflink(&src, &dst).is_ok()
}

/// Reflink (or copy) `src` to a new file `dest` (which must not exist), optionally setting `mode`.
/// Returns whether the data was reflinked or copied.
pub fn reflink_or_copy_new(
    src: &Path,
    dest: &Path,
    mode: Option<u32>,
) -> io::Result<ReflinkOutcome> {
    #[cfg(target_os = "linux")]
    {
        let src_file = File::open(src)?;
        let dst_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)?;
        let outcome = clone_or_copy_fd(&src_file, &dst_file)?;
        apply_fd_mode(&dst_file, dest, mode);
        Ok(outcome)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Enforce the "dest must not exist" contract on every platform: where the filesystem
        // doesn't support reflinks, the crate would otherwise fall back to a copy that
        // overwrites an existing dest (Linux gets this for free via `create_new`).
        if dest.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination already exists",
            ));
        }
        crate_reflink_or_copy(src, dest, mode)
    }
}

/// Reflink (or copy) `src` to `dest`, atomically replacing any existing file, optionally setting
/// `mode`. Returns whether the data was reflinked or copied.
pub fn reflink_or_copy_atomic(
    src: &Path,
    dest: &Path,
    mode: Option<u32>,
) -> io::Result<ReflinkOutcome> {
    let dest_dir = dest.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination path has no parent directory",
        )
    })?;

    #[cfg(target_os = "linux")]
    {
        let tmp = NamedTempFile::new_in(dest_dir)?;
        let src_file = open_src_nofollow(src)?;
        let outcome = clone_or_copy_fd(&src_file, tmp.as_file())?;
        apply_fd_mode(tmp.as_file(), dest, mode);
        tmp.persist(dest).map_err(|e| e.error)?;
        Ok(outcome)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let tmp_path = NamedTempFile::new_in(dest_dir)?.into_temp_path();
        fs::remove_file(&tmp_path)?;
        let outcome = crate_reflink_or_copy(src, &tmp_path, mode)?;
        tmp_path.persist(dest).map_err(|e| e.error)?;
        Ok(outcome)
    }
}

/// Reflink (or copy) `src` directly onto `dest` in place (non-atomic fallback for when a temp file
/// cannot be staged in the destination directory).
pub fn reflink_or_copy_direct(
    src: &Path,
    dest: &Path,
    mode: Option<u32>,
) -> io::Result<ReflinkOutcome> {
    #[cfg(target_os = "linux")]
    {
        let src_file = open_src_nofollow(src)?;
        let dst_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;
        let outcome = clone_or_copy_fd(&src_file, &dst_file)?;
        apply_fd_mode(&dst_file, dest, mode);
        Ok(outcome)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The destination dir may be non-writable (that's why the atomic temp path failed), so
        // overwrite the existing file in place; clonefile can't target an existing file → plain copy.
        let mut reader = fs::File::open(src)?;
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;
        let n = io::copy(&mut reader, &mut writer)?;
        set_path_mode(dest, mode);
        Ok(ReflinkOutcome::Copied(n))
    }
}

#[cfg(target_os = "linux")]
fn open_src_nofollow(src: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(src)
}

#[cfg(target_os = "linux")]
fn apply_fd_mode(file: &File, dest: &Path, mode: Option<u32>) {
    if let Some(mode) = mode {
        if let Err(e) = set_fd_mode(file, mode) {
            debug!(
                "Failed to set mode {:#o} on {}: {}",
                mode,
                dest.display(),
                e
            );
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_path_mode(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        if let Err(e) = fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            debug!(
                "Failed to set mode {:#o} on {}: {}",
                mode,
                path.display(),
                e
            );
        }
    }
}

#[cfg(not(unix))]
fn set_path_mode(_path: &Path, _mode: Option<u32>) {}

#[cfg(not(target_os = "linux"))]
fn crate_reflink_or_copy(src: &Path, dest: &Path, mode: Option<u32>) -> io::Result<ReflinkOutcome> {
    let outcome = match reflink_copy::reflink_or_copy(src, dest) {
        Ok(None) => ReflinkOutcome::Reflinked,
        Ok(Some(n)) => ReflinkOutcome::Copied(n),
        Err(e) => return Err(e),
    };
    set_path_mode(dest, mode);
    Ok(outcome)
}

#[cfg(target_os = "linux")]
fn clone_or_copy_fd(src: &File, dst: &File) -> io::Result<ReflinkOutcome> {
    use std::os::unix::fs::MetadataExt;

    let dev = dst.metadata().ok().map(|m| m.dev());
    if dev.map(device_known_unsupported).unwrap_or(false) {
        return Ok(ReflinkOutcome::Copied(copy_fd(src, dst)?));
    }
    match ficlone(dst, src) {
        Ok(()) => Ok(ReflinkOutcome::Reflinked),
        Err(e) => {
            remember_unsupported(dev, &e);
            Ok(ReflinkOutcome::Copied(copy_fd(src, dst)?))
        }
    }
}

#[cfg(target_os = "linux")]
fn ficlone(dst: &File, src: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: both descriptors are valid and owned by `dst`/`src` for the duration of the call.
    let ret = unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn copy_fd(src: &File, dst: &File) -> io::Result<u64> {
    use std::io::{Seek, SeekFrom};
    dst.set_len(0)?;
    let mut reader: &File = src;
    let mut writer: &File = dst;
    (&mut reader).seek(SeekFrom::Start(0))?;
    (&mut writer).seek(SeekFrom::Start(0))?;
    io::copy(&mut reader, &mut writer)
}

#[cfg(target_os = "linux")]
fn set_fd_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file` owns a valid descriptor for the duration of the call.
    let ret = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
static UNSUPPORTED_DEVICES: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(target_os = "linux")]
fn device_known_unsupported(dev: u64) -> bool {
    UNSUPPORTED_DEVICES.lock().unwrap().contains(&dev)
}

#[cfg(target_os = "linux")]
fn remember_unsupported(dev: Option<u64>, err: &io::Error) {
    // EXDEV (cross-filesystem) is intentionally not memoised: it's a property of this src/dst pair,
    // not of the device's reflink capability.
    let unsupported = matches!(err.kind(), io::ErrorKind::Unsupported)
        || matches!(
            err.raw_os_error(),
            Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY)
        );
    if !unsupported {
        return;
    }
    if let Some(dev) = dev {
        let newly = UNSUPPORTED_DEVICES.lock().unwrap().insert(dev);
        if newly {
            warn!(
                "file_clone: reflink not supported on destination filesystem (device {dev}): {err}. \
                 Falling back to copies; restored files will not share disk blocks with the cache."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_reflink_or_copy_new_preserves_content() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        let content = b"test data for reflink-or-copy-new";
        fs::write(&src, content).unwrap();

        let outcome = reflink_or_copy_new(&src, &dst, None).unwrap();
        match outcome {
            ReflinkOutcome::Reflinked | ReflinkOutcome::Copied(_) => {}
        }
        assert!(dst.exists());
        assert_eq!(fs::read(&dst).unwrap(), content);
    }

    #[test]
    fn test_reflink_or_copy_new_fails_if_dest_exists() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"a").unwrap();
        fs::write(&dst, b"b").unwrap();
        assert!(reflink_or_copy_new(&src, &dst, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_reflink_or_copy_new_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"executable-ish").unwrap();

        reflink_or_copy_new(&src, &dst, Some(0o600)).unwrap();
        let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_reflink_or_copy_atomic_overwrites_destination() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"new content").unwrap();
        fs::write(&dst, b"old content").unwrap();

        let outcome = reflink_or_copy_atomic(&src, &dst, None).unwrap();
        match outcome {
            ReflinkOutcome::Reflinked | ReflinkOutcome::Copied(_) => {}
        }
        assert_eq!(fs::read(&dst).unwrap(), b"new content");
    }

    #[cfg(unix)]
    #[test]
    fn test_reflink_or_copy_atomic_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"data").unwrap();

        reflink_or_copy_atomic(&src, &dst, Some(0o640)).unwrap();
        let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn test_reflink_or_copy_atomic_empty_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"").unwrap();

        reflink_or_copy_atomic(&src, &dst, None).unwrap();
        assert!(dst.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"");
    }

    #[test]
    fn test_reflink_or_copy_direct_overwrites() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"fresh").unwrap();
        fs::write(&dst, b"stale-and-longer").unwrap();
        reflink_or_copy_direct(&src, &dst, None).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"fresh");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_extract_refuses_symlinked_source() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let secret = dir.path().join("secret");
        fs::write(&secret, b"top secret outside the cache").unwrap();
        let link = dir.path().join("obj_symlink");
        symlink(&secret, &link).unwrap();
        let dest = dir.path().join("restored");

        assert!(reflink_or_copy_atomic(&link, &dest, None).is_err());
        assert!(reflink_or_copy_direct(&link, &dest, None).is_err());
        assert!(!dest.exists());
    }

    #[test]
    fn test_is_reflink_supported_nonexistent_dir_is_false() {
        let dir = tempdir().unwrap();
        assert!(!is_reflink_supported(&dir.path().join("does-not-exist")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_remember_unsupported_logic() {
        let unsupp = u64::MAX - 101;
        remember_unsupported(
            Some(unsupp),
            &io::Error::from_raw_os_error(libc::EOPNOTSUPP),
        );
        assert!(device_known_unsupported(unsupp));

        let notty = u64::MAX - 102;
        remember_unsupported(Some(notty), &io::Error::from_raw_os_error(libc::ENOTTY));
        assert!(device_known_unsupported(notty));

        let xdev = u64::MAX - 103;
        remember_unsupported(Some(xdev), &io::Error::from_raw_os_error(libc::EXDEV));
        assert!(!device_known_unsupported(xdev));

        let transient = u64::MAX - 104;
        remember_unsupported(Some(transient), &io::Error::from_raw_os_error(libc::EINTR));
        assert!(!device_known_unsupported(transient));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_copy_fd_roundtrip() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("src");
        let data = vec![42u8; 9000];
        fs::write(&src_path, &data).unwrap();
        let src = File::open(&src_path).unwrap();
        let dst_path = dir.path().join("dst");
        fs::write(&dst_path, vec![0u8; 20000]).unwrap();
        let dst = fs::OpenOptions::new().write(true).open(&dst_path).unwrap();

        let n = copy_fd(&src, &dst).unwrap();
        assert_eq!(n, data.len() as u64);
        drop(dst);
        assert_eq!(fs::read(&dst_path).unwrap(), data);
    }
}
