use std::fs;
use std::io;
use std::path::Path;

/// Test if reflink is supported on the given directory's filesystem.
pub fn is_reflink_supported(cache_dir: &Path) -> bool {
    let temp_dir = match tempfile::tempdir_in(cache_dir) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let src = temp_dir.path().join("test_src");
    let dst = temp_dir.path().join("test_dst");

    if fs::write(&src, b"test").is_err() {
        return false;
    }

    match reflink_copy::reflink(&src, &dst) {
        Ok(_) => {
            let _ = fs::remove_file(&dst);
            true
        }
        Err(_) => false,
    }
}

/// Copy file using reflink if supported, otherwise fall back to regular copy.
///
/// Note: `reflink_copy::reflink` requires the destination not to exist, while the
/// `fs::copy` fallback will overwrite an existing destination. Callers should ensure
/// the destination does not exist before calling this function if consistent behavior
/// is desired.
pub fn reflink_or_copy(src: &Path, dst: &Path) -> io::Result<()> {
    match reflink_copy::reflink(src, dst) {
        Ok(_) => Ok(()),
        Err(_) => {
            fs::copy(src, dst)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_reflink_or_copy_fallback() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");

        fs::write(&src, b"hello").unwrap();
        reflink_or_copy(&src, &dst).unwrap();

        assert!(dst.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"hello");
    }

    #[test]
    fn test_is_reflink_supported_runs_without_panic() {
        let dir = tempdir().unwrap();
        // Just verify it doesn't panic and returns a value.
        // On macOS with APFS this should return true; on other filesystems false.
        let _result = is_reflink_supported(dir.path());
    }

    #[test]
    fn test_reflink_or_copy_overwrites_destination() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");

        fs::write(&src, b"new content").unwrap();
        fs::write(&dst, b"old content").unwrap();

        reflink_or_copy(&src, &dst).unwrap();

        assert_eq!(fs::read(&dst).unwrap(), b"new content");
    }

    #[test]
    fn test_reflink_or_copy_preserves_content() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");

        let original_content = b"test data for reflink";
        fs::write(&src, original_content).unwrap();
        reflink_or_copy(&src, &dst).unwrap();

        assert_eq!(fs::read(&dst).unwrap(), original_content);
    }
}
