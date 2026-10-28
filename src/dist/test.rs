use crate::dist::{ProcessOutput, Toolchain};
use crate::util::Digest;

fn roundtrip(archive_id: &str) -> bincode::Result<Toolchain> {
    let tc = Toolchain {
        archive_id: archive_id.to_owned(),
    };
    bincode::deserialize(&bincode::serialize(&tc).unwrap())
}

#[test]
fn test_toolchain_archive_id_digest_accepted() {
    let archive_id = Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    assert_eq!(roundtrip(&archive_id).unwrap().archive_id, archive_id);
    assert_eq!(
        roundtrip(&archive_id.to_uppercase()).unwrap().archive_id,
        archive_id
    );
}

#[test]
fn test_toolchain_archive_id_non_digest_rejected() {
    let digest = Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    for archive_id in [
        "",
        "a",
        "/tmp/toolchain",
        "../toolchain",
        &digest[1..],
        &format!("{digest}0"),
        &format!("/{}", &digest[1..]),
    ] {
        assert!(roundtrip(archive_id).is_err(), "accepted {archive_id:?}");
    }
}

#[test]
fn test_process_output_exit_code_is_kept() {
    let output: std::process::Output =
        ProcessOutput::fake_output(1, b"out".to_vec(), b"err".to_vec()).into();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(output.status.signal(), None);
    }
}

// A remote compile that fails with an exit code reached the client as "killed by signal <code>".
#[cfg(unix)]
#[test]
fn test_process_output_roundtrip_is_not_a_signal() {
    use std::os::unix::process::ExitStatusExt;
    for code in [0, 1, 2, 127] {
        let compiled = std::process::Output {
            status: crate::util::exit_status_from_code(code),
            stdout: vec![],
            stderr: vec![],
        };
        let received: std::process::Output = ProcessOutput::try_from(compiled).unwrap().into();
        assert_eq!(received.status.code(), Some(code), "exit code {code}");
        assert_eq!(received.status.signal(), None, "exit code {code}");
    }
}
