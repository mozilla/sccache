use crate::dist::Toolchain;
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
