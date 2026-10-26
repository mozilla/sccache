use std::{path::PathBuf, thread};

use tempfile::tempdir;

use super::{add, read, zero};
use crate::lru_disk_cache::IN_PROCESS_STATS_FILE_NAME;
use crate::server::ServerStats;

#[test]
fn concurrent_updates_are_preserved_and_can_be_zeroed() {
    let dir = tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    let workers = 8;
    let updates_per_worker = 20;

    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let cache_dir: PathBuf = cache_dir.clone();
            thread::spawn(move || {
                for _ in 0..updates_per_worker {
                    let delta = ServerStats {
                        compile_requests: 1,
                        ..ServerStats::default()
                    };
                    add(&cache_dir, delta).unwrap();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(
        read(&cache_dir).unwrap().compile_requests,
        workers * updates_per_worker
    );
    zero(&cache_dir).unwrap();
    assert_eq!(read(&cache_dir).unwrap().compile_requests, 0);
}

#[cfg(unix)]
#[test]
fn stats_are_stored_in_cache_when_parent_is_not_writable() {
    use std::{fs, os::unix::fs::PermissionsExt};

    let dir = tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    let original_permissions = fs::metadata(dir.path()).unwrap().permissions();
    let mut read_only_permissions = original_permissions.clone();
    read_only_permissions.set_mode(original_permissions.mode() & !0o222);
    fs::set_permissions(dir.path(), read_only_permissions).unwrap();

    let result = (|| {
        add(
            &cache_dir,
            ServerStats {
                compile_requests: 1,
                ..ServerStats::default()
            },
        )?;
        assert_eq!(read(&cache_dir)?.compile_requests, 1);
        zero(&cache_dir)?;
        assert_eq!(read(&cache_dir)?.compile_requests, 0);
        Ok::<_, anyhow::Error>(())
    })();

    fs::set_permissions(dir.path(), original_permissions).unwrap();
    result.unwrap();
    assert!(cache_dir.join(IN_PROCESS_STATS_FILE_NAME).exists());
    assert!(!dir.path().join(".cache.in_process_stats.json").exists());
    assert!(!dir.path().join(".cache.in_process_stats.lock").exists());
}
