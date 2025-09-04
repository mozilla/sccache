pub mod helpers;

use anyhow::Result;
use helpers::SccacheTest;
use predicates::str::PredicateStrExt;
use serial_test::serial;

#[test]
#[serial]
fn test_sccache_cache_size() -> Result<()> {
    let test_info = SccacheTest::new(None)?;

    test_info
        .show_text_stats(false)?
        .try_stdout(
            predicates::str::is_match(r"Cache size\s+\d+\s")
                .unwrap()
                .from_utf8(),
        )?
        .try_success()?;
    Ok(())
}
