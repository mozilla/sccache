use std::{
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

use anyhow::{Context, Result};
use tempfile::Builder;

use crate::cache::disk::lock_cache_directory;
use crate::lru_disk_cache::{IN_PROCESS_STATS_FILE_NAME, TEMPFILE_PREFIX};
use crate::server::ServerStats;

pub fn read(cache_dir: &Path) -> Result<ServerStats> {
    let path = stats_path(cache_dir);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ServerStats::default());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };
    serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("failed to read {}", path.display()))
}

pub fn add(cache_dir: &Path, delta: ServerStats) -> Result<()> {
    let _lock = lock_cache_directory(cache_dir)?;
    let mut stats = match read(cache_dir) {
        Ok(stats) => stats,
        Err(error) => {
            log::warn!("could not read in-process statistics; resetting them: {error:#}");
            ServerStats::default()
        }
    };
    stats += delta;
    write(cache_dir, &stats)
}

pub fn zero(cache_dir: &Path) -> Result<()> {
    let _lock = lock_cache_directory(cache_dir)?;
    write(cache_dir, &ServerStats::default())
}

fn write(cache_dir: &Path, stats: &ServerStats) -> Result<()> {
    let path = stats_path(cache_dir);
    let mut temp = Builder::new()
        .prefix(TEMPFILE_PREFIX)
        .tempfile_in(cache_dir)
        .with_context(|| {
            format!(
                "failed to create temporary stats file in {}",
                cache_dir.display()
            )
        })?;
    serde_json::to_writer(&mut temp, stats).context("failed to serialize in-process statistics")?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to persist {}", path.display()))?;
    Ok(())
}

fn stats_path(cache_dir: &Path) -> std::path::PathBuf {
    cache_dir.join(IN_PROCESS_STATS_FILE_NAME)
}

#[cfg(test)]
#[path = "in_process_stats_tests.rs"]
mod tests;
