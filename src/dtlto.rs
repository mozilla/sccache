//! `sccache --dtlto`: a distributor for lld's Distributed ThinLTO (DTLTO) that
//! runs every ThinLTO backend job through the sccache client.

use crate::errors::*;
use crate::util::{Digest, num_cpus};
use fs_err::File;
use std::collections::HashMap;
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering::Relaxed};

/// The digest of the files a ThinLTO backend job reads, passed to the job in
/// this variable, which is part of the cache key.
pub const INPUTS_DIGEST_VAR: &str = "SCCACHE_DTLTO_INPUTS_DIGEST";

#[derive(serde::Deserialize)]
struct Args {
    args: Vec<String>,
    #[serde(default)]
    inputs: Vec<String>,
}

/// The part of lld's DTLTO job file sccache needs: the command of job `n` is
/// `common.args` followed by `jobs[n].args`, with the compiler first. `inputs`
/// are the files a job reads: its module, its index and the modules it
/// imports from; `common.inputs` are read by every job, e.g. profiles.
#[derive(serde::Deserialize)]
struct Jobs {
    common: Args,
    jobs: Vec<Args>,
}

/// The digest of every file `job` reads. The index already records a hash of
/// each imported module, but only if the module was written with one, so this
/// does not rely on it. The digests are sorted, so the order lld lists the
/// inputs in doesn't matter. Each file is hashed once per link, however many
/// jobs read it.
fn inputs_digest(
    jobs: &Jobs,
    job: &Args,
    digests: &Mutex<HashMap<String, String>>,
) -> Result<String> {
    let lock = || {
        digests
            .lock()
            .map_err(|_| anyhow!("a DTLTO worker panicked while hashing inputs"))
    };
    let mut file_digests = Vec::new();
    for input in jobs.common.inputs.iter().chain(&job.inputs) {
        let cached = lock()?.get(input).cloned();
        let digest = match cached {
            Some(digest) => digest,
            None => {
                let digest = Digest::reader_sync(File::open(input)?)?;
                lock()?.insert(input.clone(), digest.clone());
                digest
            }
        };
        file_digests.push(digest);
    }
    file_digests.sort_unstable();
    let mut m = Digest::new();
    for digest in file_digests {
        m.update(digest.as_bytes());
    }
    Ok(m.finish())
}

/// The sccache to run the jobs with. `current_exe()` resolves symlinks, and if
/// the file behind them isn't named `sccache`, it would act as a compiler.
fn sccache_exe() -> Result<PathBuf> {
    match env::args_os().next().map(PathBuf::from) {
        Some(argv0) if argv0.components().count() > 1 && argv0.is_file() => Ok(argv0),
        _ => env::current_exe().context("cannot locate the sccache executable"),
    }
}

/// Run every ThinLTO backend job from lld's DTLTO job file as
/// `sccache <compiler> <args>`, so each one goes through the usual client.
/// Once a job fails, no more jobs are taken; the running ones finish, and the
/// first failure's exit code is returned. A job that cannot be started is an
/// error instead.
pub fn run(path: &Path) -> Result<i32> {
    let jobs: Jobs = File::open(path)
        .map_err(Error::from)
        .and_then(|f| Ok(serde_json::from_reader(io::BufReader::new(f))?))
        .with_context(|| format!("failed to read DTLTO jobs from {}", path.display()))?;
    if jobs.common.args.is_empty() {
        bail!("no compiler in DTLTO jobs from {}", path.display());
    }
    let sccache = sccache_exe()?;
    let workers = match env::var("SCCACHE_DTLTO_JOBS") {
        Ok(n) if !n.is_empty() => n
            .parse::<usize>()
            .ok()
            .filter(|&n| n > 0)
            .with_context(|| format!("SCCACHE_DTLTO_JOBS={n} is not a positive number"))?,
        _ => num_cpus(),
    }
    .min(jobs.jobs.len());
    let digests = Mutex::new(HashMap::new());
    let next = AtomicUsize::new(0);
    // The first failure's exit code; 0 while every job has succeeded.
    let failed = AtomicI32::new(0);
    let fail = |code| {
        let _ = failed.compare_exchange(0, code, Relaxed, Relaxed);
    };
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| -> Result<()> {
                    while failed.load(Relaxed) == 0
                        && let Some(job) = jobs.jobs.get(next.fetch_add(1, Relaxed))
                    {
                        let status = inputs_digest(&jobs, job, &digests)
                            .context("failed to hash the inputs of a DTLTO job")
                            .and_then(|digest| {
                                process::Command::new(&sccache)
                                    .args(&jobs.common.args)
                                    .args(&job.args)
                                    .env(INPUTS_DIGEST_VAR, digest)
                                    .status()
                                    .context("failed to run a DTLTO job")
                            })
                            .inspect_err(|_| fail(1))?;
                        if !status.success() {
                            fail(status.code().filter(|&c| c != 0).unwrap_or(1));
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        // Join every worker before reporting, so no job outlives the command.
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|_| Err(anyhow!("a DTLTO worker panicked")))
            })
            .collect();
        results.into_iter().collect::<Result<()>>()
    })?;
    Ok(failed.into_inner())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_inputs_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        for name in ["module", "index", "imported", "profile"] {
            std::fs::write(path(name), name).unwrap();
        }
        let digest = |inputs: &[&str]| {
            let jobs: Jobs = serde_json::from_value(serde_json::json!({
                "common": {"args": ["clang"], "inputs": [path("profile")]},
                "jobs": [{"args": [], "inputs": inputs.iter().map(|i| path(i)).collect::<Vec<_>>()}],
            }))
            .unwrap();
            inputs_digest(&jobs, &jobs.jobs[0], &Mutex::default()).unwrap()
        };

        let base = digest(&["module", "index", "imported"]);
        assert_eq!(base, digest(&["imported", "module", "index"]));
        for changed in ["module", "index", "imported", "profile"] {
            std::fs::write(path(changed), "changed").unwrap();
            assert_ne!(base, digest(&["module", "index", "imported"]), "{changed}");
            std::fs::write(path(changed), changed).unwrap();
        }
        assert_eq!(base, digest(&["module", "index", "imported"]));
    }
}
