// Copyright 2016 Mozilla Foundation
//
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

use anyhow::{Context, Error, Result, anyhow, bail};
use flate2::read::GzDecoder;
use fs_err as fs;
use libmount::Overlay;
use sccache::dist::{
    BuildResult, BuilderIncoming, CompileCommand, InputsReader, OutputData, ProcessOutput, TcCache,
    Toolchain,
};
use sccache::lru_disk_cache::Error as LruError;
use std::collections::{HashMap, hash_map};
use std::io;
use std::iter;
use std::path::{self, Path, PathBuf};
use std::process::{ChildStdin, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use version_compare::Version;

trait CommandExt {
    fn check_stdout_trim(&mut self) -> Result<String>;
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()>;
    fn check_run(&mut self) -> Result<()>;
}

impl CommandExt for Command {
    fn check_stdout_trim(&mut self) -> Result<String> {
        let output = self.output().context("Failed to start command")?;
        check_output(&output)?;
        let stdout =
            String::from_utf8(output.stdout).context("Output from listing containers not UTF8")?;
        Ok(stdout.trim().to_owned())
    }
    // Should really take a FnOnce/FnBox
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()> {
        let mut process = self
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to start command")?;
        let mut stdin = process
            .stdin
            .take()
            .expect("Requested piped stdin but not present");
        pipe(&mut stdin).context("Failed to pipe input to process")?;
        let output = process
            .wait_with_output()
            .context("Failed to wait for process to return")?;
        check_output(&output)
    }
    fn check_run(&mut self) -> Result<()> {
        let output = self.output().context("Failed to start command")?;
        check_output(&output)
    }
}

fn check_output(output: &Output) -> Result<()> {
    if !output.status.success() {
        warn!(
            "===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        bail!("Command failed with status {}", output.status)
    }
    Ok(())
}

fn join_suffix<P: AsRef<Path>>(path: &Path, suffix: P) -> PathBuf {
    let suffixpath = suffix.as_ref();
    let mut components = suffixpath.components();
    if suffixpath.has_root() {
        assert_eq!(components.next(), Some(path::Component::RootDir));
    }
    path.join(components)
}

#[derive(Debug)]
struct OverlaySpec {
    build_dir: PathBuf,
    toolchain_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct DeflatedToolchain {
    path: PathBuf,
    build_count: u64,
    ctime: Instant,
}

pub struct OverlayBuilder {
    bubblewrap: PathBuf,
    dir: PathBuf,
    toolchain_dir_map: Mutex<HashMap<Toolchain, DeflatedToolchain>>,
    // Per-toolchain preparation locks. The gzip+untar of an uncached toolchain
    // runs under the matching entry lock here, NOT under toolchain_dir_map, so
    // two requests for different toolchains prepare in parallel while two for
    // the same uncached toolchain serialize (no half-written dir, no double
    // unpack).
    toolchain_prepare_locks: Mutex<HashMap<Toolchain, Arc<Mutex<()>>>>,
}

// Return the preparation lock for `tc`, creating it on first use. Held only
// long enough to look up or insert the entry, so distinct toolchains never
// contend here. Same key yields the same Arc; distinct keys yield distinct
// Arcs.
fn get_prepare_lock(
    locks: &Mutex<HashMap<Toolchain, Arc<Mutex<()>>>>,
    tc: &Toolchain,
) -> Arc<Mutex<()>> {
    locks
        .lock()
        .unwrap()
        .entry(tc.clone())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

impl OverlayBuilder {
    pub fn new(bubblewrap: PathBuf, dir: PathBuf) -> Result<Self> {
        info!("Creating overlay builder");

        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            // Not root, or a setuid binary - haven't put enough thought into supporting this, bail
            bail!("not running as root")
        }

        let out = Command::new(&bubblewrap)
            .arg("--version")
            .check_stdout_trim()
            .context("Failed to execute bwrap for version check")?;
        if let Some(s) = out.split_whitespace().nth(1) {
            match (Version::from("0.3.0"), Version::from(s)) {
                (Some(min), Some(seen)) => {
                    if seen < min {
                        bail!(
                            "bubblewrap 0.3.0 or later is required, got {:?} for {:?}",
                            out,
                            bubblewrap
                        );
                    }
                }
                (_, _) => {
                    bail!(
                        "Unexpected version format running {:?}: got {:?}, expected \"bubblewrap x.x.x\"",
                        bubblewrap,
                        out
                    );
                }
            }
        } else {
            bail!(
                "Unexpected version format running {:?}: got {:?}, expected \"bubblewrap x.x.x\"",
                bubblewrap,
                out
            );
        }

        // TODO: pidfile
        let ret = Self {
            bubblewrap,
            dir,
            toolchain_dir_map: Mutex::new(HashMap::new()),
            toolchain_prepare_locks: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        fs::create_dir(&ret.dir).context("Failed to create base directory for builder")?;
        fs::create_dir(ret.dir.join("builds"))
            .context("Failed to create builder builds directory")?;
        fs::create_dir(ret.dir.join("toolchains"))
            .context("Failed to create builder toolchains directory")?;
        Ok(ret)
    }

    fn cleanup(&self) -> Result<()> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).context("Failed to clean up builder directory")?;
        }
        Ok(())
    }

    fn prepare_overlay_dirs(
        &self,
        tc: &Toolchain,
        tccache: &Mutex<TcCache>,
    ) -> Result<OverlaySpec> {
        let toolchain_dir = self.dir.join("toolchains").join(&tc.archive_id);

        // Fast path: an already-prepared toolchain just bumps its build
        // counter. The global map lock is held only for this lookup.
        if let Some(entry) = self.bump_prepared_toolchain(tc, &toolchain_dir) {
            return self.make_overlay_spec(tc, entry);
        }

        // Serialize preparation on the per-toolchain lock, NOT the global map
        // lock, so requests for different toolchains prepare in parallel while
        // requests for the same uncached toolchain wait here.
        let prepare_lock = get_prepare_lock(&self.toolchain_prepare_locks, tc);
        let _prepare_guard = prepare_lock.lock().unwrap();

        // Another request may have prepared this toolchain while we waited on
        // the prepare lock; re-check before unpacking.
        if let Some(entry) = self.bump_prepared_toolchain(tc, &toolchain_dir) {
            return self.make_overlay_spec(tc, entry);
        }

        trace!("Creating toolchain directory for {}", tc.archive_id);
        // We hold this toolchain's prepare lock and it is absent from the map, so
        // any directory on disk is a stale leftover (an interrupted preparation,
        // or an eviction that pruned the map entry before deleting the dir). Clear
        // it so create_dir does not fail with AlreadyExists.
        if toolchain_dir.exists() {
            fs::remove_dir_all(&toolchain_dir)
                .context("Failed to remove stale toolchain directory")?;
        }
        fs::create_dir(&toolchain_dir)?;

        {
            // Take an owned handle to the cached archive under the lock, then
            // release the tccache mutex before untarring. The archive reader used
            // to borrow the cache guard, which serialized every toolchain's untar
            // on this one mutex; an owned File lets different toolchains untar in
            // parallel.
            let toolchain_file = {
                let mut tccache = tccache.lock().unwrap();
                match tccache.get_file(tc) {
                    Ok(file) => file,
                    Err(LruError::FileNotInCache) => {
                        bail!("expected toolchain {}, but not available", tc.archive_id)
                    }
                    Err(e) => {
                        return Err(Error::from(e).context("failed to get toolchain from cache"));
                    }
                }
            };

            tar::Archive::new(GzDecoder::new(toolchain_file))
                .unpack(&toolchain_dir)
                .or_else(|e| {
                    warn!("Failed to unpack toolchain: {:?}", e);
                    fs::remove_dir_all(&toolchain_dir)
                        .context("Failed to remove unpacked toolchain")?;
                    // Removing the corrupt archive needs the cache lock again;
                    // the untar handle is dropped by now, so re-acquire briefly.
                    tccache
                        .lock()
                        .unwrap()
                        .remove(tc)
                        .context("Failed to remove corrupt toolchain")?;
                    Err(Error::from(e))
                })?;
        }

        let entry = DeflatedToolchain {
            path: toolchain_dir,
            build_count: 1,
            ctime: Instant::now(),
        };

        // Insert the new entry and pick eviction victims under the global map
        // lock, but run the remove_dir_all for each victim AFTER dropping it so
        // filesystem teardown never serializes concurrent preparations.
        let mut evictions: Vec<Toolchain> = Vec::new();
        {
            let mut toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
            toolchain_dir_map.insert(tc.clone(), entry.clone());
            if toolchain_dir_map.len() > tccache.lock().unwrap().len() {
                let dir_map = toolchain_dir_map.clone();
                let mut entries: Vec<_> = dir_map.iter().collect();
                // In the pathological case, creation time for unpacked
                // toolchains could be the opposite of the least recently
                // recently used, so we clear out half of the accumulated
                // toolchains to prevent repeated sort/delete cycles.
                entries.sort_by_key(|a| (a.1).ctime);
                entries.truncate(entries.len() / 2);
                for (victim, _) in entries {
                    if toolchain_dir_map.remove(victim).is_some() {
                        evictions.push(victim.clone());
                    } else {
                        warn!(
                            "toolchain {:?} already gone from dir map during eviction",
                            victim
                        );
                    }
                }
            }
        }
        for victim in evictions {
            // Delete each victim under its own preparation lock so a concurrent
            // request that legitimately re-prepares the same toolchain cannot
            // create_dir+untar into the path we are deleting. Use try_lock, never
            // a blocking acquire: we already hold this request's prepare lock, and
            // blocking on a second prepare lock could deadlock against a racer that
            // picked us as its own eviction victim. A held lock means a racer is
            // actively preparing the victim, so skip its deletion.
            let victim_lock = get_prepare_lock(&self.toolchain_prepare_locks, &victim);
            let _victim_guard = match victim_lock.try_lock() {
                Ok(guard) => guard,
                Err(_) => {
                    trace!("Skipping eviction of {:?}: being prepared", victim);
                    continue;
                }
            };

            // A racer may have finished re-preparing the victim while we waited on
            // its lock. Re-verify it is still absent from the map before deleting,
            // holding the map lock only for the check and never across the
            // remove_dir_all below (keeps map and prepare locks disjoint).
            {
                let toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
                if toolchain_dir_map.contains_key(&victim) {
                    trace!("Skipping eviction of {:?}: re-prepared", victim);
                    continue;
                }
            }

            warn!("Removing old un-compressed toolchain: {:?}", victim);
            fs::remove_dir_all(self.dir.join("toolchains").join(&victim.archive_id))
                .context("Failed to remove old toolchain directory")?;

            // Prune the now-unused preparation lock entry so the map does not grow
            // without bound as toolchains churn.
            self.toolchain_prepare_locks.lock().unwrap().remove(&victim);
        }

        self.make_overlay_spec(tc, entry)
    }

    // Bump and return a clone of the prepared-toolchain entry when it is both
    // recorded in the map and present on disk, else None. Holds the global map
    // lock only for the lookup and counter bump.
    fn bump_prepared_toolchain(
        &self,
        tc: &Toolchain,
        toolchain_dir: &Path,
    ) -> Option<DeflatedToolchain> {
        let mut toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
        if toolchain_dir_map.contains_key(tc) && toolchain_dir.exists() {
            let entry = toolchain_dir_map
                .get_mut(tc)
                .expect("Key missing after checking");
            entry.build_count += 1;
            Some(entry.clone())
        } else {
            None
        }
    }

    fn make_overlay_spec(&self, tc: &Toolchain, entry: DeflatedToolchain) -> Result<OverlaySpec> {
        let DeflatedToolchain {
            path: toolchain_dir,
            build_count: id,
            ctime: _,
        } = entry;
        trace!("Creating build directory for {}-{}", tc.archive_id, id);
        let build_dir = self
            .dir
            .join("builds")
            .join(format!("{}-{}", tc.archive_id, id));
        fs::create_dir(&build_dir)?;
        Ok(OverlaySpec {
            build_dir,
            toolchain_dir,
        })
    }

    fn perform_build(
        bubblewrap: &Path,
        compile_command: CompileCommand,
        inputs_rdr: InputsReader,
        output_paths: Vec<String>,
        overlay: &OverlaySpec,
    ) -> Result<BuildResult> {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable, compile_command.arguments
        );

        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // Now mounted filesystems will be automatically unmounted when this thread dies
                    // (and tmpfs filesystems will be completely destroyed)
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
                        .context("Failed to enter a new Linux namespace")?;
                    // Make sure that all future mount changes are private to this namespace
                    // TODO: shouldn't need to add these annotations
                    let source: Option<&str> = None;
                    let fstype: Option<&str> = None;
                    let data: Option<&str> = None;
                    // Turn / into a 'slave', so it receives mounts from real root, but doesn't propagate back
                    nix::mount::mount(
                        source,
                        "/",
                        fstype,
                        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                        data,
                    )
                    .context("Failed to turn / into a slave")?;

                    let work_dir = overlay.build_dir.join("work");
                    let upper_dir = overlay.build_dir.join("upper");
                    let target_dir = overlay.build_dir.join("target");
                    fs::create_dir(&work_dir).context("Failed to create overlay work directory")?;
                    fs::create_dir(&upper_dir)
                        .context("Failed to create overlay upper directory")?;
                    fs::create_dir(&target_dir)
                        .context("Failed to create overlay target directory")?;

                    let () = Overlay::writable(
                        iter::once(overlay.toolchain_dir.as_path()),
                        upper_dir,
                        work_dir,
                        &target_dir,
                        // This error is unfortunately not Send+Sync
                    )
                    .mount()
                    .map_err(|e| anyhow!("Failed to mount overlay FS: {}", e))?;

                    trace!("copying in inputs");
                    // Note that we don't unpack directly into the upperdir since there overlayfs has some
                    // special marker files that we don't want to create by accident (or malicious intent)
                    tar::Archive::new(inputs_rdr)
                        .unpack(&target_dir)
                        .context("Failed to unpack inputs to overlay")?;

                    let CompileCommand {
                        executable,
                        arguments,
                        env_vars,
                        cwd,
                    } = compile_command;
                    let cwd = Path::new(&cwd);

                    trace!("creating output directories");
                    fs::create_dir_all(join_suffix(&target_dir, cwd))
                        .context("Failed to create cwd")?;
                    for path in output_paths.iter() {
                        // If it doesn't have a parent, nothing needs creating
                        let output_parent = if let Some(p) = Path::new(path).parent() {
                            p
                        } else {
                            continue;
                        };
                        fs::create_dir_all(join_suffix(&target_dir, cwd.join(output_parent)))
                            .context("Failed to create an output directory")?;
                    }

                    trace!("performing compile");
                    // Bubblewrap notes:
                    // - We're running as uid 0 (to do the mounts above), and so bubblewrap is run as uid 0
                    // - There's special handling in bubblewrap to compare uid and euid - of interest to us,
                    //   if uid == euid == 0, bubblewrap preserves capabilities (not good!) so we explicitly
                    //   drop all capabilities
                    // - By entering a new user namespace means any set of capabilities do not apply to any
                    //   other user namespace, i.e. you lose privileges. This is not strictly necessary because
                    //   we're dropping caps anyway so it's irrelevant which namespace we're in, but it doesn't
                    //   hurt.
                    // - --unshare-all is not ideal as it happily continues if it fails to unshare either
                    //   the user or cgroups namespace, so we list everything explicitly
                    // - The order of bind vs proc + dev is important - the new root must be put in place
                    //   first, otherwise proc and dev get hidden
                    let mut cmd = Command::new(bubblewrap);
                    cmd.arg("--die-with-parent")
                        .args(["--cap-drop", "ALL"])
                        .args([
                            "--unshare-user",
                            "--unshare-cgroup",
                            "--unshare-ipc",
                            "--unshare-pid",
                            "--unshare-net",
                            "--unshare-uts",
                        ])
                        .arg("--bind")
                        .arg(&target_dir)
                        .arg("/")
                        .args(["--proc", "/proc"])
                        .args(["--dev", "/dev"])
                        .arg("--chdir")
                        .arg(cwd);

                    for (k, v) in env_vars {
                        if k.contains('=') {
                            warn!("Skipping environment variable: {:?}", k);
                            continue;
                        }
                        cmd.arg("--setenv").arg(k).arg(v);
                    }
                    cmd.arg("--");
                    cmd.arg(executable);
                    cmd.args(arguments);
                    let compile_output = cmd
                        .output()
                        .context("Failed to retrieve output from compile")?;
                    trace!("compile_output: {:?}", compile_output);

                    let mut outputs = vec![];
                    trace!("retrieving {:?}", output_paths);
                    for path in output_paths {
                        let abspath = join_suffix(&target_dir, cwd.join(&path)); // Resolve in case it's relative since we copy it from the root level
                        match fs::File::open(abspath) {
                            Ok(file) => {
                                let output = OutputData::try_from_reader(file)
                                    .context("Failed to read output file")?;
                                outputs.push((path, output));
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::NotFound {
                                    debug!("Missing output path {:?}", path);
                                } else {
                                    return Err(
                                        Error::from(e).context("Failed to open output file")
                                    );
                                }
                            }
                        }
                    }
                    let compile_output = ProcessOutput::try_from(compile_output)
                        .context("Failed to convert compilation exit status")?;
                    Ok(BuildResult {
                        output: compile_output,
                        outputs,
                    })
                    // Bizarrely there's no way to actually get any information from a thread::Result::Err
                })
                .join()
                .unwrap_or_else(|_e| Err(anyhow!("Build thread exited unsuccessfully")))
        })
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_overlay(&self, _tc: &Toolchain, overlay: OverlaySpec) {
        // TODO: collect toolchain directories

        let OverlaySpec {
            build_dir,
            toolchain_dir: _,
        } = overlay;
        if let Err(e) = fs::remove_dir_all(&build_dir) {
            error!(
                "Failed to remove build directory {}: {}",
                build_dir.display(),
                e
            );
        }
    }
}

impl BuilderIncoming for OverlayBuilder {
    fn run_build(
        &self,
        tc: Toolchain,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
        tccache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        debug!("Preparing overlay");
        let overlay = self
            .prepare_overlay_dirs(&tc, tccache)
            .context("failed to prepare overlay dirs")?;
        debug!("Performing build in {:?}", overlay);
        let res = Self::perform_build(&self.bubblewrap, command, inputs_rdr, outputs, &overlay);
        debug!("Finishing with overlay");
        self.finish_overlay(&tc, overlay);
        debug!("Returning result");
        res.context("Compilation execution failed")
    }
}

const BASE_DOCKER_IMAGE: &str = "aidanhs/busybox";
// Make sure sh doesn't exec the final command, since we need it to do
// init duties (reaping zombies). Also, because we kill -9 -1, that kills
// the sleep (it's not a builtin) so it needs to be a loop.
const DOCKER_SHELL_INIT: &str = "while true; do /busybox sleep 365d && /busybox true; done";

// Check the diff and clean up the FS
fn docker_diff(cid: &str) -> Result<String> {
    Command::new("docker")
        .args(["diff", cid])
        .check_stdout_trim()
        .context("Failed to Docker diff container")
}

// Force remove the container
fn docker_rm(cid: &str) -> Result<()> {
    Command::new("docker")
        .args(["rm", "-f", cid])
        .check_run()
        .context("Failed to force delete container")
}

pub struct DockerBuilder {
    image_map: Mutex<HashMap<Toolchain, String>>,
    container_lists: Mutex<HashMap<Toolchain, Vec<String>>>,
}

impl DockerBuilder {
    // TODO: this should accept a unique string, e.g. inode of the tccache directory
    // having locked a pidfile, or at minimum should loudly detect other running
    // instances - pidfile in /tmp
    pub fn new() -> Result<Self> {
        info!("Creating docker builder");

        let ret = Self {
            image_map: Mutex::new(HashMap::new()),
            container_lists: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        Ok(ret)
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup(&self) -> Result<()> {
        info!("Performing initial Docker cleanup");

        let containers = Command::new("docker")
            .args(["ps", "-a", "--format", "{{.ID}} {{.Image}}"])
            .check_stdout_trim()
            .context("Unable to list all Docker containers")?;
        if !containers.is_empty() {
            let mut containers_to_rm = vec![];
            for line in containers.split('\n') {
                let mut iter = line.splitn(2, ' ');
                let container_id = iter
                    .next()
                    .context("Malformed container listing - no container ID")?;
                let image_name = iter
                    .next()
                    .context("Malformed container listing - no image name")?;
                if iter.next().is_some() {
                    bail!("Malformed container listing - third field on row")
                }
                if image_name.starts_with("sccache-builder-") {
                    containers_to_rm.push(container_id);
                }
            }
            if !containers_to_rm.is_empty() {
                Command::new("docker")
                    .args(["rm", "-f"])
                    .args(containers_to_rm)
                    .check_run()
                    .context("Failed to start command to remove old containers")?;
            }
        }

        let images = Command::new("docker")
            .args(["images", "--format", "{{.ID}} {{.Repository}}"])
            .check_stdout_trim()
            .context("Failed to list all docker images")?;
        if !images.is_empty() {
            let mut images_to_rm = vec![];
            for line in images.split('\n') {
                let mut iter = line.splitn(2, ' ');
                let image_id = iter
                    .next()
                    .context("Malformed image listing - no image ID")?;
                let image_name = iter
                    .next()
                    .context("Malformed image listing - no image name")?;
                if iter.next().is_some() {
                    bail!("Malformed image listing - third field on row")
                }
                if image_name.starts_with("sccache-builder-") {
                    images_to_rm.push(image_id);
                }
            }
            if !images_to_rm.is_empty() {
                Command::new("docker")
                    .args(["rmi"])
                    .args(images_to_rm)
                    .check_run()
                    .context("Failed to remove image")?;
            }
        }

        info!("Completed initial Docker cleanup");
        Ok(())
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Docker image along
    // the way)
    fn get_container(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let container = {
            let mut map = self.container_lists.lock().unwrap();
            map.entry(tc.clone()).or_default().pop()
        };
        match container {
            Some(cid) => Ok(cid),
            None => {
                // TODO: can improve parallelism (of creating multiple images at a time) by using another
                // (more fine-grained) mutex around the entry value and checking if its empty a second time
                let image = {
                    let mut map = self.image_map.lock().unwrap();
                    match map.entry(tc.clone()) {
                        hash_map::Entry::Occupied(e) => e.get().clone(),
                        hash_map::Entry::Vacant(e) => {
                            info!("Creating Docker image for {:?} (may block requests)", tc);
                            let image = Self::make_image(tc, tccache)?;
                            e.insert(image.clone());
                            image
                        }
                    }
                };
                Self::start_container(&image)
            }
        }
    }

    fn clean_container(&self, cid: &str) -> Result<()> {
        // Clean up any running processes
        Command::new("docker")
            .args(["exec", cid, "/busybox", "kill", "-9", "-1"])
            .check_run()
            .context("Failed to run kill on all processes in container")?;

        let diff = docker_diff(cid)?;
        if !diff.is_empty() {
            let mut lastpath = None;
            for line in diff.split('\n') {
                let mut iter = line.splitn(2, ' ');
                let changetype = iter
                    .next()
                    .context("Malformed container diff - no change type")?;
                let changepath = iter
                    .next()
                    .context("Malformed container diff - no change path")?;
                if iter.next().is_some() {
                    bail!("Malformed container diff - third field on row")
                }
                // TODO: If files are created in this dir, it gets marked as modified.
                // A similar thing applies to /root or /build etc
                if changepath == "/tmp" {
                    continue;
                }
                if changetype != "A" {
                    bail!(
                        "Path {} had a non-A changetype of {}",
                        changepath,
                        changetype
                    );
                }
                // Docker diff paths are in alphabetical order and we do `rm -rf`, so we might be able to skip
                // calling Docker more than necessary (since it's slow)
                if let Some(lastpath) = lastpath {
                    if Path::new(changepath).starts_with(lastpath) {
                        continue;
                    }
                }
                lastpath = Some(changepath);
                if let Err(e) = Command::new("docker")
                    .args(["exec", cid, "/busybox", "rm", "-rf", changepath])
                    .check_run()
                {
                    // We do a final check anyway, so just continue
                    warn!("Failed to remove added path in a container: {}", e);
                }
            }

            let newdiff = docker_diff(cid)?;
            // See note about changepath == "/tmp" above
            if !newdiff.is_empty() && newdiff != "C /tmp" {
                bail!(
                    "Attempted to delete files, but container still has a diff: {:?}",
                    newdiff
                );
            }
        }

        Ok(())
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_container(&self, tc: &Toolchain, cid: String) {
        // TODO: collect images

        if let Err(e) = self.clean_container(&cid) {
            info!("Failed to clean container {}: {}", cid, e);
            if let Err(e) = docker_rm(&cid) {
                warn!(
                    "Failed to remove container {} after failed clean: {}",
                    cid, e
                );
            }
            return;
        }

        // Good as new, add it back to the container list
        if let Some(entry) = self.container_lists.lock().unwrap().get_mut(tc) {
            debug!("Reclaimed container {}", cid);
            entry.push(cid);
        } else {
            warn!(
                "Was ready to reclaim container {} but toolchain went missing",
                cid
            );
            if let Err(e) = docker_rm(&cid) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
    }

    fn make_image(tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let cid = Command::new("docker")
            .args(["create", BASE_DOCKER_IMAGE, "/busybox", "true"])
            .check_stdout_trim()
            .context("Failed to create docker container")?;

        let mut tccache = tccache.lock().unwrap();
        let mut toolchain_rdr = match tccache.get(tc) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => bail!(
                "Expected to find toolchain {}, but not available",
                tc.archive_id
            ),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("Failed to use toolchain {}", tc.archive_id));
            }
        };

        trace!("Copying in toolchain");
        Command::new("docker")
            .args(["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| {
                io::copy(&mut toolchain_rdr, stdin)?;
                Ok(())
            })
            .context("Failed to copy toolchain tar into container")?;
        drop(toolchain_rdr);

        let imagename = format!("sccache-builder-{}", &tc.archive_id);
        Command::new("docker")
            .args(["commit", &cid, &imagename])
            .check_run()
            .context("Failed to commit container after build")?;

        Command::new("docker")
            .args(["rm", "-f", &cid])
            .check_run()
            .context("Failed to remove temporary build container")?;

        Ok(imagename)
    }

    fn start_container(image: &str) -> Result<String> {
        Command::new("docker")
            .args([
                "run",
                "-d",
                image,
                "/busybox",
                "sh",
                "-c",
                DOCKER_SHELL_INIT,
            ])
            .check_stdout_trim()
            .context("Failed to run container")
    }

    fn perform_build(
        compile_command: CompileCommand,
        mut inputs_rdr: InputsReader,
        output_paths: Vec<String>,
        cid: &str,
    ) -> Result<BuildResult> {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable, compile_command.arguments
        );

        trace!("copying in inputs");
        Command::new("docker")
            .args(["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| {
                io::copy(&mut inputs_rdr, stdin)?;
                Ok(())
            })
            .context("Failed to copy inputs tar into container")?;
        drop(inputs_rdr);

        let CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(["exec", cid, "/busybox", "mkdir", "-p"]).arg(cwd);
        for path in output_paths.iter() {
            // If it doesn't have a parent, nothing needs creating
            let output_parent = if let Some(p) = Path::new(path).parent() {
                p
            } else {
                continue;
            };
            cmd.arg(cwd.join(output_parent));
        }
        cmd.check_run()
            .context("Failed to create directories required for compile in container")?;

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in env_vars {
            if k.contains('=') {
                warn!("Skipping environment variable: {:?}", k);
                continue;
            }
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = "cd \"$1\" && shift && exec \"$@\"";
        cmd.args([cid, "/busybox", "sh", "-c", shell_cmd]);
        cmd.arg(&executable);
        cmd.arg(cwd);
        cmd.arg(executable);
        cmd.args(arguments);
        let compile_output = cmd.output().context("Failed to start executing compile")?;
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let abspath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker")
                .args(["exec", cid, "/busybox", "cat"])
                .arg(abspath)
                .output()
                .context("Failed to start command to retrieve output file")?;
            if output.status.success() {
                let output = OutputData::try_from_reader(&*output.stdout)
                    .expect("Failed to read compress output stdout");
                outputs.push((path, output));
            } else {
                debug!("Missing output path {:?}", path);
            }
        }

        let compile_output = ProcessOutput::try_from(compile_output)
            .context("Failed to convert compilation exit status")?;
        Ok(BuildResult {
            output: compile_output,
            outputs,
        })
    }
}

impl BuilderIncoming for DockerBuilder {
    // From Server
    fn run_build(
        &self,
        tc: Toolchain,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
        tccache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        debug!("Finding container");
        let cid = self
            .get_container(&tc, tccache)
            .context("Failed to get a container for build")?;
        debug!("Performing build with container {}", cid);
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid)
            .context("Failed to perform build")?;
        debug!("Finishing with container {}", cid);
        self.finish_container(&tc, cid);
        debug!("Returning result");
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tc(id: &str) -> Toolchain {
        Toolchain {
            archive_id: id.to_owned(),
        }
    }

    // Two requests for the same uncached toolchain must serialize on one
    // preparation lock (so the gzip+untar happens once, with no half-written
    // dir), while requests for different toolchains get independent locks and
    // never block each other. Constructing an OverlayBuilder requires root, so
    // drive the lock-acquisition invariant that prepare_overlay_dirs relies on
    // directly.
    #[test]
    fn test_prepare_lock_shared_per_key_and_distinct_across_keys() {
        let locks = Mutex::new(HashMap::new());

        let a1 = get_prepare_lock(&locks, &tc("aaaa"));
        let a2 = get_prepare_lock(&locks, &tc("aaaa"));
        let b = get_prepare_lock(&locks, &tc("bbbb"));

        assert!(
            Arc::ptr_eq(&a1, &a2),
            "same toolchain key must share one preparation lock"
        );
        assert!(
            !Arc::ptr_eq(&a1, &b),
            "different toolchain keys must get distinct preparation locks"
        );

        // The shared lock actually serializes: while a1 is held, a second
        // acquire of the same Arc blocks, but a different toolchain's lock is
        // free to take.
        let guard = a1.lock().unwrap();
        assert!(
            a2.try_lock().is_err(),
            "second acquire of the shared preparation lock must block"
        );
        assert!(
            b.try_lock().is_ok(),
            "a different toolchain's preparation lock must not block"
        );
        drop(guard);
    }

    // The eviction path in prepare_overlay_dirs deletes a victim only after a
    // try_lock on the victim's preparation lock succeeds. Constructing an
    // OverlayBuilder requires root, so drive the try_lock invariant the eviction
    // loop relies on directly: while a victim is being prepared (its lock held),
    // try_lock must fail so the victim is skipped; once released, try_lock must
    // succeed so the stale directory can be removed.
    #[test]
    fn test_eviction_skips_victim_while_being_prepared() {
        let locks = Mutex::new(HashMap::new());
        let victim = tc("cccc");

        let prepare_lock = get_prepare_lock(&locks, &victim);
        let held = prepare_lock.lock().unwrap();

        let eviction_view = get_prepare_lock(&locks, &victim);
        assert!(
            eviction_view.try_lock().is_err(),
            "a victim under active preparation must not be evicted"
        );

        drop(held);
        assert!(
            eviction_view.try_lock().is_ok(),
            "once preparation finishes the victim is free to evict"
        );
    }
}
