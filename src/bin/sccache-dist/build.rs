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

use flate2::read::GzDecoder;
use libmount::Overlay;
use lru_disk_cache::Error as LruError;
use sccache::dist::{
    BuildResult, CompileCommand, InputsReader, OutputData, ProcessOutput, TcCache, Toolchain,
    BuilderIncoming,
};
use std::collections::{HashMap, hash_map};
use std::fs;
use std::io;
use std::iter;
use std::path::{self, Path, PathBuf};
use std::process::{ChildStdin, Command, Output, Stdio};
use std::sync::{Mutex};

use crate::errors::*;

trait CommandExt {
    fn check_stdout_trim(&mut self) -> Result<String>;
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()>;
    fn check_run(&mut self) -> Result<()>;
}

impl CommandExt for Command {
    fn check_stdout_trim(&mut self) -> Result<String> {
        let output = self.output().chain_err(|| "Failed to start command")?;
        check_output(&output)?;
        let stdout = String::from_utf8(output.stdout).chain_err(|| "Output from listing containers not UTF8")?;
        Ok(stdout.trim().to_owned())
    }
    // Should really take a FnOnce/FnBox
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()> {
        let mut process = self.stdin(Stdio::piped()).spawn().chain_err(|| "Failed to start command")?;
        let mut stdin = process.stdin.take().expect("Requested piped stdin but not present");
        pipe(&mut stdin).chain_err(|| "Failed to pipe input to process")?;
        let output = process.wait_with_output().chain_err(|| "Failed to wait for process to return")?;
        check_output(&output)
    }
    fn check_run(&mut self) -> Result<()> {
        let output = self.output().chain_err(|| "Failed to start command")?;
        check_output(&output)
    }
}

fn check_output(output: &Output) -> Result<()> {
    if !output.status.success() {
        warn!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
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

pub struct OverlayBuilder {
    bubblewrap: PathBuf,
    dir: PathBuf,
    toolchain_dir_map: Mutex<HashMap<Toolchain, (PathBuf, u64)>>, // toolchain_dir, num_builds
}

impl OverlayBuilder {
    pub fn new(bubblewrap: PathBuf, dir: PathBuf) -> Result<Self> {
        info!("Creating overlay builder");

        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            // Not root, or a setuid binary - haven't put enough thought into supporting this, bail
            bail!("not running as root")
        }

        // TODO: pidfile
        let ret = Self {
            bubblewrap,
            dir,
            toolchain_dir_map: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        fs::create_dir(&ret.dir).chain_err(|| "Failed to create base directory for builder")?;
        fs::create_dir(ret.dir.join("builds")).chain_err(|| "Failed to create builder builds directory")?;
        fs::create_dir(ret.dir.join("toolchains")).chain_err(|| "Failed to create builder toolchains directory")?;
        Ok(ret)
    }

    fn cleanup(&self) -> Result<()> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).chain_err(|| "Failed to clean up builder directory")?
        }
        Ok(())
    }

    fn prepare_overlay_dirs(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<OverlaySpec> {
        let (toolchain_dir, id) = {
            let mut toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
            // Create the toolchain dir (if necessary) while we have an exclusive lock
            if toolchain_dir_map.contains_key(tc) {
                // TODO: use if let when sccache can use NLL
                let entry = toolchain_dir_map.get_mut(tc).expect("Key missing after checking");
                entry.1 += 1;
                entry.clone()
            } else {
                trace!("Creating toolchain directory for {}", tc.archive_id);
                let toolchain_dir = self.dir.join("toolchains").join(&tc.archive_id);
                fs::create_dir(&toolchain_dir)?;

                let mut tccache = tccache.lock().unwrap();
                let toolchain_rdr = match tccache.get(tc) {
                    Ok(rdr) => rdr,
                    Err(LruError::FileNotInCache) => bail!("expected toolchain {}, but not available", tc.archive_id),
                    Err(e) => return Err(Error::from(e).chain_err(|| "failed to get toolchain from cache")),
                };
                tar::Archive::new(GzDecoder::new(toolchain_rdr)).unpack(&toolchain_dir)?;

                let entry = (toolchain_dir, 1);
                assert!(toolchain_dir_map.insert(tc.clone(), entry.clone()).is_none());
                entry
            }
        };

        trace!("Creating build directory for {}-{}", tc.archive_id, id);
        let build_dir = self.dir.join("builds").join(format!("{}-{}", tc.archive_id, id));
        fs::create_dir(&build_dir)?;
        Ok(OverlaySpec { build_dir, toolchain_dir })
    }

    fn perform_build(bubblewrap: &Path, compile_command: CompileCommand, inputs_rdr: InputsReader, output_paths: Vec<String>, overlay: &OverlaySpec) -> Result<BuildResult> {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        crossbeam_utils::thread::scope(|scope| { scope.spawn(|| {

            // Now mounted filesystems will be automatically unmounted when this thread dies
            // (and tmpfs filesystems will be completely destroyed)
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
                .chain_err(|| "Failed to enter a new Linux namespace")?;
            // Make sure that all future mount changes are private to this namespace
            // TODO: shouldn't need to add these annotations
            let source: Option<&str> = None;
            let fstype: Option<&str> = None;
            let data: Option<&str> = None;
            // Turn / into a 'slave', so it receives mounts from real root, but doesn't propogate back
            nix::mount::mount(source, "/", fstype, nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE, data)
                .chain_err(|| "Failed to turn / into a slave")?;

            let work_dir = overlay.build_dir.join("work");
            let upper_dir = overlay.build_dir.join("upper");
            let target_dir = overlay.build_dir.join("target");
            fs::create_dir(&work_dir).chain_err(|| "Failed to create overlay work directory")?;
            fs::create_dir(&upper_dir).chain_err(|| "Failed to create overlay upper directory")?;
            fs::create_dir(&target_dir).chain_err(|| "Failed to create overlay target directory")?;

            let () = Overlay::writable(
                iter::once(overlay.toolchain_dir.as_path()),
                upper_dir,
                work_dir,
                &target_dir,
            // This error is unfortunately not Send
            ).mount().map_err(|e| Error::from(e.to_string())).chain_err(|| "Failed to mount overlay FS")?;

            trace!("copying in inputs");
            // Note that we don't unpack directly into the upperdir since there overlayfs has some
            // special marker files that we don't want to create by accident (or malicious intent)
            tar::Archive::new(inputs_rdr).unpack(&target_dir).chain_err(|| "Failed to unpack inputs to overlay")?;

            let CompileCommand { executable, arguments, env_vars, cwd } = compile_command;
            let cwd = Path::new(&cwd);

            trace!("creating output directories");
            fs::create_dir_all(join_suffix(&target_dir, cwd)).chain_err(|| "Failed to create cwd")?;
            for path in output_paths.iter() {
                // If it doesn't have a parent, nothing needs creating
                let output_parent = if let Some(p) = Path::new(path).parent() { p } else { continue };
                fs::create_dir_all(join_suffix(&target_dir, cwd.join(output_parent)))
                    .chain_err(|| "Failed to create an output directory")?;
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
            cmd
                .arg("--die-with-parent")
                .args(&["--cap-drop", "ALL"])
                .args(&[
                    "--unshare-user", "--unshare-cgroup", "--unshare-ipc",
                    "--unshare-pid", "--unshare-net", "--unshare-uts",
                ])
                .arg("--bind").arg(&target_dir).arg("/")
                .args(&["--proc", "/proc"])
                .args(&["--dev", "/dev"])
                .arg("--chdir").arg(cwd);

            for (k, v) in env_vars {
                if k.contains('=') {
                    warn!("Skipping environment variable: {:?}", k);
                    continue
                }
                cmd.arg("--setenv").arg(k).arg(v);
            }
            cmd.arg("--");
            cmd.arg(executable);
            cmd.args(arguments);
            let compile_output = cmd.output().chain_err(|| "Failed to retrieve output from compile")?;
            trace!("compile_output: {:?}", compile_output);

            let mut outputs = vec![];
            trace!("retrieving {:?}", output_paths);
            for path in output_paths {
                let abspath = join_suffix(&target_dir, cwd.join(&path)); // Resolve in case it's relative since we copy it from the root level
                match fs::File::open(abspath) {
                    Ok(file) => {
                        let output = OutputData::try_from_reader(file)
                            .chain_err(|| "Failed to read output file")?;
                        outputs.push((path, output))
                    },
                    Err(e) => {
                        if e.kind() == io::ErrorKind::NotFound {
                            debug!("Missing output path {:?}", path)
                        } else {
                            return Err(Error::from(e).chain_err(|| "Failed to open output file"))
                        }
                    },
                }
            }
            let compile_output = ProcessOutput::try_from(compile_output)
                .chain_err(|| "Failed to convert compilation exit status")?;
            Ok(BuildResult { output: compile_output, outputs })

        // Bizarrely there's no way to actually get any information from a thread::Result::Err
        }).join().unwrap_or_else(|_e| Err(Error::from("Build thread exited unsuccessfully"))) })
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_overlay(&self, _tc: &Toolchain, overlay: OverlaySpec) {
        // TODO: collect toolchain directories

        let OverlaySpec { build_dir, .. } = overlay;
        if let Err(e) = fs::remove_dir_all(&build_dir) {
            error!("Failed to remove build directory {}: {}", build_dir.display(), e);
        }
    }
}

impl BuilderIncoming for OverlayBuilder {
    type Error = Error;
    fn run_build(&self, tc: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, tccache: &Mutex<TcCache>) -> Result<BuildResult> {
        debug!("Preparing overlay");
        let overlay = self.prepare_overlay_dirs(&tc, tccache).chain_err(|| "failed to prepare overlay dirs")?;
        debug!("Performing build in {:?}", overlay);
        let res = Self::perform_build(&self.bubblewrap, command, inputs_rdr, outputs, &overlay);
        debug!("Finishing with overlay");
        self.finish_overlay(&tc, overlay);
        debug!("Returning result");
        res.chain_err(|| "Compilation execution failed")
    }
}

const BASE_DOCKER_IMAGE: &str = "aidanhs/busybox";
// Make sure sh doesn't exec the final command, since we need it to do
// init duties (reaping zombies). Also, because we kill -9 -1, that kills
// the sleep (it's not a builtin) so it needs to be a loop.
const DOCKER_SHELL_INIT: &str = "while true; do /busybox sleep 365d && /busybox true; done";

// Check the diff and clean up the FS
fn docker_diff(cid: &str) -> Result<String> {
    Command::new("docker").args(&["diff", cid]).check_stdout_trim()
        .chain_err(|| "Failed to Docker diff container")
}

// Force remove the container
fn docker_rm(cid: &str) -> Result<()> {
    Command::new("docker").args(&["rm", "-f", &cid]).check_run()
        .chain_err(|| "Failed to force delete container")
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

        let containers = Command::new("docker").args(&["ps", "-a", "--format", "{{.ID}} {{.Image}}"]).check_stdout_trim()
            .chain_err(|| "Unable to list all Docker containers")?;
        if containers != "" {
            let mut containers_to_rm = vec![];
            for line in containers.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let container_id = iter.next().ok_or_else(|| Error::from("Malformed container listing - no container ID"))?;
                let image_name = iter.next().ok_or_else(|| Error::from("Malformed container listing - no image name"))?;
                if iter.next() != None { bail!("Malformed container listing - third field on row") }
                if image_name.starts_with("sccache-builder-") {
                    containers_to_rm.push(container_id)
                }
            }
            if !containers_to_rm.is_empty() {
                Command::new("docker").args(&["rm", "-f"]).args(containers_to_rm).check_run()
                    .chain_err(|| "Failed to start command to remove old containers")?;
            }
        }

        let images = Command::new("docker").args(&["images", "--format", "{{.ID}} {{.Repository}}"]).check_stdout_trim()
            .chain_err(|| "Failed to list all docker images")?;
        if images != "" {
            let mut images_to_rm = vec![];
            for line in images.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let image_id = iter.next().ok_or_else(|| Error::from("Malformed image listing - no image ID"))?;
                let image_name = iter.next().ok_or_else(|| Error::from("Malformed image listing - no image name"))?;
                if iter.next() != None { bail!("Malformed image listing - third field on row") }
                if image_name.starts_with("sccache-builder-") {
                    images_to_rm.push(image_id)
                }
            }
            if !images_to_rm.is_empty() {
                Command::new("docker").args(&["rmi"]).args(images_to_rm).check_run()
                    .chain_err(|| "Failed to remove image")?
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
            map.entry(tc.clone()).or_insert_with(Vec::new).pop()
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
                        },
                    }
                };
                Self::start_container(&image)
            },
        }
    }

    fn clean_container(&self, cid: &str) -> Result<()> {
        // Clean up any running processes
        Command::new("docker").args(&["exec", &cid, "/busybox", "kill", "-9", "-1"]).check_run()
            .chain_err(|| "Failed to run kill on all processes in container")?;

        let diff = docker_diff(&cid)?;
        if diff != "" {
            let mut lastpath = None;
            for line in diff.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let changetype = iter.next().ok_or_else(|| Error::from("Malformed container diff - no change type"))?;
                let changepath = iter.next().ok_or_else(|| Error::from("Malformed container diff - no change path"))?;
                if iter.next() != None { bail!("Malformed container diff - third field on row") }
                // TODO: If files are created in this dir, it gets marked as modified.
                // A similar thing applies to /root or /build etc
                if changepath == "/tmp" {
                    continue
                }
                if changetype != "A" {
                    bail!("Path {} had a non-A changetype of {}", changepath, changetype);
                }
                // Docker diff paths are in alphabetical order and we do `rm -rf`, so we might be able to skip
                // calling Docker more than necessary (since it's slow)
                if let Some(lastpath) = lastpath {
                    if Path::new(changepath).starts_with(lastpath) {
                        continue
                    }
                }
                lastpath = Some(changepath.clone());
                if let Err(e) = Command::new("docker").args(&["exec", &cid, "/busybox", "rm", "-rf", changepath]).check_run() {
                    // We do a final check anyway, so just continue
                    warn!("Failed to remove added path in a container: {}", e)
                }
            }

            let newdiff = docker_diff(&cid)?;
            // See note about changepath == "/tmp" above
            if newdiff != "" && newdiff != "C /tmp" {
                bail!("Attempted to delete files, but container still has a diff: {:?}", newdiff);
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
                warn!("Failed to remove container {} after failed clean: {}", cid, e);
            }
            return
        }

        // Good as new, add it back to the container list
        if let Some(entry) = self.container_lists.lock().unwrap().get_mut(tc) {
            debug!("Reclaimed container {}", cid);
            entry.push(cid)
        } else {
            warn!("Was ready to reclaim container {} but toolchain went missing", cid);
            if let Err(e) = docker_rm(&cid) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
    }

    fn make_image(tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let cid = Command::new("docker").args(&["create", BASE_DOCKER_IMAGE, "/busybox", "true"]).check_stdout_trim()
            .chain_err(|| "Failed to create docker container")?;

        let mut tccache = tccache.lock().unwrap();
        let mut toolchain_rdr = match tccache.get(tc) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => bail!("Expected to find toolchain {}, but not available", tc.archive_id),
            Err(e) => return Err(Error::from(e).chain_err(|| format!("Failed to use toolchain {}", tc.archive_id))),
        };

        trace!("Copying in toolchain");
        Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| { io::copy(&mut toolchain_rdr, stdin)?; Ok(()) })
            .chain_err(|| "Failed to copy toolchain tar into container")?;
        drop(toolchain_rdr);

        let imagename = format!("sccache-builder-{}", &tc.archive_id);
        Command::new("docker").args(&["commit", &cid, &imagename]).check_run()
            .chain_err(|| "Failed to commit container after build")?;

        Command::new("docker").args(&["rm", "-f", &cid]).check_run()
            .chain_err(|| "Failed to remove temporary build container")?;

        Ok(imagename)
    }

    fn start_container(image: &str) -> Result<String> {
        Command::new("docker").args(&["run", "-d", image, "/busybox", "sh", "-c", DOCKER_SHELL_INIT]).check_stdout_trim()
            .chain_err(|| "Failed to run container")
    }

    fn perform_build(compile_command: CompileCommand, mut inputs_rdr: InputsReader, output_paths: Vec<String>, cid: &str) -> Result<BuildResult> {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        trace!("copying in inputs");
        Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| { io::copy(&mut inputs_rdr, stdin)?; Ok(()) })
            .chain_err(|| "Failed to copy inputs tar into container")?;
        drop(inputs_rdr);

        let CompileCommand { executable, arguments, env_vars, cwd } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", cid, "/busybox", "mkdir", "-p"]).arg(cwd);
        for path in output_paths.iter() {
            // If it doesn't have a parent, nothing needs creating
            let output_parent = if let Some(p) = Path::new(path).parent() { p } else { continue };
            cmd.arg(cwd.join(output_parent));
        }
        cmd.check_run()
            .chain_err(|| "Failed to create directories required for compile in container")?;

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in env_vars {
            if k.contains('=') {
                warn!("Skipping environment variable: {:?}", k);
                continue
            }
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = "cd \"$1\" && shift && exec \"$@\"".to_string();
        cmd.args(&[cid, "/busybox", "sh", "-c", &shell_cmd]);
        cmd.arg(&executable);
        cmd.arg(cwd);
        cmd.arg(executable);
        cmd.args(arguments);
        let compile_output = cmd.output().chain_err(|| "Failed to start executing compile")?;
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let abspath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker").args(&["exec", cid, "/busybox", "cat"]).arg(abspath).output()
                .chain_err(|| "Failed to start command to retrieve output file")?;
            if output.status.success() {
                let output = OutputData::try_from_reader(&*output.stdout)
                    .expect("Failed to read compress output stdout");
                outputs.push((path, output))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        let compile_output = ProcessOutput::try_from(compile_output)
            .chain_err(|| "Failed to convert compilation exit status")?;
        Ok(BuildResult { output: compile_output, outputs })
    }
}

impl BuilderIncoming for DockerBuilder {
    type Error = Error;
    // From Server
    fn run_build(&self, tc: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, tccache: &Mutex<TcCache>) -> Result<BuildResult> {
        debug!("Finding container");
        let cid = self.get_container(&tc, tccache)
            .chain_err(|| "Failed to get a container for build")?;
        debug!("Performing build with container {}", cid);
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid)
            .chain_err(|| "Failed to perform build")?;
        debug!("Finishing with container {}", cid);
        self.finish_container(&tc, cid);
        debug!("Returning result");
        Ok(res)
    }
}
