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

use crossbeam_utils;
use flate2::read::GzDecoder;
use libmount::Overlay;
use lru_disk_cache::Error as LruError;
use nix;
use sccache::dist::{
    BuildResult, CompileCommand, InputsReader, OutputData, TcCache, Toolchain,
    BuilderIncoming,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::iter;
use std::path::{self, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex};
use tar;

use errors::*;

fn check_output(output: &Output) {
    if !output.status.success() {
        error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
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
        ret.cleanup();
        fs::create_dir(&ret.dir).unwrap();
        fs::create_dir(ret.dir.join("builds")).unwrap();
        fs::create_dir(ret.dir.join("toolchains")).unwrap();
        Ok(ret)
    }

    fn cleanup(&self) {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).unwrap()
        }
    }

    fn prepare_overlay_dirs(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<OverlaySpec> {
        let (toolchain_dir, id) = {
            let mut toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
            // Create the toolchain dir (if necessary) while we have an exclusive lock
            if !toolchain_dir_map.contains_key(tc) {
                trace!("Creating toolchain directory for {}", tc.archive_id);
                let toolchain_dir = self.dir.join("toolchains").join(&tc.archive_id);
                fs::create_dir(&toolchain_dir)?;

                let mut tccache = tccache.lock().unwrap();
                let toolchain_rdr = match tccache.get(tc) {
                    Ok(rdr) => rdr,
                    Err(LruError::FileNotInCache) => bail!("expected toolchain {}, but not available", tc.archive_id),
                    Err(e) => return Err(Error::with_chain(e, "failed to get toolchain from cache")),
                };
                tar::Archive::new(GzDecoder::new(toolchain_rdr)).unpack(&toolchain_dir)?;
                assert!(toolchain_dir_map.insert(tc.clone(), (toolchain_dir, 0)).is_none())
            }
            let entry = toolchain_dir_map.get_mut(tc).unwrap();
            entry.1 += 1;
            entry.clone()
        };

        trace!("Creating build directory for {}-{}", tc.archive_id, id);
        let build_dir = self.dir.join("builds").join(format!("{}-{}", tc.archive_id, id));
        fs::create_dir(&build_dir)?;
        Ok(OverlaySpec { build_dir, toolchain_dir })
    }

    fn perform_build(bubblewrap: &Path, compile_command: CompileCommand, inputs_rdr: InputsReader, output_paths: Vec<String>, overlay: &OverlaySpec) -> BuildResult {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        crossbeam_utils::thread::scope(|scope| { scope.spawn(|| {

            // Now mounted filesystems will be automatically unmounted when this thread dies
            // (and tmpfs filesystems will be completely destroyed)
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
            // Make sure that all future mount changes are private to this namespace
            // TODO: shouldn't need to add these annotations
            let source: Option<&str> = None;
            let fstype: Option<&str> = None;
            let data: Option<&str> = None;
            nix::mount::mount(source, "/", fstype, nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE, data).unwrap();

            let work_dir = overlay.build_dir.join("work");
            let upper_dir = overlay.build_dir.join("upper");
            let target_dir = overlay.build_dir.join("target");
            fs::create_dir(&work_dir).unwrap();
            fs::create_dir(&upper_dir).unwrap();
            fs::create_dir(&target_dir).unwrap();

            let () = Overlay::writable(
                iter::once(overlay.toolchain_dir.as_path()),
                upper_dir,
                work_dir,
                &target_dir,
            ).mount().unwrap();

            trace!("copying in inputs");
            // Note that we don't unpack directly into the upperdir since there overlayfs has some
            // special marker files that we don't want to create by accident (or malicious intent)
            tar::Archive::new(inputs_rdr).unpack(&target_dir).unwrap();

            let CompileCommand { executable, arguments, env_vars, cwd } = compile_command;
            let cwd = Path::new(&cwd);

            trace!("creating output directories");
            fs::create_dir_all(join_suffix(&target_dir, cwd)).unwrap();
            for path in output_paths.iter() {
                fs::create_dir_all(join_suffix(&target_dir, cwd.join(Path::new(path).parent().unwrap()))).unwrap();
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
                if k.contains("=") {
                    warn!("Skipping environment variable: {:?}", k);
                    continue
                }
                cmd.arg("--setenv").arg(k).arg(v);
            }
            cmd.arg("--");
            cmd.arg(executable);
            cmd.args(arguments);
            let compile_output = cmd.output().unwrap();
            trace!("compile_output: {:?}", compile_output);

            let mut outputs = vec![];
            trace!("retrieving {:?}", output_paths);
            for path in output_paths {
                let abspath = join_suffix(&target_dir, cwd.join(&path)); // Resolve in case it's relative since we copy it from the root level
                match fs::File::open(abspath) {
                    Ok(mut file) => {
                        let output = OutputData::from_reader(file);
                        outputs.push((path, output))
                    },
                    Err(e) => {
                        if e.kind() == io::ErrorKind::NotFound {
                            debug!("Missing output path {:?}", path)
                        } else {
                            panic!(e)
                        }
                    },
                }
            }
            BuildResult { output: compile_output.into(), outputs }

        }).join().unwrap() })
    }

    fn finish_overlay(&self, _tc: &Toolchain, overlay: OverlaySpec) {
        // TODO: collect toolchain directories

        let OverlaySpec { build_dir, toolchain_dir: _ } = overlay;
        fs::remove_dir_all(build_dir).unwrap();
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
        Ok(res)
    }
}

const BASE_DOCKER_IMAGE: &str = "aidanhs/busybox";

pub struct DockerBuilder {
    image_map: Mutex<HashMap<Toolchain, String>>,
    container_lists: Mutex<HashMap<Toolchain, Vec<String>>>,
}

impl DockerBuilder {
    // TODO: this should accept a unique string, e.g. inode of the tccache directory
    // having locked a pidfile, or at minimum should loudly detect other running
    // instances - pidfile in /tmp
    pub fn new() -> Self {
        info!("Creating docker builder");

        let ret = Self {
            image_map: Mutex::new(HashMap::new()),
            container_lists: Mutex::new(HashMap::new()),
        };
        ret.cleanup();
        ret
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup(&self) {
        info!("Performing initial Docker cleanup");

        let containers = {
            let output = Command::new("docker").args(&["ps", "-a", "--format", "{{.ID}} {{.Image}}"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        if containers != "" {
            let mut containers_to_rm = vec![];
            for line in containers.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let container_id = iter.next().unwrap();
                let image_name = iter.next().unwrap();
                if iter.next() != None { panic!() }
                if image_name.starts_with("sccache-builder-") {
                    containers_to_rm.push(container_id)
                }
            }
            if !containers_to_rm.is_empty() {
                let output = Command::new("docker").args(&["rm", "-f"]).args(containers_to_rm).output().unwrap();
                check_output(&output)
            }
        }

        let images = {
            let output = Command::new("docker").args(&["images", "--format", "{{.ID}} {{.Repository}}"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        if images != "" {
            let mut images_to_rm = vec![];
            for line in images.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let image_id = iter.next().unwrap();
                let image_name = iter.next().unwrap();
                if iter.next() != None { panic!() }
                if image_name.starts_with("sccache-builder-") {
                    images_to_rm.push(image_id)
                }
            }
            if !images_to_rm.is_empty() {
                let output = Command::new("docker").args(&["rmi"]).args(images_to_rm).output().unwrap();
                check_output(&output)
            }
        }

        info!("Completed initial Docker cleanup");
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Docker image along
    // the way)
    fn get_container(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> String {
        let container = {
            let mut map = self.container_lists.lock().unwrap();
            map.entry(tc.clone()).or_insert_with(Vec::new).pop()
        };
        match container {
            Some(cid) => cid,
            None => {
                // TODO: can improve parallelism (of creating multiple images at a time) by using another
                // (more fine-grained) mutex around the entry value and checking if its empty a second time
                let image = {
                    let mut map = self.image_map.lock().unwrap();
                    map.entry(tc.clone()).or_insert_with(|| {
                        info!("Creating Docker image for {:?} (may block requests)", tc);
                        Self::make_image(tc, tccache)
                    }).clone()
                };
                Self::start_container(&image)
            },
        }
    }

    fn finish_container(&self, tc: &Toolchain, cid: String) {
        // TODO: collect images

        // Clean up any running processes
        let output = Command::new("docker").args(&["exec", &cid, "/busybox", "kill", "-9", "-1"]).output().unwrap();
        check_output(&output);

        // Check the diff and clean up the FS
        fn dodiff(cid: &str) -> String {
            let output = Command::new("docker").args(&["diff", cid]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        }
        let diff = dodiff(&cid);
        if diff != "" {
            let mut shoulddelete = false;
            let mut lastpath = None;
            for line in diff.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let changetype = iter.next().unwrap();
                let changepath = iter.next().unwrap();
                if iter.next() != None { panic!() }
                // TODO: If files are created in this dir, it gets marked as modified.
                // A similar thing applies to /root or /build etc
                if changepath == "/tmp" {
                    continue
                }
                if changetype != "A" {
                    warn!("Deleting container {}: path {} had a non-A changetype of {}", &cid, changepath, changetype);
                    shoulddelete = true;
                    break
                }
                // Docker diff paths are in alphabetical order and we do `rm -rf`, so we might be able to skip
                // calling Docker more than necessary (since it's slow)
                if let Some(lastpath) = lastpath {
                    if Path::new(changepath).starts_with(lastpath) {
                        continue
                    }
                }
                lastpath = Some(changepath.clone());
                let output = Command::new("docker").args(&["exec", &cid, "/busybox", "rm", "-rf", changepath]).output().unwrap();
                check_output(&output);
            }

            let newdiff = dodiff(&cid);
            // See note about changepath == "/tmp" above
            if !shoulddelete && newdiff != "" && newdiff != "C /tmp" {
                warn!("Deleted files, but container still has a diff: {:?}", newdiff);
                shoulddelete = true
            }

            if shoulddelete {
                let output = Command::new("docker").args(&["rm", "-f", &cid]).output().unwrap();
                check_output(&output);
                return
            }
        }

        // Good as new, add it back to the container list
        trace!("Reclaimed container");
        self.container_lists.lock().unwrap().get_mut(tc).unwrap().push(cid);
    }

    fn make_image(tc: &Toolchain, tccache: &Mutex<TcCache>) -> String {
        let cid = {
            let output = Command::new("docker").args(&["create", BASE_DOCKER_IMAGE, "/busybox", "true"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };

        let mut tccache = tccache.lock().unwrap();
        let toolchain_rdr = match tccache.get(tc) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => panic!("expected toolchain, but not available"),
            Err(e) => panic!("{}", e),
        };

        trace!("Copying in toolchain");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut {toolchain_rdr}, &mut process.stdin.take().unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        check_output(&output);

        let imagename = format!("sccache-builder-{}", &tc.archive_id);
        let output = Command::new("docker").args(&["commit", &cid, &imagename]).output().unwrap();
        check_output(&output);

        let output = Command::new("docker").args(&["rm", "-f", &cid]).output().unwrap();
        check_output(&output);

        imagename
    }

    fn start_container(image: &str) -> String {
        // Make sure sh doesn't exec the final command, since we need it to do
        // init duties (reaping zombies). Also, because we kill -9 -1, that kills
        // the sleep (it's not a builtin) so it needs to be a loop.
        let output = Command::new("docker")
            .args(&["run", "-d", image, "/busybox", "sh", "-c", "while true; do /busybox sleep 365d && /busybox true; done"]).output().unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned()
    }

    fn perform_build(compile_command: CompileCommand, inputs_rdr: InputsReader, output_paths: Vec<String>, cid: &str) -> BuildResult {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        trace!("copying in inputs");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut {inputs_rdr}, &mut process.stdin.take().unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        check_output(&output);

        let CompileCommand { executable, arguments, env_vars, cwd } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", cid, "/busybox", "mkdir", "-p"]).arg(cwd);
        for path in output_paths.iter() {
            cmd.arg(cwd.join(Path::new(path).parent().unwrap()));
        }
        let output = cmd.output().unwrap();
        check_output(&output);

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in env_vars {
            if k.contains("=") {
                warn!("Skipping environment variable: {:?}", k);
                continue
            }
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = format!("cd \"$1\" && shift && exec \"$@\"");
        cmd.args(&[cid, "/busybox", "sh", "-c", &shell_cmd]);
        cmd.arg(&executable);
        cmd.arg(cwd);
        cmd.arg(executable);
        cmd.args(arguments);
        let compile_output = cmd.output().unwrap();
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let abspath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker").args(&["exec", cid, "/busybox", "cat"]).arg(abspath).output().unwrap();
            if output.status.success() {
                outputs.push((path, OutputData::from_reader(&*output.stdout)))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        BuildResult { output: compile_output.into(), outputs }
    }
}

impl BuilderIncoming for DockerBuilder {
    type Error = Error;
    // From Server
    fn run_build(&self, tc: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, tccache: &Mutex<TcCache>) -> Result<BuildResult> {
        debug!("Finding container");
        let cid = self.get_container(&tc, tccache);
        debug!("Performing build with container {}", cid);
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid);
        debug!("Finishing with container {}", cid);
        self.finish_container(&tc, cid);
        debug!("Returning result");
        Ok(res)
    }
}
