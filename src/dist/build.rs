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

use dist::cache::TcCache;
use lru_disk_cache::Error as LruError;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use super::{CompileCommand, InputsReader, Toolchain};
use super::{BuildResult, BuilderIncoming};

use errors::*;

pub struct DockerBuilder {
    image_map: Arc<Mutex<HashMap<Toolchain, String>>>,
    container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
}

fn check_output(output: &Output) {
    if !output.status.success() {
        error!("===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
}

impl DockerBuilder {
    pub fn new() -> Self {
        Self::cleanup();
        Self {
            image_map: Arc::new(Mutex::new(HashMap::new())),
            container_lists: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup() {
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
    fn get_container(image_map: &Mutex<HashMap<Toolchain, String>>, container_lists: &Mutex<HashMap<Toolchain, Vec<String>>>, tc: &Toolchain, cache: Arc<Mutex<TcCache>>) -> String {
        let container = {
            let mut map = container_lists.lock().unwrap();
            map.entry(tc.clone()).or_insert_with(Vec::new).pop()
        };
        match container {
            Some(cid) => cid,
            None => {
                // TODO: can improve parallelism (of creating multiple images at a time) by using another
                // (more fine-grained) mutex around the entry value and checking if its empty a second time
                let image = {
                    let mut map = image_map.lock().unwrap();
                    map.entry(tc.clone()).or_insert_with(|| {
                        info!("Creating Docker image for {:?} (may block requests)", tc);
                        Self::make_image(tc, cache)
                    }).clone()
                };
                Self::start_container(&image)
            },
        }
    }

    fn finish_container(container_lists: &Mutex<HashMap<Toolchain, Vec<String>>>, tc: &Toolchain, cid: String) {
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
        container_lists.lock().unwrap().get_mut(&tc).unwrap().push(cid);
    }

    fn make_image(tc: &Toolchain, cache: Arc<Mutex<TcCache>>) -> String {
        let cid = {
            let output = Command::new("docker").args(&["create", &tc.docker_img, "/busybox", "true"]).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };

        let mut toolchain_cache = cache.lock().unwrap();
        let toolchain_reader = match toolchain_cache.get(&tc.archive_id) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => panic!("expected toolchain, but not available"),
            Err(e) => panic!("{}", e),
        };

        trace!("Copying in toolchain");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut {toolchain_reader}, &mut process.stdin.take().unwrap()).unwrap();
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
        let cwd = PathBuf::from(compile_command.cwd);

        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!("Compile command: {:?} {:?}", compile_command.executable, compile_command.arguments);

        trace!("copying in build dir");
        let mut process = Command::new("docker").args(&["cp", "-", &format!("{}:/", cid)]).stdin(Stdio::piped()).spawn().unwrap();
        io::copy(&mut {inputs_rdr}, &mut process.stdin.take().unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        check_output(&output);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", cid, "/busybox", "mkdir", "-p"]).arg(&cwd);
        for path in output_paths.iter() {
            cmd.arg(cwd.join(Path::new(path).parent().unwrap()));
        }
        let output = cmd.output().unwrap();
        check_output(&output);

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in compile_command.env_vars {
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = format!("cd \"$1\" && shift && exec \"$@\"");
        cmd.args(&[cid, "/busybox", "sh", "-c", &shell_cmd]);
        cmd.arg(&compile_command.executable);
        cmd.arg(&cwd);
        cmd.arg(compile_command.executable);
        cmd.args(compile_command.arguments);
        let compile_output = cmd.output().unwrap();
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let dockerpath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker").args(&["exec", cid, "/busybox", "cat"]).arg(dockerpath).output().unwrap();
            if output.status.success() {
                outputs.push((path, output.stdout))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        BuildResult { output: compile_output.into(), outputs }
    }
}

impl BuilderIncoming for DockerBuilder {
    // From Server
    fn run_build(&self, tc: Toolchain, command: CompileCommand, outputs: Vec<String>, inputs_rdr: InputsReader, cache: Arc<Mutex<TcCache>>) -> Result<BuildResult> {
        let image_map = self.image_map.clone();
        let container_lists = self.container_lists.clone();

        debug!("Finding container");
        let cid = Self::get_container(&image_map, &container_lists, &tc, cache);
        debug!("Performing build with container {}", cid);
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid);
        debug!("Finishing with container {}", cid);
        Self::finish_container(&container_lists, &tc, cid);
        debug!("Returning result");
        Ok(res)
    }
}
