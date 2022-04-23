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

use anyhow::{bail, Context, Error, Result};
use flate2::read::GzDecoder;
use sccache::dist::{
    BuildResult, BuilderIncoming, CompileCommand, InputsReader, OutputData, ProcessOutput, TcCache,
    Toolchain,
};
use sccache::lru_disk_cache::Error as LruError;
use std::collections::{hash_map, HashMap};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{hint, thread};
use uuid::Uuid;

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

// Force remove the container
fn pot_rm(cid: &str, pot_cmd: &PathBuf) -> Result<()> {
    Command::new(pot_cmd)
        .args(&["destroy", "-F", "-p", cid])
        .check_run()
        .context("Failed to force delete container")
}

#[derive(Clone)]
pub struct PotBuilder {
    pot_fs_root: PathBuf,
    clone_from: String,
    pot_cmd: PathBuf,
    pot_clone_args: Vec<String>,
    image_map: Arc<Mutex<HashMap<Toolchain, String>>>,
    container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
    cleanup_thread_count: Arc<AtomicUsize>,
    max_cleanup_thread_count: usize,
}

impl PotBuilder {
    // TODO: this should accept a unique string, e.g. inode of the tccache directory
    // having locked a pidfile, or at minimum should loudly detect other running
    // instances - pidfile in /tmp
    pub fn new(
        pot_fs_root: PathBuf,
        clone_from: String,
        pot_cmd: PathBuf,
        pot_clone_args: Vec<String>,
    ) -> Result<Self> {
        info!("Creating pot builder");

        let ret = Self {
            pot_fs_root,
            clone_from,
            pot_cmd,
            pot_clone_args,
            image_map: Arc::new(Mutex::new(HashMap::new())),
            container_lists: Arc::new(Mutex::new(HashMap::new())),
            cleanup_thread_count: Arc::new(AtomicUsize::new(0)),
            max_cleanup_thread_count: num_cpus::get() * 3,
        };
        ret.cleanup()?;
        Ok(ret)
    }

    // This removes all leftover pots from previous runs
    fn cleanup(&self) -> Result<()> {
        info!("Performing initial pot cleanup");
        let mut to_remove = Command::new(&self.pot_cmd)
            .args(&["ls", "-q"])
            .check_stdout_trim()
            .context("Failed to force delete container")?
            .split('\n')
            .filter(|a| a.starts_with("sccache-builder-") || a.starts_with("sccache-image-"))
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        to_remove.sort();
        for cid in to_remove {
            trace!("Removing pot {}", cid);
            if let Err(e) = pot_rm(&cid, &self.pot_cmd) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
        info!("Completed initial pot cleanup");
        Ok(())
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Pot image along
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
                            info!("Creating pot image for {:?} (may block requests)", tc);
                            let image = Self::make_image(
                                tc,
                                tccache,
                                &self.pot_fs_root,
                                &self.clone_from,
                                &self.pot_cmd,
                                &self.pot_clone_args,
                            )?;
                            e.insert(image.clone());
                            image
                        }
                    }
                };
                Self::start_container(&image, &self.pot_cmd, &self.pot_clone_args)
            }
        }
    }

    fn clean_container(cid: &str) -> Result<()> {
        Command::new("pot")
            .args(&["stop", "-p", cid])
            .check_run()
            .context("Failed to stop container")?;

        Command::new("pot")
            .args(&["revert", "-p", cid])
            .check_run()
            .context("Failed to revert container")?;

        Command::new("pot")
            .args(&["start", "-p", cid])
            .check_run()
            .context("Failed to (re)start container")?;
        Ok(())
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_container(
        container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
        tc: Toolchain,
        cid: String,
        pot_cmd: &PathBuf,
    ) {
        if let Err(e) = Self::clean_container(&cid) {
            info!("Failed to clean container {}: {}", cid, e);
            if let Err(e) = pot_rm(&cid, pot_cmd) {
                warn!(
                    "Failed to remove container {} after failed clean: {}",
                    cid, e
                );
            }
            return;
        }

        // Good as new, add it back to the container list
        if let Some(entry) = container_lists.lock().unwrap().get_mut(&tc) {
            debug!("Reclaimed container {}", cid);
            entry.push(cid)
        } else {
            warn!(
                "Was ready to reclaim container {} but toolchain went missing",
                cid
            );
            if let Err(e) = pot_rm(&cid, pot_cmd) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
    }

    fn make_image(
        tc: &Toolchain,
        tccache: &Mutex<TcCache>,
        pot_fs_root: &Path,
        clone_from: &str,
        pot_cmd: &PathBuf,
        pot_clone_args: &[String],
    ) -> Result<String> {
        let imagename = format!("sccache-image-{}", &tc.archive_id);
        trace!("Creating toolchain image: {}", imagename);
        let mut clone_args: Vec<&str> = ["clone", "-p", &imagename, "-P", clone_from].to_vec();
        clone_args.append(&mut pot_clone_args.iter().map(|s| s as &str).collect());
        Command::new(pot_cmd)
            .args(clone_args)
            .check_run()
            .context("Failed to create pot container")?;

        let mut tccache = tccache.lock().unwrap();
        let toolchain_rdr = match tccache.get(tc) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => {
                bail!("expected toolchain {}, but not available", tc.archive_id)
            }
            Err(e) => return Err(Error::from(e).context("failed to get toolchain from cache")),
        };

        trace!("Copying in toolchain");
        tar::Archive::new(GzDecoder::new(toolchain_rdr))
            .unpack(pot_fs_root.join("jails").join(&imagename).join("m"))
            .or_else(|e| {
                warn!("Failed to unpack toolchain: {:?}", e);
                tccache
                    .remove(tc)
                    .context("Failed to remove corrupt toolchain")?;
                Err(Error::from(e))
            })?;

        Command::new(pot_cmd)
            .args(&["snapshot", "-p", &imagename])
            .check_run()
            .context("Failed to snapshot container after build")?;

        Ok(imagename)
    }

    fn start_container(
        image: &str,
        pot_cmd: &PathBuf,
        pot_clone_args: &[String],
    ) -> Result<String> {
        let cid = format!("sccache-builder-{}", Uuid::new_v4());
        let mut clone_args: Vec<&str> = ["clone", "-p", &cid, "-P", image].to_vec();
        clone_args.append(&mut pot_clone_args.iter().map(|s| s as &str).collect());
        Command::new(pot_cmd)
            .args(&clone_args)
            .check_run()
            .context("Failed to create pot container")?;

        Command::new(pot_cmd)
            .args(&["snapshot", "-p", &cid])
            .check_run()
            .context("Failed to snapshotpot container")?;

        Command::new(pot_cmd)
            .args(&["start", "-p", &cid])
            .check_run()
            .context("Failed to start container")?;
        Ok(cid.to_string())
    }

    fn perform_build(
        compile_command: CompileCommand,
        inputs_rdr: InputsReader,
        output_paths: Vec<String>,
        cid: &str,
        pot_fs_root: &Path,
    ) -> Result<BuildResult> {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable,
            compile_command.arguments
        );

        trace!("copying in inputs");
        // not elegant
        tar::Archive::new(inputs_rdr)
            .unpack(pot_fs_root.join("jails").join(cid).join("m"))
            .context("Failed to unpack inputs to pot")?;

        let CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("jexec");
        cmd.args(&[cid, "mkdir", "-p"]).arg(cwd);
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
        let mut cmd = Command::new("jexec");
        cmd.arg(cid);
        cmd.arg("env");
        for (k, v) in env_vars {
            if k.contains('=') {
                warn!("Skipping environment variable: {:?}", k);
                continue;
            }
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg(env);
        }
        let shell_cmd = "cd \"$1\" && shift && exec \"$@\"";
        cmd.args(&["sh", "-c", shell_cmd]);
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
            let output = Command::new("jexec")
                .args(&[cid, "cat"])
                .arg(abspath)
                .output()
                .context("Failed to start command to retrieve output file")?;
            if output.status.success() {
                let output = OutputData::try_from_reader(&*output.stdout)
                    .expect("Failed to read compress output stdout");
                outputs.push((path, output))
            } else {
                debug!("Missing output path {:?}", path)
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

impl BuilderIncoming for PotBuilder {
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
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid, &self.pot_fs_root)
            .context("Failed to perform build")?;
        debug!("Finishing with container {}", cid);
        let cloned = self.clone();
        let tc = tc;
        while cloned.cleanup_thread_count.fetch_add(1, Ordering::SeqCst)
            > self.max_cleanup_thread_count
        {
            cloned.cleanup_thread_count.fetch_sub(1, Ordering::SeqCst);
            hint::spin_loop();
        }
        thread::spawn(move || {
            Self::finish_container(cloned.container_lists, tc, cid, &cloned.pot_cmd);
            cloned.cleanup_thread_count.fetch_sub(1, Ordering::SeqCst);
        });
        debug!("Returning result");
        Ok(res)
    }
}
