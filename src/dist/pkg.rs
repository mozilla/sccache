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

use dist;
use std::io;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::str;
use tar;

use errors::*;

pub use self::toolchain_imp::*;

pub trait ToolchainPackager {
    fn write_pkg(self: Box<Self>, f: fs::File) -> Result<()>;
}

pub trait InputsPackager: Send {
    fn write_inputs(self: Box<Self>, wtr: &mut io::Write) -> Result<dist::PathTransformer>;
}

pub trait OutputsRepackager {
    fn repackage_outputs(self: Box<Self>, wtr: &mut io::Write) -> Result<dist::PathTransformer>;
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod toolchain_imp {
    use std::fs;
    use super::ToolchainPackager;

    use errors::*;

    // Distributed client, but an unsupported platform for toolchain packaging so
    // create a failing implementation that will conflict with any others.
    impl<T> ToolchainPackager for T {
        fn write_pkg(self: Box<Self>, _f: fs::File) -> Result<()> {
            bail!("Automatic packaging not supported on this platform")
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod toolchain_imp {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::fs;
    use std::path::{Component, Path, PathBuf};
    use std::process;
    use std::str;
    use super::tarify_path;
    use tar;

    use errors::*;

    pub struct ToolchainPackageBuilder {
        // Put dirs and file in a deterministic order (map from tar_path -> real_path)
        dir_set: BTreeMap<PathBuf, PathBuf>,
        file_set: BTreeMap<PathBuf, PathBuf>,
    }

    impl ToolchainPackageBuilder {
        pub fn new() -> Self {
            ToolchainPackageBuilder { dir_set: BTreeMap::new(), file_set: BTreeMap::new() }
        }

        pub fn add_common(&mut self) -> Result<()> {
            self.add_dir(PathBuf::from("/tmp"))
        }

        pub fn add_executable_and_deps(&mut self, executable: PathBuf) -> Result<()> {
            let mut remaining = vec![executable.to_owned()];
            while let Some(obj_path) = remaining.pop() {
                assert!(obj_path.is_absolute());
                let tar_path = tarify_path(&obj_path)?;
                // If file already in the set, assume we've analysed all deps
                if self.file_set.contains_key(&tar_path) {
                    continue
                }
                remaining.extend(find_ldd_libraries(&obj_path)?);
                self.file_set.insert(tar_path, obj_path);
            }
            Ok(())
        }

        pub fn add_dir(&mut self, dir_path: PathBuf) -> Result<()> {
            assert!(dir_path.is_absolute());
            if !dir_path.is_dir() {
                bail!(format!("{} was not a dir when readying for tar", dir_path.to_string_lossy()))
            }
            if dir_path.components().next_back().expect("asserted absolute") == Component::RootDir {
                return Ok(())
            }
            let tar_path = tarify_path(&dir_path)?;
            self.dir_set.insert(tar_path, dir_path);
            Ok(())
        }

        pub fn add_file(&mut self, file_path: PathBuf) -> Result<()> {
            assert!(file_path.is_absolute());
            if !file_path.is_file() {
                bail!(format!("{} was not a file when readying for tar", file_path.to_string_lossy()))
            }
            let tar_path = tarify_path(&file_path)?;
            self.file_set.insert(tar_path, file_path);
            Ok(())
        }

        pub fn into_compressed_tar<W: Write>(self, writer: W) -> Result<()> {
            use flate2;
            use flate2::write::GzEncoder;
            let ToolchainPackageBuilder { dir_set, file_set } = self;

            let mut builder = tar::Builder::new(GzEncoder::new(writer, flate2::Compression::default()));
            for (tar_path, dir_path) in dir_set.into_iter() {
                builder.append_dir(tar_path, dir_path)?
            }
            for (tar_path, file_path) in file_set.into_iter() {
                let file = &mut fs::File::open(file_path)?;
                builder.append_file(tar_path, file)?
            }
            builder.finish().map_err(Into::into)
        }
    }

    // The dynamic linker is the only thing that truly knows how dynamic libraries will be
    // searched for, so we need to ask it directly.
    //
    // This function will extract any absolute paths from output like the following:
    // $ ldd /bin/ls
    //         linux-vdso.so.1 =>  (0x00007ffeb41f6000)
    //         libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f6877f4f000)
    //         libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f6877b85000)
    //         libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f6877915000)
    //         libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f6877711000)
    //         /lib64/ld-linux-x86-64.so.2 (0x00007f6878171000)
    //         libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f68774f4000)
    fn find_ldd_libraries(executable: &Path) -> Result<Vec<PathBuf>> {

        let process::Output { status, stdout, stderr } = process::Command::new("ldd").arg(executable).output()?;

        // Not a file ldd understands
        if !status.success() {
            bail!(format!("ldd failed to run on {}", executable.to_string_lossy()))
        }

        if !stderr.is_empty() {
            trace!("ldd stderr non-empty: {:?}", String::from_utf8_lossy(&stderr))
        }

        let stdout = str::from_utf8(&stdout).map_err(|_| "ldd output not utf8")?;

        // If it's static the output will be a line like "not a dynamic executable", so be forgiving
        // in the parsing here and treat parsing oddities as an empty list.
        let mut libs = vec![];
        for line in stdout.lines() {
            let line = line.trim();
            let mut parts: Vec<_> = line.split_whitespace().collect();

            // Remove a possible "(0xdeadbeef)" or assume this isn't a library line
            match parts.pop() {
                Some(s) if s.starts_with('(') && s.ends_with(')') => (),
                Some(_) |
                None => continue,
            }

            if parts.len() > 3 {
                continue
            }

            let libpath = match (parts.get(0), parts.get(1), parts.get(2)) {
                // "linux-vdso.so.1 =>  (0x00007ffeb41f6000)"
                (Some(_libname), Some(&"=>"), None) => continue,
                // "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f6877b85000)"
                (Some(_libname), Some(&"=>"), Some(libpath)) => PathBuf::from(libpath),
                // "/lib64/ld-linux-x86-64.so.2 (0x00007f6878171000)"
                (Some(libpath), None, None) => PathBuf::from(libpath),
                _ => continue,
            };

            if !libpath.is_absolute() {
                continue
            }

            libs.push(libpath)
        }
        Ok(libs)
    }
}

pub fn make_tar_header(src: &Path, dest: &str) -> io::Result<tar::Header> {
    let metadata_res = fs::metadata(&src);

    let mut file_header = tar::Header::new_ustar();
    // TODO: test this works
    if let Ok(metadata) = metadata_res {
        // TODO: if the source file is a symlink, I think this does bad things
        file_header.set_metadata(&metadata);
    } else {
        warn!("Couldn't get metadata of file {:?}, falling back to some defaults", src);
        file_header.set_mode(0o644);
        file_header.set_uid(0);
        file_header.set_gid(0);
        file_header.set_mtime(0);
        file_header.set_device_major(0).expect("expected a ustar header");
        file_header.set_device_minor(0).expect("expected a ustar header");
        file_header.set_entry_type(tar::EntryType::file());
    }

    // tar-rs imposes that `set_path` takes a relative path
    assert!(dest.starts_with("/"));
    let dest = dest.trim_left_matches("/");
    assert!(!dest.starts_with("/"));
    // `set_path` converts its argument to a Path and back to bytes on Windows, so this is
    // a bit of an inefficient round-trip. Windows path separators will also be normalised
    // to be like Unix, and the path is (now) relative so there should be no funny results
    // due to Windows
    // TODO: should really use a `set_path_str` or similar
    file_header.set_path(&dest)?;
    Ok(file_header)
}

/// Simplify the path and strip the leading slash
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn tarify_path(path: &Path) -> Result<PathBuf> {
    let final_path = simplify_path(path)?;
    let mut components = final_path.components();
    assert_eq!(components.next(), Some(Component::RootDir));
    Ok(components.as_path().to_owned())
}

/// Simplify a path to one without any relative components, erroring if it looks
/// like there could be any symlink complexity that means a simplified path is not
/// equivalent to the original (see the documentation of `fs::canonicalize` for an
/// example).
///
/// So why avoid resolving symlinks? Any path that we are trying to simplify has
/// (usually) been added to an archive because something will try access it, but
/// resolving symlinks (be they for the actual file or directory components) can
/// make the accessed path 'disappear' in favour of the canonical path.
pub fn simplify_path(path: &Path) -> Result<PathBuf> {
    let mut final_path = PathBuf::new();
    for component in path.components() {
        match component {
            c @ Component::RootDir |
            c @ Component::Prefix(_) |
            c @ Component::Normal(_) => final_path.push(c),
            Component::ParentDir => {
                // If the path is doing funny symlink traversals, just give up
                let is_symlink = fs::symlink_metadata(&final_path)
                    .chain_err(|| "Missing directory while simplifying path")?
                    .file_type()
                    .is_symlink();
                if is_symlink {
                    bail!("Cannot handle symlinks in parent paths")
                }
                final_path.pop();
            },
            Component::CurDir => continue,
        }
    }
    Ok(final_path)
}

