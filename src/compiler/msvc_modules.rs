// Copyright 2026 Mozilla Foundation
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

use super::CompilationCacheMetadata;
use super::c::ParsedArguments;
use crate::cache::{CacheRead, DecompressionFailure};
use crate::config::MSVC_MODULE_ORIGIN_DIR;
use crate::errors::*;
use crate::lru_disk_cache::LruDiskCache;
use crate::util::{Digest, HashToDigest, env_var_name_matches};
use anyhow::ensure;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsString;
use std::hash::Hash;
use std::io::{self, Write};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::Arc;
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FILE_ID_INFO, FileBasicInfo, FileIdInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
};

const METADATA_NAME: &str = "msvc-module-origin-v3";
const SHARD_CAPACITY: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
struct PathMap {
    from: PathBuf,
    to: PathBuf,
}

fn prefix_suffix<'a>(path: &'a Path, prefix: &Path) -> Option<&'a str> {
    let path = path.to_str()?;
    let prefix = prefix.to_str()?;
    let ascii_start = path
        .get(..prefix.len())
        .filter(|start| start.is_ascii() && prefix.is_ascii());
    let boundary = if let Some(start) = ascii_start {
        let fold = |byte: u8| {
            if byte == b'/' {
                b'\\'
            } else {
                byte.to_ascii_lowercase()
            }
        };
        if !start.bytes().map(fold).eq(prefix.bytes().map(fold)) {
            return None;
        }
        prefix.len()
    } else {
        let boundary = path
            .char_indices()
            .nth(prefix.chars().count())
            .map_or(path.len(), |(offset, _)| offset);
        let start = path.get(..boundary)?.replace('/', "\\");
        let prefix_wide: Vec<_> = prefix.replace('/', "\\").encode_utf16().collect();
        let start_wide: Vec<_> = start.encode_utf16().collect();
        if unsafe {
            CompareStringOrdinal(
                start_wide.as_ptr(),
                start_wide.len().try_into().ok()?,
                prefix_wide.as_ptr(),
                prefix_wide.len().try_into().ok()?,
                1,
            )
        } != CSTR_EQUAL
        {
            return None;
        }
        boundary
    };
    let suffix = &path[boundary..];
    if suffix.is_empty() || prefix.ends_with('\\') || suffix.starts_with(['\\', '/']) {
        Some(suffix.trim_start_matches(['\\', '/']))
    } else {
        None
    }
}

fn normalized_absolute(path: &str) -> Option<PathBuf> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path.to_str()?.contains(['/', '=', ',', ';'])
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        || (path.to_str()?.ends_with('\\') && path.parent().is_some())
    {
        return None;
    }
    Some(path.to_owned())
}

fn mapping_root(path: &str) -> Option<PathBuf> {
    let without_separator = path.strip_suffix('\\')?;
    // A drive root needs the separator to be absolute.
    normalized_absolute(without_separator).or_else(|| {
        let root = normalized_absolute(path)?;
        root.parent().is_none().then_some(root)
    })
}

fn with_separator(path: &Path) -> String {
    let path = path.to_str().expect("pathmap roots were validated");
    if path.ends_with('\\') {
        path.to_owned()
    } else {
        format!("{path}\\")
    }
}

fn mapped_path(maps: &[PathMap], path: &Path) -> PathBuf {
    maps.iter()
        .find_map(|map| prefix_suffix(path, &map.from).map(|suffix| translated(map, suffix)))
        .unwrap_or_else(|| path.to_owned())
}

fn translated(map: &PathMap, suffix: &str) -> PathBuf {
    if suffix.is_empty() {
        map.to.clone()
    } else {
        map.to.join(suffix)
    }
}

fn compatible(maps: &[PathMap], map: &PathMap) -> bool {
    maps.iter().all(|other| {
        if let Some(suffix) = prefix_suffix(&map.from, &other.from) {
            translated(other, suffix).as_os_str() == map.to.as_os_str()
        } else if let Some(suffix) = prefix_suffix(&other.from, &map.from) {
            translated(map, suffix).as_os_str() == other.to.as_os_str()
        } else {
            true
        }
    })
}

#[derive(Clone)]
pub(super) struct MappedModules {
    user_maps: Vec<PathMap>,
    maps: Vec<PathMap>,
    state_dir: PathBuf,
    pub(super) uncacheable_import: bool,
}

impl MappedModules {
    pub(super) fn new(
        args: &ParsedArguments,
        cwd: &Path,
        env: &[(OsString, OsString)],
        basedirs: &[Vec<u8>],
    ) -> Result<Option<Self>> {
        let Some(flags) = args
            .common_args
            .iter()
            .map(|arg| arg.to_str())
            .collect::<Option<Vec<_>>>()
        else {
            debug!("MSVC mapped caching disabled: opaque compiler arguments");
            return Ok(None);
        };
        if flags.iter().any(|arg| {
            let flag = arg.trim_start_matches(['-', '/']);
            flag == "C" || flag.starts_with("d1") || flag.starts_with("d2")
        }) {
            debug!("MSVC mapped caching disabled: source-preserving or internal compiler options");
            return Ok(None);
        }
        if basedirs.is_empty()
            || !flags.iter().any(|arg| matches!(*arg, "/FC" | "-FC"))
            || !flags.iter().any(|arg| {
                matches!(
                    *arg,
                    "/experimental:deterministic" | "-experimental:deterministic"
                )
            })
        {
            return Ok(None);
        }
        let mut maps = Vec::new();
        for flag in flags {
            let Some(spec) = flag
                .strip_prefix("/pathmap:")
                .or_else(|| flag.strip_prefix("-pathmap:"))
            else {
                continue;
            };
            let Some((from, to)) = spec.split_once('=') else {
                debug!("MSVC mapped caching disabled: unsupported /pathmap syntax");
                return Ok(None);
            };
            let Some(from) = mapping_root(from) else {
                debug!(
                    "MSVC mapped caching disabled: physical /pathmap root needs a trailing backslash"
                );
                return Ok(None);
            };
            let Some(to) = mapping_root(to) else {
                debug!(
                    "MSVC mapped caching disabled: logical /pathmap root needs a trailing backslash"
                );
                return Ok(None);
            };
            let map = PathMap { from, to };
            if !basedirs.iter().any(|base| {
                String::from_utf8_lossy(base)
                    .replace('/', "\\")
                    .trim_end_matches('\\')
                    .eq_ignore_ascii_case(map.from.to_str().unwrap().trim_end_matches('\\'))
            }) || !compatible(&maps, &map)
            {
                debug!(
                    "MSVC mapped caching disabled: incompatible /pathmap or SCCACHE_BASEDIRS roots"
                );
                return Ok(None);
            }
            maps.push(map);
        }
        if maps.is_empty()
            || args
                .input
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || args.outputs.values().any(|out| {
                out.path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            })
            || !maps
                .iter()
                .any(|map| prefix_suffix(cwd, &map.from).is_some())
            || !maps
                .iter()
                .any(|map| prefix_suffix(&cwd.join(&args.input), &map.from).is_some())
            || args.outputs.values().any(|out| {
                !out.optional
                    && !maps
                        .iter()
                        .any(|map| prefix_suffix(&cwd.join(&out.path), &map.from).is_some())
            })
        {
            return Ok(None);
        }
        let Some(root) = env
            .iter()
            .find(|(name, _)| env_var_name_matches(name, "SCCACHE_DIR"))
            .map(|(_, value)| PathBuf::from(value))
            .filter(|root| root.is_absolute())
        else {
            debug!("MSVC mapped caching disabled: use an absolute, writable SCCACHE_DIR");
            return Ok(None);
        };
        Ok(Some(Self {
            user_maps: maps.clone(),
            maps,
            state_dir: root.join(MSVC_MODULE_ORIGIN_DIR),
            uncacheable_import: false,
        }))
    }

    pub(super) fn path(&self, path: &Path) -> PathBuf {
        mapped_path(&self.user_maps, path)
    }

    pub(super) fn preprocessed_digest(
        &self,
        bytes: &[u8],
        cwd: &Path,
        textual_inputs: &[PathBuf],
    ) -> Result<String> {
        for path in textual_inputs {
            ensure!(
                mapped_path(&self.maps, path) == self.path(path),
                "Inherited IFC path mapping would alter a textual input: {}. Rebuild imported IFCs in this checkout",
                path.display()
            );
        }
        let inherited = !self.extra_args().is_empty();
        let known_ascii: HashSet<_> = textual_inputs
            .iter()
            .filter_map(|path| path.to_str())
            .filter(|path| path.is_ascii())
            .map(|path| path.replace('/', "\\").to_ascii_lowercase())
            .collect();
        let mut digest = Digest::new();
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            let checksum_pragma = line
                .trim_ascii_start()
                .strip_prefix(b"#")
                .and_then(|line| line.trim_ascii_start().strip_prefix(b"pragma"))
                .is_some_and(|line| line.trim_ascii_start().starts_with(b"checksum"));
            if line.starts_with(b"#line ") {
                let marker = line
                    .iter()
                    .position(|byte| *byte == b'"')
                    .zip(line.iter().rposition(|byte| *byte == b'"'))
                    .filter(|(start, end)| start < end)
                    .and_then(|(start, end)| {
                        serde_json::from_slice::<String>(&line[start..=end])
                            .ok()
                            .map(|name| (start, end, cwd.join(name)))
                    });
                if let Some((start, end, path)) = marker
                    && (known_ascii.contains(
                        &path
                            .to_string_lossy()
                            .replace('/', "\\")
                            .to_ascii_lowercase(),
                    ) || textual_inputs.iter().any(|input| {
                        prefix_suffix(input, &path) == Some("")
                            && prefix_suffix(&path, input) == Some("")
                    }))
                {
                    (&line[..start], self.path(&path), &line[end + 1..]).hash(&mut HashToDigest {
                        digest: &mut digest,
                    });
                    continue;
                }
                ensure!(
                    !inherited,
                    "Cannot safely inherit IFC path mappings with synthetic or unsupported #line filenames. Rebuild imported IFCs in this checkout"
                );
                debug!("Keeping an MSVC source-location directive path-dependent");
                cwd.hash(&mut HashToDigest {
                    digest: &mut digest,
                });
            } else if checksum_pragma {
                ensure!(
                    !inherited,
                    "Cannot safely inherit IFC path mappings with #pragma checksum"
                );
                cwd.hash(&mut HashToDigest {
                    digest: &mut digest,
                });
            }
            line.hash(&mut HashToDigest {
                digest: &mut digest,
            });
        }
        Ok(digest.finish())
    }

    pub(super) fn arguments(&self, args: &[OsString]) -> Vec<OsString> {
        let mut result = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let Some(text) = arg.to_str() else {
                result.push(arg.clone());
                continue;
            };
            let flag = text.trim_start_matches(['-', '/']);
            if let Some(spec) = flag.strip_prefix("pathmap:") {
                // Preserve the logical spelling and mapping boundary, not the physical root.
                result.push(format!("-pathmap:={}", spec.split_once('=').unwrap().1).into());
            } else if matches!(
                flag,
                "ifcOutput" | "ifcSearchDir" | "stdIfcDir" | "sourceDependencies"
            ) {
                result.push(arg.clone());
                if let Some(value) = args.next() {
                    result.push(self.path(Path::new(value)).into_os_string());
                }
            } else if matches!(
                flag,
                "reference" | "headerUnit" | "headerUnit:quote" | "headerUnit:angle"
            ) {
                result.push(arg.clone());
                if let Some(value) = args.next() {
                    result.push(self.reference(value));
                }
            } else if let Some(prefix) = ["external:I", "FI", "Fo", "I"]
                .iter()
                .find(|p| flag.starts_with(**p))
            {
                let path = &flag[prefix.len()..];
                if path.is_empty() {
                    result.push(arg.clone());
                    if let Some(value) = args.next() {
                        result.push(self.path(Path::new(value)).into_os_string());
                    }
                } else {
                    result.push(
                        format!(
                            "{}{prefix}{}",
                            &text[..1],
                            self.path(Path::new(path)).display()
                        )
                        .into(),
                    );
                }
            } else {
                result.push(arg.clone());
            }
        }
        result
    }

    fn reference(&self, value: &std::ffi::OsStr) -> OsString {
        let Some(value) = value.to_str() else {
            return value.to_owned();
        };
        if let Some((name, path)) = value.split_once('=') {
            format!(
                "{}={}",
                self.path(Path::new(name)).display(),
                self.path(Path::new(path)).display()
            )
            .into()
        } else {
            self.path(Path::new(value)).into_os_string()
        }
    }

    pub(super) fn imports(&mut self, imports: &[PathBuf]) -> Result<Vec<(PathBuf, Vec<u8>)>> {
        let mut contexts = Vec::new();
        for path in imports {
            let snapshot = Snapshot::read(path)?;
            let shard = OriginShard::new(&self.state_dir, &snapshot.key);
            let _lock = shard.lock()?;
            let file = shard.record_path(&snapshot.key);
            let record: OriginRecord = serde_json::from_slice(&fs::read(&file).with_context(|| {
                format!("Missing MSVC IFC producer context for {}. Rebuild imported IFCs with mapped caching enabled", path.display())
            })?).context("Invalid MSVC IFC provenance index")?;
            ensure!(
                record.stamp == snapshot.stamp
                    && record.context.ifc_digest.as_deref() == Some(snapshot.digest.as_str()),
                "Stale MSVC IFC producer context for {}. Rebuild this IFC with mapped caching enabled",
                path.display()
            );
            record.context.check()?;
            self.uncacheable_import |= record.context.uncacheable;
            if let Err(error) = filetime::set_file_mtime(&file, filetime::FileTime::now()) {
                debug!("Cannot update MSVC IFC provenance recency: {error}");
            }
            for map in &record.context.maps {
                ensure!(
                    compatible(&self.maps, map),
                    "Conflicting inherited MSVC path mappings for {}. Rebuild the module graph with non-overlapping physical roots",
                    path.display()
                );
                if !self.maps.contains(map) {
                    self.maps.push(map.clone());
                }
            }
            contexts.push((self.path(path), serde_json::to_vec(&record.context)?));
        }
        contexts.sort();
        Ok(contexts)
    }

    pub(super) async fn with_imports(
        mut self,
        paths: Vec<PathBuf>,
    ) -> Result<(Self, Vec<(PathBuf, Vec<u8>)>)> {
        tokio::runtime::Handle::current()
            .spawn_blocking(move || {
                let contexts = self.imports(&paths)?;
                Ok((self, contexts))
            })
            .await?
    }

    pub(super) fn extra_args(&self) -> Vec<OsString> {
        self.maps
            .iter()
            .filter(|map| !self.user_maps.contains(map))
            .map(|map| {
                format!(
                    "-pathmap:{}={}",
                    with_separator(&map.from),
                    with_separator(&map.to)
                )
                .into()
            })
            .collect()
    }

    pub(super) fn metadata(
        &self,
        args: &ParsedArguments,
        cwd: &Path,
        includes_prefix: &str,
        uncacheable: bool,
    ) -> Arc<dyn CompilationCacheMetadata> {
        let path = args.outputs.get("ifc").map(|out| cwd.join(&out.path));
        Arc::new(ModuleMetadata {
            logical_path: path.as_ref().map(|path| self.path(path)),
            path,
            mapping: self.clone(),
            includes_prefix: includes_prefix.to_owned(),
            uncacheable,
            source_name: args
                .input
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerContext {
    version: u32,
    producer_key: String,
    ifc_digest: Option<String>,
    logical_path: Option<PathBuf>,
    maps: Vec<PathMap>,
    diagnostic_roots: Option<Vec<PathMap>>,
    uncacheable: bool,
}

impl ProducerContext {
    fn check(&self) -> Result<()> {
        ensure!(
            self.version == 3,
            "Unsupported MSVC producer-context version"
        );
        ensure!(
            self.ifc_digest.is_some() == self.logical_path.is_some(),
            "Incomplete MSVC IFC producer context"
        );
        ensure!(!self.maps.is_empty(), "Invalid MSVC producer mappings");
        for map in &self.maps {
            ensure!(
                map.from.to_str().and_then(normalized_absolute).is_some()
                    && map.to.to_str().and_then(normalized_absolute).is_some()
                    && compatible(&self.maps, map),
                "Invalid MSVC producer path mapping"
            );
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileStamp {
    length: u64,
    volume: u64,
    id: [u8; 16],
    created: i64,
    written: i64,
    changed: i64,
}

struct Snapshot {
    key: String,
    stamp: FileStamp,
    digest: String,
}

impl Snapshot {
    fn read(path: &Path) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let stamp = Self::stamp(&file)?;
        let digest = Digest::reader_sync(&mut file)?;
        ensure!(
            stamp == Self::stamp(&file)?,
            "MSVC IFC changed while reading {}",
            path.display()
        );
        let handle = file.as_raw_handle() as _;
        let size =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_GUID) };
        ensure!(
            size > 0,
            "Cannot identify MSVC IFC path: {}",
            io::Error::last_os_error()
        );
        let mut buffer = vec![0; size as usize];
        let len = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), size, VOLUME_NAME_GUID)
        };
        ensure!(
            len > 0 && len < size,
            "Cannot identify MSVC IFC path: {}",
            io::Error::last_os_error()
        );
        let canonical = OsString::from_wide(&buffer[..len as usize]);
        let mut key = Digest::new();
        canonical.hash(&mut HashToDigest { digest: &mut key });
        Ok(Self {
            key: key.finish(),
            stamp,
            digest,
        })
    }

    fn stamp(file: &fs::File) -> Result<FileStamp> {
        let handle = file.as_raw_handle() as _;
        let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        let mut id: FILE_ID_INFO = unsafe { std::mem::zeroed() };
        let basic_ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                std::ptr::from_mut(&mut basic).cast(),
                std::mem::size_of_val(&basic) as u32,
            )
        };
        ensure!(
            basic_ok != 0,
            "Cannot read MSVC IFC change stamp: {}",
            io::Error::last_os_error()
        );
        let id_ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                std::ptr::from_mut(&mut id).cast(),
                std::mem::size_of_val(&id) as u32,
            )
        };
        ensure!(
            id_ok != 0,
            "Cannot read MSVC IFC file identity: {}",
            io::Error::last_os_error()
        );
        ensure!(
            basic.ChangeTime > 0 && id.FileId.Identifier != [0; 16],
            "The filesystem cannot provide stable MSVC IFC provenance"
        );
        Ok(FileStamp {
            length: file.metadata()?.len(),
            volume: id.VolumeSerialNumber,
            id: id.FileId.Identifier,
            created: basic.CreationTime,
            written: basic.LastWriteTime,
            changed: basic.ChangeTime,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginRecord {
    stamp: FileStamp,
    context: ProducerContext,
}

// Shard the bounded index so a write need not rescan all recorded IFCs.
struct OriginShard {
    dir: PathBuf,
    lock: PathBuf,
}

impl OriginShard {
    fn new(root: &Path, key: &str) -> Self {
        let shard = &key[..2];
        Self {
            dir: root.join(shard),
            lock: root.join(format!("{shard}.lock")),
        }
    }

    fn lock(&self) -> Result<std::fs::File> {
        let directory = self
            .lock
            .parent()
            .expect("lock belongs to the origin directory");
        fs::create_dir_all(directory)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock)?;
        // Client-side and server-side compiles may share this index.
        lock.lock()?;
        Ok(lock)
    }

    fn record_path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    fn insert(&self, key: &str, data: &[u8], capacity: u64) -> Result<()> {
        let _lock = self.lock()?;
        let mut cache = LruDiskCache::new(&self.dir, capacity)?;
        let mut entry = cache.prepare_add(key, data.len() as u64)?;
        entry.as_file_mut().write_all(data)?;
        cache.commit(entry)?;
        Ok(())
    }
}

struct ModuleMetadata {
    path: Option<PathBuf>,
    logical_path: Option<PathBuf>,
    mapping: MappedModules,
    includes_prefix: String,
    source_name: String,
    uncacheable: bool,
}

impl ModuleMetadata {
    fn register(&self, snapshot: Snapshot, context: ProducerContext) -> Result<()> {
        ensure!(
            Some(snapshot.digest.as_str()) == context.ifc_digest.as_deref(),
            "MSVC IFC changed before producer context was registered"
        );
        let origin = serde_json::to_vec(&OriginRecord {
            stamp: snapshot.stamp,
            context,
        })?;
        OriginShard::new(&self.mapping.state_dir, &snapshot.key).insert(
            &snapshot.key,
            &origin,
            SHARD_CAPACITY,
        )
    }

    fn decode(&self, key: &str, data: &[u8]) -> Result<ProducerContext> {
        let context: ProducerContext =
            serde_json::from_slice(data).context("Invalid MSVC cache producer context")?;
        context.check()?;
        ensure!(
            context.producer_key == key && context.logical_path == self.logical_path,
            "MSVC cache entry is bound to another producer or logical output"
        );
        Ok(context)
    }
}

struct DigestWriter(Digest);

impl Write for DigestWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.update(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CompilationCacheMetadata for ModuleMetadata {
    fn name(&self) -> &'static str {
        METADATA_NAME
    }

    fn create(&self, key: &str, output: &process::Output) -> Result<Vec<u8>> {
        let snapshot = self.path.as_deref().map(Snapshot::read).transpose()?;
        let mut path_sensitive_diagnostics = false;
        for bytes in [&output.stdout, &output.stderr] {
            let text = super::msvc::from_local_codepage(bytes)?;
            for line in text
                .lines()
                .filter(|line| !line.starts_with(&self.includes_prefix))
            {
                if !line.is_empty() && line != self.source_name {
                    path_sensitive_diagnostics = true;
                }
            }
        }
        let context = ProducerContext {
            version: 3,
            producer_key: key.to_owned(),
            ifc_digest: snapshot.as_ref().map(|s| s.digest.clone()),
            logical_path: self.logical_path.clone(),
            maps: self.mapping.maps.clone(),
            diagnostic_roots: path_sensitive_diagnostics.then(|| self.mapping.user_maps.clone()),
            uncacheable: self.uncacheable,
        };
        context.check()?;
        let bytes = serde_json::to_vec(&context)?;
        if let Some(snapshot) = snapshot {
            self.register(snapshot, context)?;
        }
        Ok(bytes)
    }

    fn validate(&self, key: &str, data: &[u8], entry: &mut CacheRead) -> Result<bool> {
        let context = self
            .decode(key, data)
            .map_err(|error| anyhow!(DecompressionFailure).context(error))?;
        if let Some(expected) = &context.ifc_digest {
            let mut digest = DigestWriter(Digest::new());
            entry.get_object("ifc", &mut digest)?;
            ensure!(digest.0.finish() == *expected, DecompressionFailure);
        }
        Ok(!context.uncacheable
            && context
                .diagnostic_roots
                .as_ref()
                .is_none_or(|roots| roots == &self.mapping.user_maps)
            && context
                .maps
                .iter()
                .all(|map| compatible(&self.mapping.user_maps, map)))
    }

    fn restored(&self, key: &str, data: &[u8]) -> Result<()> {
        if let Some(path) = &self.path {
            self.register(Snapshot::read(path)?, self.decode(key, data)?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::CacheWrite;
    use std::io::Cursor;

    fn output() -> process::Output {
        process::Output {
            status: crate::mock_command::exit_status(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn mapping(root: &Path, state_dir: &Path) -> MappedModules {
        let maps = vec![PathMap {
            from: root.to_owned(),
            to: r"X:\logical".into(),
        }];
        MappedModules {
            user_maps: maps.clone(),
            maps,
            state_dir: state_dir.to_owned(),
            uncacheable_import: false,
        }
    }

    #[test]
    fn opaque_mapping_policies_do_not_enable_relocation() {
        let root = Path::new(r"Q:\project");
        let flags = [
            "/c",
            "/std:c++20",
            "/FC",
            "/experimental:deterministic",
            r"/pathmap:Q:\project\=X:\logical\",
            "source.cpp",
        ]
        .map(OsString::from);
        let super::super::CompilerArguments::Ok(mut args) =
            super::super::msvc::parse_arguments(&flags, root, false)
        else {
            panic!("expected cacheable native arguments")
        };
        let basedirs = vec![b"q:/project/".to_vec()];
        let env = vec![("SCCACHE_DIR".into(), r"Q:\cache".into())];
        assert!(
            MappedModules::new(&args, root, &[], &basedirs)
                .unwrap()
                .is_none()
        );
        assert!(
            MappedModules::new(&args, root, &env, &basedirs)
                .unwrap()
                .is_some()
        );
        args.common_args.push("/d1trimfile:Q:\\project".into());
        assert!(
            MappedModules::new(&args, root, &env, &basedirs)
                .unwrap()
                .is_none()
        );
        args.common_args.pop();
        let pathmap = args
            .common_args
            .iter()
            .position(|arg| arg.to_str().is_some_and(|s| s.starts_with("/pathmap:")))
            .unwrap();
        args.common_args[pathmap] = r"/pathmap:Q:\project\=X:\one\,Q:\other\=X:\two\".into();
        assert!(
            MappedModules::new(&args, root, &env, &basedirs)
                .unwrap()
                .is_none()
        );
        args.common_args[pathmap] = r"/pathmap:Q:\project=X:\logical".into();
        assert!(
            MappedModules::new(&args, root, &env, &basedirs)
                .unwrap()
                .is_none()
        );
        args.common_args[pathmap] = flags[4].clone();
        args.common_args.push(OsString::from_wide(&[0xD800]));
        assert!(
            MappedModules::new(&args, root, &env, &basedirs)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn producer_context_is_not_identified_by_ifc_digest() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unit.ifc");
        fs::write(&path, b"identical IFC bytes").unwrap();
        let mut mapped = mapping(temp.path(), &temp.path().join("state"));
        let args = [
            "-DROOT=Q:\\original",
            "-IQ:\\original\\include",
            r"-pathmap:Q:\original\=X:\logical\",
            "-reference",
            "unit=Q:\\original\\unit.ifc",
        ]
        .map(OsString::from);
        let source_map = mapping(Path::new(r"Q:\original"), &mapped.state_dir);
        let normalized = source_map.arguments(&args);
        assert_eq!(normalized[0], args[0]);
        assert_eq!(normalized[4], "unit=X:\\logical\\unit.ifc");
        let meta = ModuleMetadata {
            path: Some(path.clone()),
            logical_path: Some(mapped.path(&path)),
            mapping: mapped.clone(),
            includes_prefix: "Note: including file:".into(),
            source_name: "unit.h".into(),
            uncacheable: false,
        };
        let first = meta.create("producer-one", &output()).unwrap();
        assert_eq!(
            mapped.imports(std::slice::from_ref(&path)).unwrap()[0].1,
            first
        );
        let second = meta.create("producer-two", &output()).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            mapped.imports(std::slice::from_ref(&path)).unwrap()[0].1,
            second
        );
        let prior = Snapshot::read(&path).unwrap().stamp;
        let written =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
        fs::write(&path, b"identical IFC bytes").unwrap();
        filetime::set_file_mtime(&path, written).unwrap();
        let current = Snapshot::read(&path).unwrap().stamp;
        assert_eq!(prior.id, current.id);
        assert_eq!(prior.written, current.written);
        assert!(
            mapped
                .imports(std::slice::from_ref(&path))
                .unwrap_err()
                .to_string()
                .contains("Stale")
        );
        meta.create("producer-two", &output()).unwrap();
        let written =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"identical IFC bytes").unwrap();
        filetime::set_file_mtime(&path, written).unwrap();
        assert!(mapped.imports(&[path]).is_err());
    }

    #[test]
    fn restoration_validates_context_and_registers_actual_file() {
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("producer");
        let b = temp.path().join("different receiver with spaces");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let source = a.join("unit.ifc");
        let target = b.join("unit.ifc");
        let bytes = b"cached IFC";
        fs::write(&source, bytes).unwrap();
        let producer = ModuleMetadata {
            path: Some(source),
            logical_path: Some(r"X:\logical\unit.ifc".into()),
            mapping: mapping(&a, &temp.path().join("producer-state")),
            includes_prefix: "Note: including file:".into(),
            source_name: "unit.h".into(),
            uncacheable: false,
        };
        let data = producer.create("producer-key", &output()).unwrap();
        let receiver = ModuleMetadata {
            path: Some(target.clone()),
            logical_path: producer.logical_path.clone(),
            mapping: mapping(&b, &temp.path().join("receiver-state")),
            includes_prefix: producer.includes_prefix.clone(),
            source_name: producer.source_name.clone(),
            uncacheable: false,
        };
        let entry = |bytes: &[u8]| {
            let mut entry = CacheWrite::new();
            entry
                .put_object("ifc", &mut Cursor::new(bytes), None)
                .unwrap();
            CacheRead::from(Cursor::new(entry.finish().unwrap())).unwrap()
        };
        assert!(
            receiver
                .validate("producer-key", &data, &mut entry(bytes))
                .unwrap()
        );
        assert!(
            receiver
                .validate("another-key", &data, &mut entry(bytes))
                .is_err()
        );
        assert!(
            receiver
                .validate("producer-key", b"{}", &mut entry(bytes))
                .is_err()
        );
        assert!(
            receiver
                .validate("producer-key", &data, &mut entry(b"corrupt IFC"))
                .is_err()
        );
        let mut warning = output();
        warning.stdout = b"unit.h\nwarning: compiler diagnostic\n".to_vec();
        let warned = producer.create("producer-key", &warning).unwrap();
        assert!(
            !receiver
                .validate("producer-key", &warned, &mut entry(bytes))
                .unwrap()
        );
        let mut future: serde_json::Value = serde_json::from_slice(&data).unwrap();
        future["version"] = 4.into();
        assert!(
            receiver
                .validate(
                    "producer-key",
                    &serde_json::to_vec(&future).unwrap(),
                    &mut entry(bytes)
                )
                .is_err()
        );
        fs::write(&target, bytes).unwrap();
        receiver.restored("producer-key", &data).unwrap();
        let mut mapped = receiver.mapping.clone();
        assert_eq!(
            mapped.imports(std::slice::from_ref(&target)).unwrap()[0].1,
            data
        );
        assert_eq!(mapped.extra_args().len(), 1);
        let key = Snapshot::read(&target).unwrap().key;
        fs::remove_file(OriginShard::new(&mapped.state_dir, &key).record_path(&key)).unwrap();
        assert!(
            mapped
                .imports(&[target])
                .unwrap_err()
                .to_string()
                .contains("Missing")
        );
        assert_eq!(fs::read_dir(b).unwrap().count(), 1);
    }

    #[test]
    fn identical_ifcs_keep_distinct_producer_mapping_contexts() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let mut expected = Vec::new();
        for index in 0..65 {
            let name = format!("provider-{index:02}");
            let logical = format!(r"X:\logical-{index:02}");
            let root = temp.path().join(&name);
            fs::create_dir(&root).unwrap();
            let path = root.join("unit.ifc");
            fs::write(&path, b"identical IFC bytes").unwrap();
            let mut mapped = mapping(&root, &state);
            mapped.user_maps[0].to = logical.into();
            mapped.maps = mapped.user_maps.clone();
            let producer = ModuleMetadata {
                path: Some(path.clone()),
                logical_path: Some(mapped.path(&path)),
                mapping: mapped,
                includes_prefix: "Note: including file:".into(),
                source_name: "unit.h".into(),
                uncacheable: false,
            };
            expected.push((path, producer.create(&name, &output()).unwrap()));
        }
        assert_eq!(
            Snapshot::read(&expected[0].0).unwrap().digest,
            Snapshot::read(&expected[1].0).unwrap().digest
        );
        let mut receiver = mapping(&temp.path().join("receiver"), &state);
        let actual = receiver
            .imports(
                &expected
                    .iter()
                    .map(|(path, _)| path.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(receiver.extra_args().len(), 65);
    }

    #[test]
    fn source_location_directives_and_inherited_maps_do_not_change_current_inputs() {
        let a = mapping(Path::new(r"Q:\first"), Path::new(r"Q:\state"));
        let mut b = mapping(Path::new(r"Q:\second"), Path::new(r"Q:\state"));
        let source_a = PathBuf::from(r"Q:\first\main.cpp");
        let source_b = PathBuf::from(r"Q:\second\main.cpp");
        let first = br#"#line 1 "Q:\\first\\main.cpp"
const char* literal = "Q:\\first\\data";
"#;
        let second = br#"#line 1 "Q:\\second\\main.cpp"
const char* literal = "Q:\\first\\data";
"#;
        assert_eq!(
            a.preprocessed_digest(first, Path::new(r"Q:\first"), &[source_a])
                .unwrap(),
            b.preprocessed_digest(
                second,
                Path::new(r"Q:\second"),
                std::slice::from_ref(&source_b)
            )
            .unwrap()
        );
        let synthetic = br#"#line 42 "Q:\\first\\fiction.cpp"
auto location = std::source_location::current();
"#;
        assert_ne!(
            a.preprocessed_digest(synthetic, Path::new(r"Q:\first"), &[])
                .unwrap(),
            b.preprocessed_digest(synthetic, Path::new(r"Q:\second"), &[])
                .unwrap()
        );
        let checksum = br#"#  pragma    checksum("Q:\\first\\fiction.cpp", "guid", "checksum")
"#;
        assert_ne!(
            a.preprocessed_digest(checksum, Path::new(r"Q:\first"), &[])
                .unwrap(),
            b.preprocessed_digest(checksum, Path::new(r"Q:\second"), &[])
                .unwrap()
        );
        b.maps.extend(a.maps);
        assert!(
            b.preprocessed_digest(checksum, Path::new(r"Q:\second"), &[])
                .is_err()
        );
        assert!(
            b.preprocessed_digest(synthetic, Path::new(r"Q:\second"), &[source_b])
                .is_err()
        );
        assert!(
            b.preprocessed_digest(b"", Path::new(r"Q:\second"), &[r"Q:\first\header.h".into()])
                .is_err()
        );
    }

    #[test]
    fn origin_index_evicts_old_records_within_a_shard() {
        let temp = tempfile::tempdir().unwrap();
        let shard = OriginShard::new(temp.path(), "ab01");
        shard.insert("ab01", b"first", 6).unwrap();
        shard.insert("ab02", b"second", 6).unwrap();
        assert!(!shard.record_path("ab01").exists());
        assert_eq!(fs::read(shard.record_path("ab02")).unwrap(), b"second");
    }

    #[test]
    fn overlapping_roots_must_have_consistent_translations() {
        let parent = PathMap {
            from: r"Q:\source".into(),
            to: r"X:\logical".into(),
        };
        assert!(!compatible(
            std::slice::from_ref(&parent),
            &PathMap {
                from: r"Q:\source\nested".into(),
                to: r"X:\logical".into()
            }
        ));
        assert!(compatible(
            &[parent],
            &PathMap {
                from: r"Q:\source\nested".into(),
                to: r"X:\logical\nested".into()
            }
        ));
        assert_eq!(
            mapped_path(
                &[PathMap {
                    from: r"Q:\source".into(),
                    to: r"X:\logical".into()
                }],
                Path::new(r"Q:\source-other\file")
            ),
            Path::new(r"Q:\source-other\file")
        );
    }
}
