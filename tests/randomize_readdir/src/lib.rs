// Copyright 2024 Mozilla Foundation
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

use ctor::ctor;
use libc::{c_char, c_int, c_void, dirent, dirent64, dlsym, DIR, RTLD_NEXT};
use once_cell::sync::OnceCell;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::RwLock;

type Opendir = unsafe extern "C" fn(dirname: *const c_char) -> *mut DIR;
type Fdopendir = unsafe extern "C" fn(fd: c_int) -> *mut DIR;
type Readdir = unsafe extern "C" fn(dirp: *mut DIR) -> *mut dirent;
type Readdir64 = unsafe extern "C" fn(dirp: *mut DIR) -> *mut dirent64;
type Closedir = unsafe extern "C" fn(dirp: *mut DIR) -> c_int;

struct DirentIterator<Dirent> {
    entries: Vec<Dirent>,
    index: usize,
}

impl<Dirent> Iterator for DirentIterator<Dirent> {
    type Item = *mut Dirent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.entries.len() {
            return None;
        }

        let ptr = &mut self.entries[self.index];
        self.index += 1;
        Some(ptr)
    }
}

struct ReaddirState {
    iter: Option<DirentIterator<dirent>>,
    iter64: Option<DirentIterator<dirent64>>,
}

struct State {
    opendir: Opendir,
    fdopendir: Fdopendir,
    readdir: Readdir,
    readdir64: Readdir64,
    closedir: Closedir,

    dirs: RwLock<HashMap<usize, ReaddirState>>,
}

impl State {
    fn new_opendir(&self, dirp: *mut DIR) {
        self.dirs.write().expect("lock poisoned").insert(
            dirp as usize,
            ReaddirState {
                iter: None,
                iter64: None,
            },
        );
    }

    fn wrapped_readdir_inner<Dirent, GetIter, Readdir>(
        &self,
        dirp: *mut DIR,
        get_iter: GetIter,
        readdir: Readdir,
    ) -> *mut Dirent
    where
        Dirent: Copy,
        GetIter: FnOnce(&mut ReaddirState) -> &mut Option<DirentIterator<Dirent>>,
        Readdir: Fn() -> *mut Dirent,
    {
        self.dirs
            .write()
            .expect("lock poisoned")
            .get_mut(&(dirp as usize))
            .map(|dirstate| {
                let iter = get_iter(dirstate);
                if iter.is_none() {
                    let mut entries = Vec::new();

                    loop {
                        let entry = readdir();
                        if entry.is_null() {
                            break;
                        }

                        entries.push(unsafe { *entry });
                    }

                    entries.shuffle(&mut thread_rng());

                    *iter = Some(DirentIterator { entries, index: 0 })
                }

                iter.as_mut().unwrap().next()
            })
            .flatten()
            .unwrap_or(std::ptr::null_mut())
    }

    fn wrapped_readdir(&self, dirp: *mut DIR) -> *mut dirent {
        self.wrapped_readdir_inner(
            dirp,
            |dirstate| &mut dirstate.iter,
            || unsafe { (self.readdir)(dirp) },
        )
    }

    fn wrapped_readdir64(&self, dirp: *mut DIR) -> *mut dirent64 {
        self.wrapped_readdir_inner(
            dirp,
            |dirstate| &mut dirstate.iter64,
            || unsafe { (self.readdir64)(dirp) },
        )
    }
}

static STATE: OnceCell<State> = OnceCell::new();

fn load_next<Prototype: Copy>(sym: &[u8]) -> Prototype {
    unsafe {
        let sym = CStr::from_bytes_with_nul(sym).expect("invalid c-string literal");
        let sym = dlsym(RTLD_NEXT, sym.as_ptr());
        if sym.is_null() {
            panic!("failed to load libc function pointer");
        }

        *(&sym as *const *mut c_void as *const Prototype)
    }
}

#[ctor]
fn init() {
    // Force loading on module init.
    let opendir = load_next::<Opendir>(b"opendir\0");
    let fdopendir = load_next::<Fdopendir>(b"fdopendir\0");
    let readdir = load_next::<Readdir>(b"readdir\0");
    let readdir64 = load_next::<Readdir64>(b"readdir64\0");
    let closedir = load_next::<Closedir>(b"closedir\0");

    _ = STATE.get_or_init(|| State {
        opendir,
        fdopendir,
        readdir,
        readdir64,
        closedir,
        dirs: RwLock::new(HashMap::new()),
    });
}

#[no_mangle]
pub extern "C" fn opendir(dirname: *const c_char) -> *mut DIR {
    let state = STATE.wait();

    let dirp = unsafe { (state.opendir)(dirname) };
    if !dirp.is_null() {
        state.new_opendir(dirp);
    }

    dirp
}

#[no_mangle]
pub extern "C" fn fdopendir(dirfd: c_int) -> *mut DIR {
    let state = STATE.wait();

    let dirp = unsafe { (state.fdopendir)(dirfd) };
    if !dirp.is_null() {
        state.new_opendir(dirp);
    }

    dirp
}

#[no_mangle]
pub extern "C" fn readdir(dirp: *mut DIR) -> *mut dirent {
    STATE.wait().wrapped_readdir(dirp)
}

#[no_mangle]
pub extern "C" fn readdir64(dirp: *mut DIR) -> *mut dirent64 {
    STATE.wait().wrapped_readdir64(dirp)
}

#[no_mangle]
pub extern "C" fn closedir(dirp: *mut DIR) -> c_int {
    let state = STATE.wait();

    state
        .dirs
        .write()
        .expect("lock poisoned")
        .remove(&(dirp as usize));

    unsafe { (state.closedir)(dirp) }
}
