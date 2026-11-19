# Caching ThinLTO backend compilations

With ThinLTO, `clang -flto=thin -c` only writes LLVM bitcode, and the expensive
part (optimization and code generation) happens at link time. sccache already
caches the `-c` step; it can also cache the code generation of each module, as
long as the linker runs it as a separate `clang` process.

Normally lld runs these backend jobs in-process, where sccache can't see them.
[Distributed ThinLTO (DTLTO)](https://llvm.org/docs/DTLTO.html) makes lld hand
every job to an external program, the *distributor*, as an ordinary command:

```text
clang -c <module>.o -fthinlto-index=<module>.thinlto.bc -o <module>.native.o [flags...]
```

sccache caches this command like any other compilation. Its statistics show up
as `LLVM IR`.

## What goes into the cache key

* the content of the bitcode module;
* the content of the index file passed with `-fthinlto-index=`. The index
  records a hash of every module the job imports functions from, so a change in
  any of them is a cache miss even if the module itself didn't change;
* the compiler and the other arguments, as for any compilation.

The *path* of the index file is not part of the key: lld names the files after
its process ID, so it differs on every link.

## Base directories

With [`SCCACHE_BASEDIRS`](Configuration.md), a build in another directory gets
the backend jobs from the cache as long as its bitcode also came from the cache:
the compile step then returns the bitcode built in the first directory, and the
backend jobs see the same modules. Bitcode compiled outside of sccache records
the absolute source path, even with `-ffile-prefix-map`, so its backend jobs
miss in every other directory.

The index stores the module paths the way the linker got them. Paths relative
to the build directory, which CMake uses, are the same in every checkout;
absolute ones make every other directory miss.

## Requirements

* clang and lld from the same LLVM release, 21 or newer. LLVM only supports
  DTLTO for ELF and COFF targets.
* Static libraries built as thin archives (`llvm-ar` with the `T` modifier). lld
  extracts members of regular archives to files with per-link names, and those
  names end up in the index, so every link would be a cache miss.
* A distributor. LLVM doesn't install one; it is a small script that reads the
  job description lld writes and runs the jobs. See
  [`tests/integration/thinlto/distributor.py`](../tests/integration/thinlto/distributor.py)
  for one that runs them in parallel behind a launcher such as sccache.

## Setup

lld calls the distributor as `<distributor> [arguments...] <jobs.json>`. With the
distributor above, pass sccache as its argument:

```text
-fuse-ld=lld
-fthinlto-distributor=/usr/bin/python3
-Xthinlto-distributor=/path/to/distributor.py
-Xthinlto-distributor=/path/to/sccache
```

lld 22 and newer can also put sccache in front of the backend commands itself,
with any distributor:

```text
-Wl,--thinlto-remote-compiler=/path/to/sccache
-Wl,--thinlto-remote-compiler-prepend-arg=/path/to/clang
```

With CMake:

```sh
cmake \
  -DCMAKE_C_COMPILER_LAUNCHER=sccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=sccache \
  -DCMAKE_CXX_FLAGS="-flto=thin" \
  -DCMAKE_AR="$(command -v llvm-ar)" \
  -DCMAKE_CXX_ARCHIVE_CREATE="<CMAKE_AR> qcT <TARGET> <LINK_FLAGS> <OBJECTS>" \
  -DCMAKE_CXX_ARCHIVE_APPEND="<CMAKE_AR> qT <TARGET> <LINK_FLAGS> <OBJECTS>" \
  -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -fthinlto-distributor=$(command -v python3) \
    -Xthinlto-distributor=/path/to/distributor.py -Xthinlto-distributor=$(command -v sccache)" \
  ...
```

Build systems that run the backend jobs themselves, with
`-Wl,--thinlto-index-only` and a separate `clang -c -fthinlto-index=...` per
module, can wrap those commands with sccache directly.

## Limitations

* Backend jobs are never sent to sccache-dist: the modules a job imports from
  are read by the paths stored in the index, and they are not shipped.
* `-fthinlto-index` is not cached when passed through `-Xclang`, or together
  with a source file (clang rejects that anyway).
* lld's own ThinLTO cache (`--thinlto-cache-dir`) is unrelated to this, and GCC's
  LTO is not supported.
* LLVM does not guarantee that DTLTO generates the same code as in-process
  ThinLTO, so switching between the two may change the binary.
