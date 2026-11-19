# Using sccache with MSVC C++20 modules

## Named modules and header units

From a Visual Studio Developer Command Prompt, run `cl` through `sccache`.
Use `/c` and `/std:c++20` (or later). If you need debug information, use `/Z7`
instead of `/Zi` or `/ZI`. Specify an explicit IFC filename with `/ifcOutput`
for each module interface, internal partition, or header unit you build.

Build a named module before compiling a source file that imports it:

```bat
sccache cl /nologo /c /std:c++20 /EHsc /Z7 /interface math.ixx /ifcOutput math.ifc /Fomath.obj
sccache cl /nologo /c /std:c++20 /EHsc /Z7 main.cpp /reference math=math.ifc /Fomain.obj
```

For a header unit imported as `import "util.h";`, use:

```bat
sccache cl /nologo /c /std:c++20 /EHsc /Z7 /exportHeader /headerName:quote util.h /ifcOutput util.ifc /Foutil.obj
sccache cl /nologo /c /std:c++20 /EHsc /Z7 use.cpp /headerUnit:quote util.h=util.ifc /Fouse.obj
```

Supply any transitive `/reference` and `/headerUnit` mappings required by MSVC.

## Sharing a cache across checkout directories

By default, absolute paths must match, even with remote cache storage. To reuse
entries across different checkout paths, set `SCCACHE_BASEDIRS` to the local
project root and add `/FC`, `/experimental:deterministic`, and `/pathmap` to both
producer and importer commands:

```bat
cd /d "C:\first checkout"
set "SCCACHE_BASEDIRS=C:\first checkout"
set "SCCACHE_DIR=C:\sccache-cache"
sccache cl /nologo /c /std:c++20 /EHsc /Z7 /FC /experimental:deterministic ^
    /pathmap:"%SCCACHE_BASEDIRS%"\=X:\project\ /interface math.ixx /ifcOutput math.ifc /Fomath.obj
sccache cl /nologo /c /std:c++20 /EHsc /Z7 /FC /experimental:deterministic ^
    /pathmap:"%SCCACHE_BASEDIRS%"\=X:\project\ main.cpp /reference math=math.ifc /Fomain.obj
```

Apply the same flags to header-unit builds. On a second machine, set
`SCCACHE_BASEDIRS` to its own checkout path and keep the logical target
`X:\project` unchanged. The logical directory does not need to exist. Use the
same compiler, SDK, relative layout, flags, and input contents on both machines.

If sources and build outputs live under separate roots, pass a `/pathmap` for
each root and list both physical roots in `SCCACHE_BASEDIRS`, separated by `;`.
Use absolute, long Windows paths and a trailing backslash on both sides of
each `/pathmap`. The trailing backslashes keep MSVC from matching sibling
directory names with the same prefix.

For a shared backend, follow the backend's setup guide (for example,
[Redis](Redis.md)) and point both machines at the same cache. Set `SCCACHE_DIR`
to a writable local directory even when the shared backend is read-only. Restart any
running sccache server after changing these settings. Build once to populate the
cache, then build from a clean checkout and check `sccache --show-stats` for hits.

## Limitations

* With path mapping, build all imported IFCs through sccache with the same
  mapping policy. Do not copy IFCs between checkouts or use untracked prebuilt
  IFCs in this mode. If sccache reports missing or stale producer context, rerun
  the IFC producer commands before building the importers.
* If the path mapping or local cache directory does not meet the requirements
  above, sccache runs the compiler without caching.
* Compiler PDBs, precompiled headers, `/analyze`, `/ifcMap`, and
  `/translateInclude` are not supported for module caching. Use `/Z7` when
  caching builds with debug information. In mapped mode, an IFC built with
  compiler PDBs also makes its importers uncacheable.
* Remote cache storage is supported, but native MSVC module compilation is
  not distributed.
