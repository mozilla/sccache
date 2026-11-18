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

## Limitations

* Cache reuse requires matching absolute build paths, including when using
  shared cache storage. `/pathmap` does not enable reuse across checkouts.
* Compiler PDBs, precompiled headers, `/analyze`, `/ifcMap`, and
  `/translateInclude` are not supported for module caching. Use `/Z7` when
  caching builds with debug information.
* Remote cache storage is supported, but native MSVC module compilation is
  not distributed.
