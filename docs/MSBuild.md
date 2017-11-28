**Note**: Using `sccache` with `msbuild` is not fully supported yet. Supporting
multiple inputs on one command line is the last remaining issue. See
https://github.com/mozilla/sccache/issues/107 for more information.

Instruct `msbuild` to use our own `cl.exe`:

    msbuild blah.sln /p:CLToolExe=cl.exe /p:CLToolPath=C:\tools

Where `C:\tools` contains `cl.exe`, the renamed `sccache.exe`.

Since there is no way to tell `msbuild` to run `sccache cl [args...]`, `sccache`
must determine which compiler to immitate based upon the name of the executable
alone. Thus, the `sccache` executable must be renamed to `cl.exe`.

## Debugging

If you want to see what the `sccache` server is doing, start it up manually
within a Visual Studio command prompt (`cl.exe` will not find the DLLs it needs
otherwise):

    set SCCACHE_LOG_LEVEL=info
    set SCCACHE_START_SERVER=1
    set SCCACHE_NO_DAEMON=1
    sccache

## Cache Misses

Common causes of cache misses are detailed in this section.

### Multiple source files per command line

`msbuild` calls `cl.exe` with multiple source files. This feature is not yet
supported by `sccache` due to its internal architecture and is the last
remaining hurdle for full support.

### PDB output

Invididual compilations are not allowed to output to a shared PDB. This is the
default behavior when `/Zi` (Program Databse) or `/ZI` (Program Database for
Edit and Continue) is specified.

Instead, you must use `/Z7` where the debug information is embedded in the
object file itself. The main trade off is that you cannot use Minimal Rebuild
(`/Gm`) or Edit and Continue.

See also: https://docs.microsoft.com/en-us/cpp/build/reference/z7-zi-zi-debug-information-format
