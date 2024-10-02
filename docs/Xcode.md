# Using `sccache` with Xcode

It is possible to use `sccache` with Xcode with some setup.

### Running the daemon
Before building, you need to run the daemon outside of Xcode. This needs to be done because if `sccache` invocation happens to implicitly start the server daemon, the Xcode build will hang on the `sccache` invocation, waiting for the process to idle timeout.

You can do this in another terminal windows by calling
```sh
SCCACHE_LOG=info SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 sccache
```

Or by setting it up in a `launchd` configuration, perhaps as `~/Library/LaunchAgents/sccache.plist` (note the paths in the plist):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>sccache.server</string>
    <key>ProgramArguments</key>
    <array>
      <string>/path/to/sccache</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SCCACHE_START_SERVER</key>
        <string>1</string>
        <key>SCCACHE_NO_DAEMON</key>
        <string>1</string>
        <key>SCCACHE_IDLE_TIMEOUT</key>
        <string>0</string>
        <key>SCCACHE_LOG</key>
        <string>info</string>
    </dict>

    <key>StandardOutPath</key>
    <string>/tmp/sccache.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/sccache.log</string>

  </dict>
</plist>
```

### Setting it up for `xcodebuild`

Xcode seems to support barely documented `C_COMPILER_LAUNCHER` attribute, for 
having a custom launcher program.

Then you can invoke `xcodebuild` like so
```sh
xcodebuild C_COMPILER_LAUNCHER=sccache
           CLANG_ENABLE_MODULES=NO
           COMPILER_INDEX_STORE_ENABLE=NO
           CLANG_USE_RESPONSE_FILE=NO
```
Where the additional arguments are for disabling some features that `sccache` can't cache currently.

These build settings can also be put in a xcconfig file, like `sccache.xcconfig`
```
C_COMPILER_LAUNCHER=sccache
CLANG_ENABLE_MODULES=NO
COMPILER_INDEX_STORE_ENABLE=NO
CLANG_USE_RESPONSE_FILE=NO
```
Which can then be invoked with
```sh
xcodebuild -xcconfig sccache.xcconfig
```


### Setting it up for `cmake` Xcode generator
While `cmake` has the convenient `CMAKE_<LANG>_COMPILER_LAUNCHER` for prepending tools like `sccache`, it is not supported for the Xcode generator.

But you can configuring it directly with something like
```cmake

# This bit before the first `project()`, as the COMPILER_LAUNCHER variables are read in then
if(DEFINED CCACHE)
    find_program(CCACHE_EXE ${CCACHE} REQUIRED)
    if(NOT CMAKE_GENERATOR STREQUAL "Xcode")
        # Support for other generators should work with these
        set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_EXE}")
        set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXE}")
    else()
        # And this should work for Xcode generator
        set(CMAKE_XCODE_ATTRIBUTE_C_COMPILER_LAUNCHER ${CCACHE_EXE})
        set(CMAKE_XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES "NO")
        set(CMAKE_XCODE_ATTRIBUTE_COMPILER_INDEX_STORE_ENABLE "NO")
        set(CMAKE_XCODE_ATTRIBUTE_CLANG_USE_RESPONSE_FILE "NO")
    endif()
endif()
```
Then configuring with `-DCCACHE=sccache` should work on all generators.



