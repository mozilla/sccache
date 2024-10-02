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
When you override the `CC` variable for `xcodebuild`, it seems to always escape the spaces, so its not enough to just set it, but we need a wrapper script, something like

```sh
echo "#\!/bin/sh\nsccache $(xcrun -f cc) \$@" > wrapper.sh
chmod +x wrapper.sh
```
(YMMV if you need to select another sdk or toolchain for the xcrun)

Then you can invoke `xcodebuild` like so
```sh
xcodebuild CC="$(pwd)/wrapper.sh"
           CLANG_ENABLE_MODULES=NO
           COMPILER_INDEX_STORE_ENABLE=NO
```
Where the additional arguments are for disabling some features that `sccache` can't cache currently.

These build settings can also be put in a xcconfig file, like `sccache.xcconfig`
```
CC=$(SRCROOT)/wrapper.sh
CLANG_ENABLE_MODULES=NO
COMPILER_INDEX_STORE_ENABLE=NO
```
Which can then be invoked with
```sh
xcodebuild -xcconfig sccache.xcconfig
```


### Setting it up for `cmake` Xcode generator
While `cmake` has the convenient `CMAKE_<LANG>_COMPILER_LAUNCHER` for prepending tools like `sccache`, it is not supported for the Xcode generator.

It can be then integrated with having a template file for the wrapper script, `launcher.sh.in`:
```sh
#!/bin/sh
exec "${CCACHE_EXE}" "${LAUNCHER_COMPILER}" "$@"
```

And then configuring it something like
```cmake

# This bit before the first `project()`, as the COMPILER_LAUNCHER variables are read in then
if(DEFINED CCACHE)
	find_program(CCACHE_EXE ${CCACHE} REQUIRED)
	if(NOT CMAKE_GENERATOR STREQUAL "Xcode")
		# Support for other generators should work with these
		set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_EXE}")
		set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXE}")
	endif()
endif()

# .. your project stuff ..

# This bit needs to be after the first `project()` call, to have valid `CMAKE_C_COMPILER` variable.
# Alternatively in a file included with CMAKE_PROJECT_INCLUDE
if(DEFINED CCACHE)
	if(CMAKE_GENERATOR STREQUAL "Xcode")
		set(LAUNCHER_COMPILER ${CMAKE_C_COMPILER})
		configure_file(${CMAKE_CURRENT_LIST_DIR}/launcher.sh.in launcher-cc.sh)
		execute_process(COMMAND chmod a+rx
		"${CMAKE_CURRENT_BINARY_DIR}/launcher-cc.sh")
		set(CMAKE_XCODE_ATTRIBUTE_CC "${CMAKE_CURRENT_BINARY_DIR}/launcher-cc.sh")
		set(CMAKE_XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES "NO")
		set(CMAKE_XCODE_ATTRIBUTE_COMPILER_INDEX_STORE_ENABLE "NO")
	endif()
endif()
```
Then configuring with `-DCCACHE=sccache` should work on all generators.



