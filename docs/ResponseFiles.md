# Response Files

Response files are a way for compilers to accept arguments that would otherwise overflow the character limit in the command line. [On Windows in particular](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation), the character limit per command is 8191 characters. These files can contain additional options that the compiler will read and process as if they were provided in the original command. Each compiler that supports response files has different formats/expectations and implementations. Support for response files are also re-implemented per compiler by sccache so it can cache compilations accurately. There is currently support for response files on the gcc and msvc implementations in sccache.

## GCC

As defined by the [gcc docs](https://gcc.gnu.org/onlinedocs/gcc-4.6.3/gcc/Overall-Options.html#Overall-Options):

1. Options in a response file are inserted in-place in the original command line. If the file does not exist or cannot be read, the option will be treated literally, and not removed.
2. Options in a response file are separated by whitespace.
3. Single or double quotes can be used to include whitespace in an option.
4. Any character (including a backslash) may be included by prefixing the character to be included with a backslash (e.g. `\\`, `\?`, `\@`, etc).
5. The response file may itself contain additional @file options; any such options will be processed recursively.

Implementation details:
- The gcc implementation in sccache supports all of these **except** #3. If a response file contains **any** quotations (`"` or `'`), the @file arg is treated literally and not removed (and its content not processed).
- Additionally, sccache will not expand concatenated arguments such as `-include@foo` (see [#150](https://github.com/mozilla/sccache/issues/150#issuecomment-318586953) for more on this).
- Recursive files are processed depth-first; when an @file option is encountered, its contents are read and each option is evaluated in-place before continuing to options following the @file.

## MSVC

Per the [MSVC docs](https://learn.microsoft.com/en-us/cpp/build/reference/cl-command-files?view=msvc-170):

1. The contents of a response file are inserted in-place in the original command.
2. Response files can contain multiple lines of options, but each option must begin and end on the same line.
3. Backslashes (`\`) cannot be used to combine options across multiple lines.
4. The `/link` directive has special treatment:
    1. Entering an @file: if the `/link` option is provided prior to an `@file` in the command line, the `/link` directive does not affect any options within the `@file`.
    2. Newlines: A `/link` directive provided in an `@file` on one line does not affect the next line.
    3. Exiting an @file: A `/link` directive on the final line of a response file does not affect options following the `@file` option in the command line.
5. A response file cannot contain additional `@file` options, they are not recursive. (found in a [separate doc](https://learn.microsoft.com/en-us/cpp/build/reference/at-specify-a-compiler-response-file?view=msvc-170))
6. (implied) options can be wrapped in double-quotes (`"`), which allows whitespace to be preserved within the option

The msvc implementation in sccache supports all of these **except** #4, because sccache doesn't accept the `/link` directive. 

Additionally, because `msbuild` generates response files using an encoding other than `utf-8`, all text files under the [WHATWG encoding standard](https://encoding.spec.whatwg.org/) are supported. This includes both `utf-8` and `utf-16`.
