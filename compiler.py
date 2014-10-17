# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Compiler helpers hiding all the details of how to parse command lines,
# run the preprocessor and compile.

import hashlib
import os
import subprocess
import tempfile
import which


class NotACompilationError(RuntimeError):
    pass

class CannotCacheError(RuntimeError):
    pass


class Compiler(object):
    '''
    Base class for compiler helpers. Subclasses must implement the following
    methods:
        parse_arguments: parse a command line and return a dict containing
            all necessary information for preprocessing and compilation. This
            dict is meant to be passed to the two other methods. As a contract
            with the caller, this dict also contains a 'output' item which
            value is a dict associating keys to output files (a compilation
            can have more than one output)
        preprocess: return the preprocessor output corresponding to the command
            line in the form of a tuple return_code, stdout_buf, stderr_buf
            (with the preprocessor output in stdout_buf)
        compile: run the compilation corresponding to the command line,
            possibly using the preprocessor output directly. Returns a tuple
            return_code, stdout_buf, stderr_buf, may_cache.
    '''
    def __init__(self, executable):
        self.executable = executable
        self.mtime = os.path.getmtime(executable)

        h = hashlib.new('sha1')
        h.update(open(executable, 'rb').read())
        self.digest = h.hexdigest()

    def parse_arguments(self, args):
        raise NotImplementedError('%s.prepare_arguments is not implemented' %
            self.__class__.__name__)

    def preprocess(self, parsed_args, cwd=None):
        raise NotImplementedError('%s.preprocess is not implemented' %
            self.__class__.__name__)

    def compile(self, preprocessor_output, parsed_args, cwd=None):
        raise NotImplementedError('%s.compile is not implemented' %
            self.__class__.__name__)

    _compilers = {}

    @staticmethod
    def from_path(executable, cwd=None):
        '''
        Returns a Compiler-derived object for the given executable path
        (absolute or relative to the given cwd).
        '''
        if os.sep in executable or (os.altsep and os.altsep in executable):
            executable = os.path.join(cwd, executable)
            if not os.path.exists(executable):
                return None

        if not os.path.exists(executable):
            try:
                executable = which.which(executable)
            except which.WhichError:
                return None

        # Use a cache of instances.
        if executable in Compiler._compilers:
            compiler = Compiler._compilers[executable]
            if os.path.getmtime(executable) == compiler.mtime:
                return compiler

        compiler = None

        # Try to detect the compiler type
        fh, path = tempfile.mkstemp(suffix='.c')
        with os.fdopen(fh, 'w') as f:
            f.write(
                '#if defined(_MSC_VER)\n'
                'msvc\n'
                '#elif defined(__clang__)\n'
                'clang\n'
                '#elif defined(__GNUC__)\n'
                'gcc\n'
                '#endif\n'
            )
        # Try preprocessing the above temporary file
        try:
            out = subprocess.check_output([executable, '-E', path],
                stderr=open(os.devnull, 'w'))
        except:
            out = ''
        finally:
            os.remove(path)

        lines = out.splitlines()
        if 'clang' in lines:
            compiler = ClangCompiler(executable)
        elif 'gcc' in lines:
            compiler = GCCCompiler(executable)
        elif 'msvc' in lines:
            compiler = MSVCCompiler(executable)

        if compiler:
            Compiler._compilers[executable] = compiler
        return compiler


class GCCCompiler(Compiler):
    '''
    Compiler implementation for GCC
    '''

    FILE_TYPES = {
        '.c': 'cpp-output',
        '.cc': 'c++-cpp-output',
        '.cpp': 'c++-cpp-output',
        '.cxx': 'c++-cpp-output',
    }

    ARGS_WITH_VALUE = set([
        '--param', '-A', '-D', '-F', '-G', '-I', '-L', '-MF',
        '-MQ', '-U', '-V', '-Xassembler', '-Xlinker',
        '-Xpreprocessor', '-aux-info', '-b', '-idirafter',
        '-iframework', '-imacros', '-imultilib', '-include',
        '-install_name', '-iprefix', '-iquote', '-isysroot',
        '-isystem', '-iwithprefix', '-iwithprefixbefore',
        '-u',
    ])

    def parse_arguments(self, args):
        # TODO: Handle more flags. This is enough to build Firefox.

        # Arguments common to preprocessor and compilation invocations.
        common_args = []
        # Arguments for the preprocessor only
        preprocessor_args = []

        input = ()
        output = None
        split_dwarf = False
        target = None
        need_explicit_target = False
        compilation = False
        iter_args = iter(args)
        for arg in iter_args:
            if arg == '-c':
                compilation = True
            elif arg == '-o':
                output = iter_args.next()
            elif arg == '-gsplit-dwarf':
                split_dwarf = True
                common_args.append(arg)
            elif arg in self.ARGS_WITH_VALUE:
                # All these flags take a value.
                if arg in ('-MF', '-MQ'):
                    preprocessor_args.append(arg)
                    preprocessor_args.append(iter_args.next())
                else:
                    common_args.append(arg)
                    common_args.append(iter_args.next())
            elif arg == '-MT':
                # Target used for depfiles. If given, we want to keep it
                # instead of passing the output.
                target = iter_args.next()
            elif arg == '-fprofile-use' or arg.startswith('@'):
                # Flags we can't handle.
                raise CannotCacheError()
            else:
                if arg in ('-M', '-MM', '-MD', '-MMD'):
                    # If one of the above options is on the command line, we'll
                    # need -MT on the preprocessor command line, whether it's
                    # been passed already or not
                    need_explicit_target = True
                    preprocessor_args.append(arg)
                elif arg.startswith('-') and len(arg) != 1:
                    common_args.append(arg)
                else:
                    input += (arg,)

        # We only support compilation with a given output file (not stdout) and
        # only one input (not stdin)
        if not compilation:
            raise NotACompilationError()
        if not output or len(input) != 1 or input[0] == '-':
            raise CannotCacheError()

        input = input[0]
        extension = os.path.splitext(input)[1]
        # When compiling from the preprocessed output given as stdin, we need
        # to give its file type.
        if extension not in GCCCompiler.FILE_TYPES:
            raise CannotCacheError()

        if need_explicit_target:
            preprocessor_args.extend(['-MT', target or output])

        output = { 'obj': output }

        if split_dwarf:
            output['dwo'] = os.path.splitext(output['obj'])[0] + '.dwo'

        return {
            'input': input,
            'extension': extension,
            'output': output,
            'preprocessor_args': preprocessor_args,
            'common_args': common_args,
        }

    def preprocess(self, parsed_args, cwd=None):
        # Preprocess over a pipe.
        proc = subprocess.Popen([self.executable, '-E', parsed_args['input']]
            + parsed_args['preprocessor_args'] + parsed_args['common_args'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        preprocessed, stderr = proc.communicate()
        ret = proc.wait()
        return ret, preprocessed, stderr

    def compile(self, preprocessor_output, parsed_args, cwd=None):
        # Compile from the preprocessor output
        proc = subprocess.Popen([self.executable, '-c', '-x',
            GCCCompiler.FILE_TYPES[parsed_args['extension']], '-', '-o',
            parsed_args['output']['obj']] + parsed_args['common_args'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd)

        stdout, stderr = proc.communicate(preprocessor_output)
        ret = proc.wait()
        return ret, stdout, stderr, True


class ClangCompiler(GCCCompiler):
    '''
    Compiler implementation for Clang
    '''

    ARGS_WITH_VALUE = GCCCompiler.ARGS_WITH_VALUE | set([
        '-arch',
    ])

    def compile(self, preprocessor_output, parsed_args, cwd=None):
        # Clang needs a temporary file for compilation, otherwise debug info
        # doesn't have a reference to the input file.
        fh, path = tempfile.mkstemp(suffix=parsed_args['extension'])
        with os.fdopen(fh, 'w') as f:
            f.write(preprocessor_output)
        try:
            proc = subprocess.Popen([self.executable, '-c', path, '-o',
                parsed_args['output']['obj']] + parsed_args['common_args'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)

            stdout, stderr = proc.communicate()
            ret = proc.wait()
        finally:
            os.remove(path)

        if ret and any(arg.startswith('-Werror')
                for arg in parsed_args['common_args']):
            # Sadly, clang tries to be smart with warning, and may emit more
            # of them when compiling preprocessed output, which can lead to
            # -Werror triggering failures. So try again if it did fail.
            proc = subprocess.Popen([self.executable, '-c', parsed_args['input'],
                '-o' + parsed_args['output']['obj']] + parsed_args['common_args'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)

            stdout, stderr = proc.communicate()
            ret = proc.wait()

        return ret, stdout, stderr, True


class MSVCCompiler(Compiler):
    '''
    Compiler implementation for MSVC

    This adds support for a non standard "-deps[depfile]" option to output the
    Make dependencies like GCC does with the -MP -MF flags. Note the lack of
    space between -deps and the depfile path, like e.g. -Fo[output]. This
    allows the option to be passed on an unwrapped cl.exe command without
    erroring out (it just warns about the unknown option).
    '''

    def __init__(self, executable):
        Compiler.__init__(self, executable)
        # MSVC localizes its output, and we need to parse it for -showIncludes.
        self._includes_prefix = self._find_includes_prefix()
        if not self._includes_prefix:
            raise RuntimeError('Cannot find -showIncludes prefix')

    def _find_includes_prefix(self):
        # Find the prefix for the -showIncludes output.
        fh, path = tempfile.mkstemp(suffix='.c')
        with os.fdopen(fh, 'w') as f:
            f.write('#include <stdio.h>\n')
        try:

            out = subprocess.check_output([self.executable, '-c', '-nologo',
                '-Fonul', '-showIncludes', path], stderr=subprocess.STDOUT)
            for line in out.splitlines():
                line = line.split(' ')
                if line and line[-1].endswith('stdio.h'):
                    for i in range(len(line) - 1, -1, -1):
                        if os.path.exists(' '.join(line[i:])):
                            return ' '.join(line[:i])
                    l = line.split()

            return None
        finally:
            os.remove(path)

    def parse_arguments(self, args):
        # TODO: Handle more flags. This is enough to build Firefox.
        # Arguments common to preprocessor and compilation invocations.
        common_args = []

        input = ()
        output = None
        debug_info = False
        pdb = None
        compilation = False
        depfile = None
        iter_args = iter(args)
        for arg in iter_args:
            if arg == '-c':
                compilation = True
            elif arg.startswith('-Fo'):
                output = arg[3:]
            elif arg in ('-FI',):
                # All these flags take a value.
                common_args.append(arg)
                common_args.append(iter_args.next())
            elif arg.startswith('-deps'):
                depfile = arg[5:]
            elif arg == '-showIncludes' or arg.startswith('@'):
                # Flags we can't handle.
                raise CannotCacheError()
            elif arg == '-Zi':
                debug_info = True
                common_args.append(arg)
            elif arg.startswith('-Fd'):
                pdb = arg[3:]
                common_args.append(arg)
            elif arg[:3] in ('-FA', '-Fa', '-Fe', '-Fm', 'Fp', '-FR',
                             '-Fx'):
                # Flags we can't handle as they output more files and we can
                # only cache one at the moment. TODO: handle more multi-file
                # outputs.
                raise CannotCacheError()
            else:
                if arg.startswith('-') and len(arg) != 1:
                    common_args.append(arg)
                else:
                    input += (arg,)

        # We only support compilation with a given output file (not stdout) and
        # only one input (MSVC doesn't support stdin as input, so no need to
        # check for that)
        if not compilation:
            raise NotACompilationError()
        if not output or len(input) != 1:
            raise CannotCacheError()

        input = input[0]
        extension = os.path.splitext(input)[1]

        output = { 'obj': output }

        # -Fd is not taken into account unless -Zi is given
        if debug_info:
            # -Zi without -Fd defaults to vcxxx.pdb (where xxx depends on the
            # MSVC version), and that's used for all compilations with the same
            # working directory. We can't cache such a pdb.
            if not pdb:
                raise CannotCacheError()
            output['pdb'] = pdb

        return {
            'input': input,
            'extension': extension,
            'output': output,
            'depfile': depfile,
            'common_args': common_args,
        }


    def preprocess(self, parsed_args, cwd=None):
        showIncludes = ['-showIncludes'] if parsed_args['depfile'] else []

        # Preprocess over a pipe.
        proc = subprocess.Popen([self.executable, '-E', parsed_args['input'],
            '-nologo'] + showIncludes + parsed_args['common_args'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        preprocessed, stderr = proc.communicate()
        ret = proc.wait()

        # Parse the output to extract dependency info.
        if showIncludes:
            from win32util import normcase
            from makeutil import Makefile
            mk = Makefile()
            rule = mk.create_rule([parsed_args['output']['obj']])
            rule.add_dependencies([normcase(parsed_args['input'])])
            filtered_stderr = ''
            for line in stderr.splitlines(True):
                if line.startswith(self._includes_prefix):
                    dep = normcase(line[len(self._includes_prefix):].strip())
                    if ' ' not in dep:
                        rule.add_dependencies([dep])
                else:
                    filtered_stderr += line
            depfile = parsed_args['depfile']
            if cwd:
                depfile = os.path.join(cwd, depfile)
            with open(depfile, 'w') as f:
                mk.dump(f)
            stderr = filtered_stderr

        return ret, preprocessed, stderr

    def compile(self, preprocessor_output, parsed_args, cwd=None):
        # MSVC doesn't read anything from stdin, so it needs a temporary file
        # as input.
        may_cache = True
        if 'pdb' in parsed_args['output']:
            pdb = parsed_args['output']['pdb']
            pdb = os.path.join(cwd, pdb) if cwd else pdb
            # If the pdb exists, we don't know if it's shared with another
            # compilation, and if it is, we can't cache. Sadly, this is racy.
            if os.path.exists(pdb):
                may_cache = False

        fh, path = tempfile.mkstemp(suffix=parsed_args['extension'])
        with os.fdopen(fh, 'w') as f:
            f.write(preprocessor_output)
        try:
            proc = subprocess.Popen([self.executable, '-c', path,
                '-Fo' + parsed_args['output']['obj']] + parsed_args['common_args'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
            stdout, stderr = proc.communicate()
            ret = proc.wait()
            # Replace all occurrences of the temporary file name with the
            # original input file name in both stdout and stderr.
            tmpname = os.path.basename(path)
            inputname = os.path.basename(parsed_args['input'])
            stdout = stdout.replace(tmpname, inputname)
            stderr = stderr.replace(tmpname, inputname)
        finally:
            os.remove(path)

        if ret:
            # Sadly, MSVC preprocessor output is such that it sometimes fails to
            # compile. So try again if it did fail.
            proc = subprocess.Popen([self.executable, '-c', parsed_args['input'],
                '-Fo' + parsed_args['output']['obj']] + parsed_args['common_args'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
            stdout, stderr = proc.communicate()
            ret = proc.wait()

        return ret, stdout, stderr, may_cache
