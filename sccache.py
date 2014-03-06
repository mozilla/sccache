# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import httplib
import os
import subprocess
import sys
import time
import urllib2
import which
from collections import OrderedDict


if 'SCCACHE_NAMESERVER' in os.environ:
    from dns.resolver import Resolver, Cache
    resolver = Resolver(configure=False)
    resolver.cache = Cache()
    resolver.nameservers.append(os.environ['SCCACHE_NAMESERVER'])
    def dns_query(host):
        for rr in resolver.query(host):
            return rr.address
else:
    import socket
    def dns_query(host):
        for family, socktype, proto, canonname, sockaddr in \
                socket.getaddrinfo(host, 0):
            return sockaddr[0]


def WrapperFactory(parent_class):
    class WrapperConnection(parent_class):
        def connect(self):
            self.host = dns_query(self.host)
            parent_class.connect(self)

    return WrapperConnection

SCCacheHTTPConnection = WrapperFactory(httplib.HTTPConnection)
SCCacheHTTPSConnection = WrapperFactory(httplib.HTTPSConnection)

class SCCacheHTTPHandler(urllib2.HTTPHandler):
    def http_open(self, req):
        return self.do_open(SCCacheHTTPConnection, req)

class SCCacheHTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(SCCacheHTTPSConnection, req)

urllib2.install_opener(
    urllib2.build_opener(SCCacheHTTPHandler, SCCacheHTTPSHandler))

FILE_TYPES = {
    '.c': 'cpp-output',
    '.cc': 'c++-cpp-output',
    '.cpp': 'c++-cpp-output',
    '.cxx': 'c++-cpp-output',
}


class Bucket(object):
    def __init__(self):
        self._name = os.environ.get('SCCACHE_BUCKET', '')
        self._status = 0

    def get(self, key):
        self._status = -1
        if not self._name:
            return None
        # Doing this unconditionally makes builds not requiring it ~2 minutes slower.
        if 'BOTO_CONFIG' in os.environ:
            from boto.s3.connection import S3Connection
            from boto.utils import find_class
            fmt = find_class(S3Connection.DefaultCallingFormat)()
            url = 'http://%s%s' % (fmt.build_host(S3Connection.DefaultHost, self._name), fmt.build_path_base(self._name, key))
        else:
            url = 'http://%s.s3.amazonaws.com/%s' % (self._name, key)
        try:
            data = urllib2.urlopen(url).read()
            self._status = 200
            return CacheData(data) if data else None
        except urllib2.HTTPError as e:
            self._status = e.code
            return None
        except:
            return None

    def put(self, key, data):
        self._status = -1
        if not self._name:
            raise Exception('No bucket name')
        from boto.s3.connection import S3Connection
        from boto.exception import S3ResponseError
        try:
            if 'SCCACHE_NO_HTTPS' in os.environ:
                conn = S3Connection(port=80, is_secure=False,
                    https_connection_factory=(SCCacheHTTPConnection, ()))
            else:
                conn = S3Connection(
                    https_connection_factory=(SCCacheHTTPSConnection, ()))
            bucket = conn.get_bucket(self._name, validate=False)
            k = bucket.new_key(key)
            k.set_contents_from_string(data, headers={
                'x-amz-acl': 'public-read',
            })
        except S3ResponseError as e:
            self._status = e.status
            raise

    @property
    def status(self):
        return self._status

    @property
    def name(self):
        return self._name


class CacheData(object):
    def __init__(self, data=None, obj=None):
        assert bool(data) != bool(obj)
        self._data = data
        self._obj = obj

    def dump(self, output):
        with open(output, 'wb') as out:
            if self._obj:
                out.write(self._obj)
            else:
                import gzip
                from cStringIO import StringIO
                import shutil
                with gzip.GzipFile(mode='r',
                        fileobj=StringIO(self._data)) as obj:
                    shutil.copyfileobj(obj, out)

    @property
    def data(self):
        if not self._data:
            import gzip
            from cStringIO import StringIO
            data = StringIO()
            with gzip.GzipFile(mode='w', compresslevel=6, fileobj=data) as fh:
                fh.write(self._obj)
            self._data = data.getvalue()

        return self._data

    @classmethod
    def from_object(self, path):
        with open(path, 'rb') as fh:
            return CacheData(obj=fh.read())


def parse_arguments(command):
    program, args = command[0], command[1:]
    if not os.path.exists(program):
        try:
            program = which.which(program)
        except which.WhichError:
            return None

    reduced_args = []
    input = ()
    output = None
    target = None
    need_explicit_target = False
    compilation = False
    iter_args = iter(args)
    for arg in iter_args:
        if arg == '-c':
            compilation = True
        elif arg == '-o':
            output = iter_args.next()
        elif arg in ('--param', '-A', '-D', '-F', '-G', '-I', '-L', '-MF',
                     '-MQ', '-U', '-V', '-Xassembler', '-Xlinker',
                     '-Xpreprocessor', '-aux-info', '-b', '-idirafter',
                     '-iframework', '-imacros', '-imultilib', '-include',
                     '-install_name', '-iprefix', '-iquote', '-isysroot',
                     '-isystem', '-iwithprefix', '-iwithprefixbefore',
                     '-u'):
            reduced_args.append(arg)
            reduced_args.append(iter_args.next())
        elif arg == '-MT':
            target = iter_args.next()
        elif arg == '-fprofile-use':
            return None
        else:
            if arg in ('-M', '-MM', '-MD', '-MMD'):
                need_explicit_target = True
            if arg.startswith('-') and len(arg) != 1:
                reduced_args.append(arg)
            else:
                input += (arg,)

    if not compilation or not output or len(input) != 1 or input[0] == '-':
        return None

    typ = os.path.splitext(input[0])[1]
    if typ not in FILE_TYPES:
        return None

    mt = ['-MT', target or output] if need_explicit_target else []

    return program, input[0], FILE_TYPES[typ], output, args, mt, reduced_args


def hash_key(program, args, preprocessed):
    import hashlib
    hash = hashlib.new('sha1')
    hash.update(str(os.path.getmtime(program)))
    hash.update(str(os.path.getsize(program)))
    hash.update(program)
    hash.update(' '.join('args'))
    hash.update(preprocessed)
    digest = hash.hexdigest()
    return '%s/%s/%s/%s' % (digest[0], digest[1], digest[2], digest)


def cache_store(path, cache_data, key):
    bucket = Bucket()
    try:
        bucket.put(key, cache_data.data)
        return True
    except:
        return False

def get_result(command, stdout=sys.stdout, stderr=sys.stderr,
               cwd=None):
    if not command:
        return 0

    compilation = parse_arguments(command)
    if not compilation:
        # Fallback to whatever we're wrapping in case parse_arguments didn't
        # like the command line.
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd)
        stdout_data, stderr_data = proc.communicate()
        ret = proc.wait()
        if stdout_data:
            stdout.write(stdout_data)
        if stderr_data:
            stderr.write(stderr_data)
        return ret

    program, input, file_type, output, args, mt, reduced_args = compilation
    proc = subprocess.Popen([program, '-E', input] + mt + reduced_args,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    preprocessed, stderr_data = proc.communicate()
    ret = proc.wait()
    if stderr_data:
        stderr.write(stderr_data)
    if ret:
        return ret

    bucket = None

    output_from_cwd = os.path.join(cwd, output) if cwd else output
    if preprocessed:
        key = hash_key(program, args, preprocessed)

        if not 'SCCACHE_RECACHE' in os.environ:
            bucket = Bucket()
            cache = bucket.get(key)
            if cache:
                cache.dump(output_from_cwd)
                return 0

    proc = subprocess.Popen([program, '-c', '-x', file_type, '-', '-o', output]
        + reduced_args, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    stdout_data, stderr_data = proc.communicate(preprocessed)
    ret = proc.wait()
    if stdout_data:
        stdout.write(stdout_data)
    if stderr_data:
        stderr.write(stderr_data)

    if ret or not os.path.exists(output_from_cwd):
        return ret

    return 0, output, key


def main(command, stdout=sys.stdout, stderr=sys.stderr):
    result = get_result(command, stdout, stderr)
    if isinstance(result, tuple):
        result, output, key = result

        def do_store(stderr, output, key, conn):
            cache = CacheData.from_object(output)
            conn.send('')
            conn.close()
            cache_store(output, cache, key)

        from multiprocessing import Process, Pipe
        parent_conn, child_conn = Pipe()
        Process(target=do_store, args=(stderr, output, key, child_conn)).start()
        parent_conn.recv()
        parent_conn.close()

    return result


if __name__ == '__main__':
    # When invoked from configure, configure tests may fail because of
    # our verbose output. Fortunately, we inherit configure's file
    # descriptors, so we can redirect to file descriptor 5, which is
    # config.log.
    try:
        stderr = os.fdopen(5, 'w')
    except:
        stderr = sys.stderr

    ret = main(sys.argv[1:], stderr=stderr)
    stderr.flush()
    # Use os._exit because we don't want automatic Process.join.
    os._exit(ret)
