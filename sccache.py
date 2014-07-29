#!/usr/bin/env python2.7

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# sccache is a ccache-like tool. It is used as a compiler wrapper and
# avoids compilation when possible, storing a cache in a remote storage.
#
# It works as a client-server. The client spawns a server if one is not
# running already, and sends the wrapped command line as a request to the
# server, which then does the work and returns stdout/stderr for the job.
# The client-server model allows the server to be more efficient in its
# handling of the remote storage.

import json
import os
import socket
import sys
import codecs
import locale
from base_server import CommandClient, PORT
from errno import ECONNREFUSED

# Set the output encoding in case the output is being redirected to a file.  In
# this case, the default encoding is ASCII, but we may have unicode characters
# in stderr/stdout, which causes python to report a UnicodeEncodeError.
if not sys.stdout.encoding:
    sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout);
if not sys.stderr.encoding:
    sys.stderr = codecs.getwriter(locale.getpreferredencoding())(sys.stderr);

if __name__ == '__main__':
    cmd = sys.argv[1:]
    if cmd:
        data = {
            'cmd': cmd,
            'cwd': os.getcwd(),
        }
    else:
        data = None

    try:
        client = CommandClient(('localhost', PORT))
        result = client.request(data)
    except socket.error as e:
        if e.errno != ECONNREFUSED: # Connection refused
            raise
        if not cmd:
            sys.exit(0)
        import subprocess
        import time
        if sys.platform == 'win32':
            # DETACHED_PROCESS makes the process independent of the console
            # we're running from, and doesn't make the parent process block
            # until the server terminates. On windows, close_fds conflicts
            # with providing stdin/stdout/stderr.
            proc = subprocess.Popen([sys.executable,
                os.path.join(os.path.abspath(os.path.dirname(__file__)),
                    'server.py')],
                close_fds=True,
                creationflags=8, # DETACHED_PROCESS
            )
        else:
            proc = subprocess.Popen([sys.executable,
                os.path.join(os.path.abspath(os.path.dirname(__file__)),
                    'server.py')],
                stdin=open(os.devnull, 'r'),
                stdout=open(os.devnull, 'w'),
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
        # Try connecting as long as the server process is initializing, and
        # the port is still not listening.
        while proc.returncode is None:
            time.sleep(0.001)
            try:
                client = CommandClient(('localhost', PORT))
                result = client.request(data)
            except socket.error as e:
                if e.errno == ECONNREFUSED: # Connection refused
                    proc.poll()
                    continue
            break
        # If the server process failed to start, it may be because another
        # client was racing with us and started another server process which
        # bound the port, which our server couldn't bind as a consequence.
        if proc.returncode:
            try:
                client = CommandClient(('localhost', PORT))
                result = client.request(data)
            except socket.error as e:
                if e.errno == ECONNREFUSED: # Connection refused
                    raise RuntimeError("Couldn't start server. Try running it manually to find out why:\n\t%s %s" % (
                        sys.executable,
                        os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                     'server.py'),
                    ))

    retcode = result.get('retcode', 1)
    # The server returns a code -2 when the command line can't be handled.
    if retcode == -2:
        import subprocess
        sys.exit(subprocess.call(cmd))
    sys.stderr.write(result.get('stderr', ''))
    sys.stderr.flush()
    sys.stdout.write(result.get('stdout', ''))
    sys.stdout.flush()

    sys.exit(retcode)
