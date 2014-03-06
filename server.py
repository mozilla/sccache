# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Main server implementation for sccache. This is where jobs are received
# from the base server implementation and dispatched to a job pool.
# Roughly, this is how a request goes:
# - a CommandHandler receives the request in the handle method and
#   sends it to the CommandServer so that it dispatches it.
# - the CommandServer prepares a job for the pool based on the compiler
#   and command line arguments, then sends it to the pool.
# - the pool treats the job by calling run_command, which runs the
#   preprocessor, checks if the cache has something corresponding to that.
#   It gets the cache content if there is one, or compiles if there isn't.
#   After the compilation, its status is returned to the server, while the
#   job continues by storing the result of the compilation on storage.
# - The server receives the compilation or cache hit status on a dedicated
#   thread, which then redispatches it to the ResponseHelper corresponding
#   to the job.

import base_server
import hashlib
import json
import os
import sys
from cStringIO import StringIO
from base_server import PORT
from cache import CacheData
from collections import defaultdict
from compiler import (
    CannotCacheError,
    Compiler,
    NotACompilationError,
)
from pool import AdaptiveProcessPool
from storage import Storage
from threading import Thread, Event


class CommandHandler(base_server.CommandHandler):
    '''
    Command handler for the sccache server. Expects requests in a dict form
    and dispatches them to the sccache server job pool.
    '''
    def handle(self, request):
        if request is None:
            self.server.stop()
            stats = self.server.stats
            self.responder.respond(0, stderr=
                'sccache: Terminated sccache server\n' +
                'sccache: Cache hits: %d\n' % (stats['hit']) +
                'sccache: Cache misses: %d\n' % (stats['miss']) +
                'sccache: Failures: %d\n' % (stats['failure']) +
                'sccache: Non-cachable calls: %d\n' % (stats['non-cachable']) +
                'sccache: Non-compilation calls: %d\n' % (stats['non-compile']) +
                'sccache: Max processes used: %d\n' %
                    (self.server._pool.max_processes_used) +
                self._time_stats()
            )
            return

        if not isinstance(request, dict):
            raise TypeError('Expected dict, got %s' % type(request))

        self.server.dispatch_job(request, self.responder)

    def _time_stats(self):
        if not self.server.get_time_stats and not self.server.put_time_stats:
            return ''
        return 'sccache: get_time_stats: %s\nsccache: put_time_stats: %s\n' % (
            json.dumps(self.server.get_time_stats),
            json.dumps(self.server.put_time_stats),
        )


class CommandServer(base_server.CommandServer):
    '''
    Main sccache server.
    '''
    def __init__(self, addr):
        self._pool = AdaptiveProcessPool(run_command)
        # Used to keep track of ResponseHelpers so that the right one can be
        # used when a job result is received from the pool.
        self._last_id = 0
        self._responders = {}
        # Used to keep track of whether the server is receiving requests.
        self._taking_work = Event()

        self.stats = defaultdict(int)
        self.get_time_stats = defaultdict(list)
        self.put_time_stats = defaultdict(list)

        try:
            base_server.CommandServer.__init__(self, addr, CommandHandler)
        except:
            # We need to stop the job pool to avoid the process living forever
            # waiting for jobs.
            self._pool.stop()
            raise

        Thread(target=self.dispatch_results).start()
        Thread(target=self._watchdog).start()

    def dispatch_job(self, request, responder):
        # Mark the server as not idle.
        self._taking_work.set()

        # Sanity checks on the requested command line
        cmd = request.get('cmd')
        if not cmd:
            raise ArgumentError('Command is either missing or empty')
        if not isinstance(cmd, list):
            raise TypeError('Expected list, got %s' % type(cmd))

        executable, args = cmd[0], cmd[1:]
        cwd = request.get('cwd')

        # Get a Compiler instance corresponding to that executable.
        # The cwd is necessary because sometimes the path to the executable is
        # relative.
        compiler = Compiler.from_path(executable, cwd)
        if not compiler:
            raise RuntimeError('%s is not a known compiler' % executable)

        # Parse the command line arguments in the main thread, this is fast
        # enough not to be a problem in practice, and avoids dispatching
        # compilations that can't be cached.
        parsed_args = None
        try:
            parsed_args = compiler.parse_arguments(args)
        except CannotCacheError:
            self.stats['non-cachable'] += 1
        except NotACompilationError:
            self.stats['non-compile'] += 1

        if not parsed_args:
            # Return status code -2 when the compiler result can't be cached
            # or when the compiler is invoked for something else than a
            # compilation.
            responder.respond(-2)
            return

        # Prepare job for run_command and send it to the job pool.
        self._last_id += 1
        job = {
            'id': self._last_id,
            'compiler': compiler,
            'args': args,
            'parsed_args': parsed_args,
            'cwd': cwd,
        }
        self._responders[self._last_id] = responder
        self._pool.add_job(job)

    def dispatch_results(self):
        # This runs in a dedicated thread.
        for result in self._pool.results():
            if not isinstance(result, dict):
                continue
            # Redispatch the results from the pool to the corresponding client.
            id = result.get('id')
            stats = result.get('stats')
            if stats:
                for key in ('dns', 'connect', 'response', 'size'):
                    value = stats.get(key, 0)
                    if id:
                        self.get_time_stats[key].append(value)
                    else:
                        self.put_time_stats[key].append(value)
            responder = self._responders.get(id)
            if not responder:
                continue
            responder.respond(
                result.get('retcode', -1),
                result.get('stdout', ''),
                result.get('stderr', ''),
            )
            status = result.get('status')
            if status:
                self.stats[status] += 1

    def _watchdog(self):
        # This runs in a dedicated thread.
        while not self.stopping:
            self._taking_work.clear()
            self._taking_work.wait(timeout=600)
            # If the server hasn't received a connection in the past 600
            # seconds, stop it.
            if not self._taking_work.is_set():
                self.stop()
                break

    def stop(self):
        if not self.stopping:
            base_server.CommandServer.stop(self)
            # If the watchdog is waiting for the taking_work event timeout,
            # trigger one now to unblock it and make it quit.
            self._taking_work.set()
            self._pool.stop()


def hash_key(compiler, args, preprocessed):
    '''
    For a given compiler, command line arguments, and preprocessor output,
    return a unique key.
    '''
    h = hashlib.new('sha1')
    h.update(compiler.digest)
    h.update(compiler.executable)
    h.update(' '.join(args))
    h.update(preprocessed)
    digest = h.hexdigest()
    return '%s/%s/%s/%s' % (digest[0], digest[1], digest[2], digest)


def _run_command(job):
    '''
    Job handler for compilation and caching.
    '''
    id = job['id']
    compiler = job['compiler']
    args = job['args']
    parsed_args = job['parsed_args']
    cwd = job['cwd']
    storage = Storage.from_environment()

    # First, run the preprocessor for the given command
    retcode, preprocessed, stderr = compiler.preprocess(parsed_args, cwd)
    if retcode:
        yield dict(id=id, retcode=retcode, stderr=stderr, status='failure')
        return

    output = parsed_args['output']
    output_from_cwd = os.path.join(cwd, output) if cwd else output
    if preprocessed:
        # Compute the key corresponding to the preprocessor output, the command
        # line, and the compiler.
        # TODO: Remove preprocessor-only arguments from args (like -D, -I...)
        key = hash_key(compiler, args, preprocessed)

        if not 'SCCACHE_RECACHE' in os.environ:
            # Get cached data if there is.
            data = storage.get(key)
            if data:
                CacheData(data).dump(output_from_cwd)
                yield dict(id=id, retcode=0, status='hit',
                    stats=storage.last_stats)
                return

    # In case of cache miss, compile
    ret, stdout, stderr = compiler.compile(preprocessed, parsed_args, cwd)
    # Get the output file content before returning the job status
    if not ret and os.path.exists(output_from_cwd):
        cache = CacheData.from_file(output_from_cwd)
    else:
        cache = None

    yield dict(id=id, retcode=ret, stdout=stdout, stderr=stderr, status='miss',
        stats=storage.last_stats)

    # Store cache after returning the job status.
    if cache:
        storage.put(key, cache.data)
        yield dict(stats=storage.last_stats)


def run_command(job):
    '''
    Wrapper around _run_command, used to handle exceptions there gracefully.
    '''
    try:
        for result in _run_command(job):
            yield result
    except Exception as e:
        import traceback
        yield dict(id=job['id'], retcode=1, stderr=traceback.format_exc())


if __name__ == '__main__':
    server = CommandServer(('localhost', PORT))
