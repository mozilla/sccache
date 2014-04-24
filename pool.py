# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Multiprocess/thread job pool with a non-fixed number of processes/threads.

import multiprocessing.queues
import os
import sys
from multiprocessing import Process
from threading import Thread, current_thread
from Queue import Queue, Empty


class AdaptivePool(object):
    '''
    Generic job pool handler. Subclasses define QUEUE_CLASS and PROCESS_CLASS
    which provide specific Queue and Process/Thread implementations.

    A pool is created like the following:
        def handler(data):
            result = do_something_with(data)
            yield result
        pool = AdaptivePoolSubclass(handler)

    Jobs are initiated with:
        pool.add_job(data)

    This dispatches the job data to an idle process/thread which then executes
    the handler with that data as argument. If no idle process/thread is found,
    a new one is spawned (hence the pool being adaptive).

    Results are either yielded or returned in a list from the handler. Using
    yield allows to keep the process/thread busy doing something else after
    having returned a result.

    Pool users may read results with the following (preferably in a separate
    thread):
        for result in pool.results():
            do_something_with(result)

    The pool itself, when it receives a job with add_job dispatches it to a
    dedicated control thread that is responsible for tracking jobs and
    processes/threads. The control thread then dispatches to processes/threads
    through the job_queue.

    Processes/threads are spawned with the AdaptivePoolWorker function, which
    conveniently wraps the handler. AdaptivePoolWorker handles communications
    with the control thread through the control queue, and sends results to the
    result queue, which is read from the results() iterator.
    '''
    def __init__(self, job_handler):
        self.control_queue = self.QUEUE_CLASS()
        self.job_queue = self.QUEUE_CLASS()
        self.result_queue = self.QUEUE_CLASS()
        self.pending_jobs = 0
        self.job_handler = job_handler
        self.processes = {}
        self.idle_processes = {}
        self.max_processes_used = 0
        self.stopping = False

        self.control_thread = Thread(target=self.control_loop)
        self.control_thread.start()

    def add_job(self, job_data):
        if job_data is not None:
            self.control_queue.put(('job', job_data))

    def results(self):
        while True:
            result = self.result_queue.get()
            if result is None:
                return
            yield result

    def stop(self, timeout=None):
        self.control_queue.put_nowait(('stop', 0))
        self.control_thread.join(timeout)

    def _join_process(self, id):
        if id not in self.processes:
            return
        proc = self.processes[id]
        proc.join()
        if id in self.idle_processes:
            del self.idle_processes[id]
        del self.processes[id]

    def _processes_cleanup(self):
        for p in self.processes.values():
            if not p.is_alive():
                self._join_process(p.ident)

    def control_loop(self):
        while True:
            self._processes_cleanup()
            # If we don't have enough idle processes to handle the pending
            # jobs, spawn a new process.
            if len(self.idle_processes) < self.pending_jobs:
                proc = self.PROCESS_CLASS(target=AdaptivePoolWorker,
                    args=(self.PROCESS_CLASS, self.job_handler, self.job_queue,
                        self.result_queue, self.control_queue))
                proc.start()
                self.idle_processes[proc.ident] = \
                    self.processes[proc.ident] = proc
                if len(self.processes) > self.max_processes_used:
                    self.max_processes_used = len(self.processes)

            if not self.processes and self.stopping:
                # Make the results iterator stop.
                self.result_queue.put_nowait(None)
                return
            try:
                cmd, data = self.control_queue.get(timeout=30)
            except Empty:
                # Trigger processes cleanup once in a while.
                continue

            if cmd == 'job':
                self.pending_jobs += 1
                self.job_queue.put_nowait(data)

            elif cmd == 'busy':
                # When stress-testing, we can receive the busy signal for an
                # "old" job after we cleaned up the process emitting it.
                if data in self.idle_processes:
                    del self.idle_processes[data]
                self.pending_jobs -= 1

            elif cmd == 'idle':
                # We may receive the idle signal after we cleaned up the
                # process.
                if data in self.processes:
                    self.idle_processes[data] = self.processes[data]

            elif cmd == 'stop':
                if data == 0:
                    # We received a stop request for the pool itself, dispatch
                    # to all processes.
                    self.stopping = True
                    for p in self.processes:
                        self.job_queue.put_nowait(None)
                else:
                    self._join_process(data)


def AdaptivePoolWorker(process_class, job_handler, job_queue, result_queue,
        control_queue):
    if process_class == Process:
        id = os.getpid()
    elif process_class == Thread:
        id = current_thread().ident
    else:
        raise Exception('process_class is neither Process or Thread')
    while True:
        try:
            job = job_queue.get(timeout=30)
        except Empty:
            job = None

        if job is None:
            # If we received a None, it means the pool controller requested us
            # to stop. Acknowledge, and stop.
            # If there were no incoming job until the timeout above, just
            # voluntarily stop.
            control_queue.put_nowait(('stop', id))
            return

        # We got a job, notify the pool controller that we're now busy
        control_queue.put_nowait(('busy', id))
        try:
            for result in job_handler(job):
                # The result queue takes None as a request to stop, so don't
                # send that.
                if result is not None:
                    result_queue.put_nowait(result)
        except:
            pass
        # The handler returned, we can notify the pool controller we're free to
        # take new jobs.
        control_queue.put_nowait(('idle', id))


class AdaptiveProcessPool(AdaptivePool):
    PROCESS_CLASS = Process
    QUEUE_CLASS = multiprocessing.queues.Queue

class AdaptiveThreadPool(AdaptivePool):
    PROCESS_CLASS = Thread
    QUEUE_CLASS = Queue

if sys.platform == 'win32':
    # Wrap CreateProcess to avoid the pool creating windows for each
    # new process. Ideally, we'd make the effort to change create_flags
    # only when CreateProcess is called from the instantiation of Process,
    # but it doesn't really matter for now.
    import _subprocess
    _CreateProcess = _subprocess.CreateProcess
    def _WrapCreateProcess(name, cmd, process_attr, thread_attr,
            inherit_handler, create_flags, env, cwd, startup_info):
        create_flags |= 0x08000000; # CREATE_NO_WINDOW
        return _CreateProcess(name, cmd, process_attr, thread_attr,
            inherit_handler, create_flags, env, cwd, startup_info)
    _subprocess.CreateProcess = _WrapCreateProcess
