# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Low level client and server implementation for sccache.

import asyncore
import json
import socket
import sys
import traceback
from threading import Thread, Event
import multiprocessing.util

PORT = 4225


class CommandServer(object):
    '''
    A CommandServer is a server listening on TCP that reads commands in JSON
    format and sends them in unserialized form to a handler class instance it
    creates.
    The JSON is free form and just needs to be agreed upon between the client
    and the callback. This class does not impose any specific message format.
    The response message format, however, is fixed. See ResponseHelper.respond.

    The handler class must derive from CommandHandler.
    '''
    def __init__(self, addr, handler_class):
        assert issubclass(handler_class, CommandHandler)
        self._handler_class = handler_class
        self.stopping = False
        self._listeners_and_readers = {}
        self._dispatcher = ListeningDispatcher(self,
            map=self._listeners_and_readers)
        self._dispatcher.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform != 'win32':
            # On Windows, SO_REUSEADDR has different semantics and makes a
            # second process happily bind on the same addr. On Unix, it only
            # allows to bind on the same addr as TIME_WAITing sockets, not
            # LISTENing sockets.
            self._dispatcher.set_reuse_addr()
        self._dispatcher.bind(addr)
        self._dispatcher.listen(128)
        # On Unix, forked processes inherit the listening sockets from their
        # parent process. But on OSX, contrary to Linux, when the parent
        # process stops listening, the socket, at the OS level, is still
        # LISTENing, but the child processes are not taking handling
        # connections, and that can lead to a dead-lock situation when a
        # sccache server stopped listening but one of its worker process
        # is stuck for some reason. In that case a client won't fork a new
        # server for further processing.
        multiprocessing.util.register_after_fork(
            self._dispatcher.socket,
            lambda socket: socket.close()
        )

        Thread(target=self._listeners_and_readers_loop).start()

    def handle_request(self, request, dispatcher):
        # Our dispatchers are meant to wait for a write after having read the
        # request. Switch them to the writers dict.
        dispatcher.del_channel()
        responder = ResponseHelper(dispatcher)
        try:
            request = json.loads(request)
            self._handler_class(self, responder).handle(request)
        except Exception as e:
            responder.respond(-1, stderr=traceback.format_exc())

    def add_connected_socket(self, sock):
        # asyncore.dispatchers self-register in the given dict, which then
        # contains a reference. We don't need a local reference.
        ConnectedDispatcher(self, sock, self._listeners_and_readers)

    def _listeners_and_readers_loop(self):
        while self._listeners_and_readers or not self.stopping:
            try:
                asyncore.loop(count=1, timeout=1,
                    map=self._listeners_and_readers)
            except:
                pass

    def _writers_loop(self, writers):
        asyncore.loop(map=writers)

    def notify_ready(self, dispatcher):
        writers = {}
        # del_channel also unset the dispatchers's _fileno. set_socket refills
        # it while also doing add_channel.
        dispatcher.set_socket(dispatcher.socket, writers)
        # asyncore.dispatcher never updates the map it associated with at
        # creation time, which doesn't fit well with us switching.
        dispatcher._map = writers

        # Just spawn a new thread for each writer, it's simpler than having to
        # deal with being stuck in select() when a new connection is ready to
        # write.
        Thread(target=self._writers_loop, args=(writers, )).start()

    def stop(self):
        self.stopping = True
        self._dispatcher.handle_close()


class CommandHandler(object):
    '''
    Base class for handlers to be used with CommandServer. Subclasses
    implement the handle function as they see fit.

    Instances are created by the CommandServer. They are given a reference to
    the server (available as handler_instance.server) and a ResponseHelper
    instance (available as handler_instance.responder) which must be used to
    send the response corresponding to the handled request.
    '''
    def __init__(self, server, responder):
        self.server = server
        self.responder = responder

    def handle(self, request):
        self.responder.respond(1,
            stderr='%s.handle is not implemented' % self.__class__.__name__)


class ResponseHelper(object):
    '''
    A helper to format CommandServer responses and send them to an
    asyncore.dispatcher.
    '''
    def __init__(self, dispatcher):
        self._dispatcher = dispatcher
        self._responded = False

    def respond(self, retcode, stdout='', stderr=''):
        if self._responded:
            return
        data = {
            'retcode': retcode,
            'stdout': stdout,
            'stderr': stderr,
        }
        self._dispatcher.set_write_buffer(json.dumps(data))
        self._responded = True


class BaseDispatcher(asyncore.dispatcher):
    '''
    An asyncore dispatcher helper base for both listening and connected
    sockets.
    '''
    max_size = 8192

    def handle_close(self):
        try:
            # Without this, the port stays LISTENing after the listening
            # socket file descriptor is closed. But this raises an exception
            # on Windows. This also properly closes the TCP connection for
            # connected sockets.
            self.socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.close()


class ServerDispatcher(BaseDispatcher):
    def __init__(self, server, sock=None, map=None):
        asyncore.dispatcher.__init__(self, sock, map)
        self._server = server


class ListeningDispatcher(ServerDispatcher):
    '''
    An asyncore dispatcher helper for listening sockets.
    '''
    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            return
        sock, addr = pair
        self._server.add_connected_socket(sock)


class ConnectedDispatcherMixin(object):
    def readable(self):
        return self._is_readable

    def writable(self):
        return not self._is_readable and self._buf

    def handle_read(self):
        data = self.recv(self.max_size)
        if data:
            self._buf += data

    def handle_write(self):
        sent = self.send(self._buf[:self.max_size])
        self._buf = self._buf[sent:]


class ConnectedDispatcher(ConnectedDispatcherMixin, ServerDispatcher):
    '''
    An asyncore dispatcher helper for connected sockets.
    '''
    def __init__(self, server, sock=None, map=None):
        ServerDispatcher.__init__(self, server, sock, map)
        self._buf = ''
        # Connected sockets for the CommandServer are only in one state:
        # readable or writable. Not both at the same time.
        self._is_readable = True

    def handle_read(self):
        ConnectedDispatcherMixin.handle_read(self)
        # We're done reading data if the last received byte is null.
        if self._buf and self._buf[-1] == '\0':
            buf = self._buf[:-1]
            self._buf = ''
            self._is_readable = False
            self._server.handle_request(buf, self)

    def handle_write(self):
        ConnectedDispatcherMixin.handle_write(self)
        if not self._buf:
            self.handle_close()

    def set_write_buffer(self, data):
        self._buf = data
        self._server.notify_ready(self)


class ClientDispatcher(ConnectedDispatcherMixin, BaseDispatcher):
    '''
    An asyncore dispatcher helper for connected sockets for clients.
    '''
    def __init__(self, sock=None, map=None):
        BaseDispatcher.__init__(self, sock, map)
        self._buf = ''
        self._is_readable = False

    def handle_write(self):
        ConnectedDispatcherMixin.handle_write(self)
        if not self._buf:
            self._is_readable = True

    def set_write_buffer(self, data):
        self._buf = data + '\0'

    def handle_error(self):
        raise

    @property
    def buf(self):
        return self._buf


class CommandClient(object):
    '''
    A client implementation to connect to a CommandServer.
    '''
    def __init__(self, addr):
        self._map = {}
        self._dispatcher = ClientDispatcher(map=self._map)
        # Using create_socket calls setblocking, which makes asyncore just eat
        # connection errors.
        self._dispatcher.set_socket(socket.socket(
           socket.AF_INET, socket.SOCK_STREAM))
        self._dispatcher.connect(addr)

    def request(self, request):
        self._dispatcher.set_write_buffer(json.dumps(request))
        asyncore.loop(map=self._map)
        try:
            return json.loads(self._dispatcher.buf)
        except:
            return {
                'retcode': 1,
                'stderr': traceback.format_exc(),
            }
