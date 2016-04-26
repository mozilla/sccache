# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Helpers for storage access (S3)

import errno
import httplib
import os
import socket
import time
import urllib2


def ensure_dir(path):
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
    if not os.path.isdir(path):
        raise RuntimeError('%s is not a directory' % directory)


class Storage(object):
    '''
    Abstract class defining the interface for Storage classes.
    '''
    def get(self, key):
        raise NotImplementedError('%s.get is not implemented' %
            self.__class__.__name__)

    def put(self, key, data):
        raise NotImplementedError('%s.put is not implemented' %
            self.__class__.__name__)

    def failed(self):
        '''Return whether the given Storage has failed during previous uses.'''
        return False

    _storage = None
    _iter = None

    @staticmethod
    def from_environment():
        '''
        Return a Storage instance matching the configuration in the
        environment.
            SCCACHE_BUCKET sets the S3 bucket,
            SCCACHE_NAMESERVER defines a DNS server to use instead of using
                getaddrinfo,
            SCCACHE_DIR defines a directory where to store a local cache.
                Defining SCCACHE_DIR makes any of the above variable ignored.
        '''
        if Storage._storage and not Storage._storage.failed():
            return Storage._storage

        if not Storage._iter:
            Storage._iter = iter(Storage._iter_storages())

        try:
            Storage._storage = Storage._iter.next()
            return Storage._storage
        except StopIteration:
            return None

    @staticmethod
    def _iter_storages():
        directory = os.environ.get('SCCACHE_DIR')
        if directory:
            yield LocalStorage(directory)

        bucket_name = os.environ.get('SCCACHE_BUCKET')
        if bucket_name:
            storage = BotoStorage(bucket_name,
                dns_server=os.environ.get('SCCACHE_NAMESERVER'))
            yield storage

            if not isinstance(storage, S3Storage):
                from boto import config
                if config.getbool('s3', 'fallback', False):
                    yield S3Storage(bucket_name,
                        dns_server=os.environ.get('SCCACHE_NAMESERVER'))


class LocalStorage(Storage):
    '''
    Storage class for a local directory.
    '''
    def __init__(self, directory):
        ensure_dir(directory)

        self._directory = directory
        self.last_stats = {}

    def _normalize_key(self, key):
        return '%s/%s/%s' % (key[0], key[1], key)

    def get(self, key):
        path = os.path.join(self._directory, self._normalize_key(key))
        if os.path.isfile(path):
            with open(path, 'rb') as data:
                return data.read()

    def put(self, key, data):
        path = os.path.join(self._directory, self._normalize_key(key))
        parent = os.path.dirname(path)
        try:
            ensure_dir(os.path.dirname(path))
            with open(path, 'wb') as out:
                out.write(data)
            return True
        except:
            return False


class S3CompatibleStorage(Storage):
    '''
    Storage class for S3-compatible servers.
    '''
    DefaultHost = 's3.amazonaws.com'
    DefaultCallingFormat = 'boto.s3.connection.SubdomainCallingFormat'

    def __init__(self, bucket_name, host=DefaultHost,
            calling_format=DefaultCallingFormat,
            dns_server=None):

        assert bucket_name
        self._bucket_name = bucket_name

        from boto.s3.connection import S3Connection
        from boto.utils import find_class
        from boto import config

        self._calling_format = find_class(calling_format)()
        self._host = self._calling_format.build_host(host, self._bucket_name)
        self._failed = False

        # Prepare the wrapper classes to use for urllib and boto.
        dns_query = dns_query_function(dns_server)
        self._http_connection_class = ConnectionWrapperFactory(
            httplib.HTTPConnection, dns_query)
        self._https_connection_class = ConnectionWrapperFactory(
            httplib.HTTPSConnection, dns_query)
        self._url_opener = OpenerFactory(
            self._http_connection_class, self._https_connection_class)

        # Get the boto S3 bucket instance
        if config.getbool('Boto', 'is_secure', True):
            s3_connection = S3Connection(host=host, port=443,
                https_connection_factory=(self._https_connection_class, ()))
        else:
            s3_connection = S3Connection(host=host, port=80,
                https_connection_factory=(self._http_connection_class, ()))

        self._bucket = s3_connection.get_bucket(self._bucket_name,
            validate=False)

        self.last_stats = {}

    def _normalize_key(self, key):
        return '%s/%s/%s/%s' % (key[0], key[1], key[2], key)

    def get(self, key):
        # Don't use boto here, because it can't do simple GET requests, and those
        # are actually significantly faster.
        url = 'http://%s%s' % (self._host,
            self._calling_format.build_path_base(self._bucket_name,
                self._normalize_key(key)))
        _last_stats.clear()
        try:
            data = self._url_opener.open(url, timeout=5).read()
            _last_stats['size'] = len(data)
            return data
        except Exception as e:
            if not isinstance(e, urllib2.HTTPError) or e.code not in (404, 403):
                self._failed = True
            return None
        finally:
            if 'TINDERBOX_OUTPUT' in os.environ:
                self.last_stats = dict(_last_stats)

    def put(self, key, data):
        # Store the given data on S3, and set an acl at the same time to allow
        # public HTTP GETs later on (which we use in get())
        _last_stats.clear()
        _last_stats['size'] = len(data)
        try:
            k = self._bucket.new_key(self._normalize_key(key))
            k.set_contents_from_string(data, headers={
                'x-amz-acl': 'public-read',
                'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                'Cache-Control': 'max-age=1296000', # Two weeks
            })
            return True
        except Exception as e:
            from boto.exception import S3ResponseError
            if isinstance(e, S3ResponseError) and e.status == 403 and \
                    e.error_code == 'SignatureDoesNotMatch':
                # More often than it should, S3 returns a SignatureDoesNotMatch
                # error. Consider it an error (returning False as such), but
                # don't consider it hard enough to trigger a fallback.
                return False
            self._failed = True
            return False
        finally:
            if 'TINDERBOX_OUTPUT' in os.environ:
                self.last_stats = dict(_last_stats)

    def failed(self):
        return self._failed


_last_stats = {}


class S3Storage(S3CompatibleStorage):
    pass


class BotoStorage(S3CompatibleStorage):
    '''
    Storage class for boto-configured S3-compatible servers.
    '''
    def __new__(cls, bucket_name, dns_server):
        from boto.s3.connection import S3Connection
        from boto import config

        # If the boto config points to S3 and doesn't have a separate host for
        # get requests (see further below), just return a S3Storage instance.
        get_host = config.get('get', 'host', S3Connection.DefaultHost)
        if get_host == S3CompatibleStorage.DefaultHost:
            return S3Storage(bucket_name=bucket_name, dns_server=dns_server)

        return super(BotoStorage, cls).__new__(cls)

    def __init__(self, bucket_name, dns_server=None):
        from boto.s3.connection import S3Connection
        from boto.utils import find_class
        from boto import config

        S3CompatibleStorage.__init__(self,
            bucket_name=bucket_name,
            host=S3Connection.DefaultHost,
            # The boto config can override the default calling format, and since
            # we don't use boto for get(), we need to use the right calling format.
            calling_format=S3Connection.DefaultCallingFormat,
            dns_server=dns_server
        )

        # Allow to use a different host/calling format for GET requests by
        # adding the following boto config:
        #   [get]
        #   host = my.server.tld
        #   calling_format = boto.s3.connection.TheCallingFormat
        get_host = config.get('get', 'host', S3Connection.DefaultHost)
        get_calling_format = config.get('get', 'calling_format',
                                        S3Connection.DefaultCallingFormat)

        if get_host != S3Connection.DefaultHost:
            if get_calling_format != S3Connection.DefaultCallingFormat:
                self._calling_format = find_class(get_calling_format)()
            self._host = self._calling_format.build_host(get_host,
                                                         self._bucket_name)


def ConnectionWrapperFactory(parent_class, dns_query):
    '''
    Create a httplib.HTTPConnection/httplib.HTTPSConnection subclass. The exact
    parent class is given as parent_class, and the created subclass's connect
    method uses the dns_query function to resolve the connection host name.
    '''
    class ConnectionWrapper(parent_class):
        def create_connection(self, address, timeout, source_address):
            '''
            httplib.HTTP(S)Connection creates a socket connection to
            self.host using _create_connection, which by default is a
            redirect to socket.create_connection(). self._create_connection exists
            on httplib.HTTPConnection as a way of overriding it for unit tests.
            Connections are made to self.host by default.  When attempting
            to perform DNS resolution and connecting to an IP address instead
            of hostname, SSL certificate validation is broken in Python 2.7.9+.
            This wrapper allows for a dns query to be made, and socket
            connection made to an IP address while still maintaining self.host
            as the unresolved hostname for validation.
            '''
            t0 = time.time()
            host, port = address
            resolvedHost = dns_query(host)
            self._socket_connect_timestamp = t1 = time.time()
            _last_stats['dns'] = (t1 - t0) * 1000
            sock = socket.create_connection((resolvedHost, port),
                                            timeout, source_address)
            return sock

        def connect(self):
            self._create_connection = self.create_connection
            parent_class.connect(self)
            self._connect_time = time.time()
            _last_stats['connect'] = (
                self._connect_time - self._socket_connect_timestamp) * 1000

        def getresponse(self, buffering=False):
            res = parent_class.getresponse(self, buffering)
            _last_stats['response'] = (time.time() - self._connect_time) * 1000
            return res


    return ConnectionWrapper


def OpenerFactory(HTTPConnection, HTTPSConnection):
    '''
    Create an OpenerDirector instance with handlers using the given
    HTTPConnection and HTTPSConnection classes.
    '''
    class HTTPHandler(urllib2.HTTPHandler):
        def http_open(self, req):
            return self.do_open(HTTPConnection, req)

    class HTTPSHandler(urllib2.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(HTTPSConnection, req)

    return urllib2.build_opener(HTTPHandler, HTTPSHandler)


def dns_query_function(server=None):
    '''
    Return a dns query function using the given DNS server address, or
    getaddrinfo if none is given.
    '''
    if server:
        from dns.resolver import Resolver, Cache
        resolver = Resolver(configure=False)
        resolver.cache = Cache()
        resolver.nameservers.append(server)
        def dns_query(host):
            for rr in resolver.query(host):
                return rr.address
    else:
        import socket
        def dns_query(host):
            for family, socktype, proto, canonname, sockaddr in \
                    socket.getaddrinfo(host, 0):
                return sockaddr[0]
    return dns_query
