# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Helpers for storage access (S3)

import httplib
import os
import time
import urllib2
from boto.s3.connection import S3Connection
from boto.utils import find_class


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

    _storage = None

    @staticmethod
    def from_environment():
        '''
        Return a Storage instance matching the configuration in the
        environment.
            SCCACHE_BUCKET sets the S3 bucket,
            SCCACHE_NO_HTTPS defines whether put shall use HTTP instead of
                HTTPS,
            SCCACHE_NAMESERVER defines a DNS server to use instead of using
                getaddrinfo.
        '''
        if Storage._storage:
            return Storage._storage

        bucket_name = os.environ.get('SCCACHE_BUCKET')
        storage = None
        if bucket_name:
            storage = S3Storage(bucket_name,
                os.environ.get('SCCACHE_NO_HTTPS') != '1',
                os.environ.get('SCCACHE_NAMESERVER'))
        if storage:
            Storage._storage = storage
            return storage
        raise RuntimeError('Cannot configure storage')


class S3Storage(object):
    '''
    Storage class for S3.
    '''
    def __init__(self, bucket_name, store_with_https=True, dns_server=None):
        assert bucket_name
        self._bucket_name = bucket_name
        self._store_with_https = store_with_https

        # The boto config can override the default calling format, and since
        # we don't use boto for get(), we need to use the right calling format.
        self._calling_format = find_class(S3Connection.DefaultCallingFormat)()
        self._host = self._calling_format.build_host(S3Connection.DefaultHost,
            self._bucket_name)

        # Prepare the wrapper classes to use for urllib and boto.
        dns_query = dns_query_function(dns_server)
        self._http_connection_class = ConnectionWrapperFactory(
            httplib.HTTPConnection, dns_query)
        self._https_connection_class = ConnectionWrapperFactory(
            httplib.HTTPSConnection, dns_query)
        self._url_opener = OpenerFactory(
            self._http_connection_class, self._https_connection_class)

        # Get the boto S3 bucket instance
        if store_with_https:
            s3_connection = S3Connection(
                https_connection_factory=(self._https_connection_class, ()))
        else:
            s3_connection = S3Connection(port=80, is_secure=False,
                https_connection_factory=(self._http_connection_class, ()))

        self._bucket = s3_connection.get_bucket(self._bucket_name,
            validate=False)

        self.last_stats = {}

    def get(self, key):
        # Don't use boto here, because it can't do simple GET requests, and those
        # are actually significantly faster.
        url = 'http://%s%s' % (self._host,
            self._calling_format.build_path_base(self._bucket_name, key))
        _last_stats.clear()
        try:
            data = self._url_opener.open(url).read()
            _last_stats['size'] = len(data)
            return data
        except:
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
            k = self._bucket.new_key(key)
            k.set_contents_from_string(data, headers={
                'x-amz-acl': 'public-read',
            })
        except:
            pass
        finally:
            if 'TINDERBOX_OUTPUT' in os.environ:
                self.last_stats = dict(_last_stats)


_last_stats = {}


def ConnectionWrapperFactory(parent_class, dns_query):
    '''
    Create a httplib.HTTPConnection/httplib.HTTPSConnection subclass. The exact
    parent class is given as parent_class, and the created subclass's connect
    method uses the dns_query function to resolve the connection host name.
    '''
    class ConnectionWrapper(parent_class):
        def connect(self):
            t0 = time.time()
            self.host = dns_query(self.host)
            t1 = time.time()
            _last_stats['dns'] = (t1 - t0) * 1000
            parent_class.connect(self)
            self._connect_time = time.time()
            _last_stats['connect'] = (self._connect_time - t1) * 1000

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
