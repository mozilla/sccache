# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import gzip
import shutil
from cStringIO import StringIO


class CacheData(object):
    '''
    Helper to format the sccache data for storage.
    '''
    def __init__(self, data=None, obj=None):
        assert bool(data) != bool(obj)
        self._data = data
        self._obj = obj

    def dump(self, output):
        '''
        Write the cache data content to the given file.
        '''
        with open(output, 'wb') as out:
            if self._obj:
                out.write(self._obj)
            else:
                with gzip.GzipFile(mode='r',
                        fileobj=StringIO(self._data)) as obj:
                    shutil.copyfileobj(obj, out)

    @property
    def data(self):
        '''
        Return the raw cache data content.
        '''
        if not self._data:
            data = StringIO()
            with gzip.GzipFile(mode='w', compresslevel=6, fileobj=data) as fh:
                fh.write(self._obj)
            self._data = data.getvalue()

        return self._data

    @staticmethod
    def from_file(path):
        '''
        Read cache data content from the given file and return an instance
        corresponding to that data.
        '''
        with open(path, 'rb') as fh:
            return CacheData(obj=fh.read())
