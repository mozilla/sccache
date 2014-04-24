# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import shutil
from cStringIO import StringIO
from zipfile import ZipFile, ZIP_DEFLATED


class CacheData(object):
    '''
    Helper to format the sccache data for storage. For consumers, it's a
    dict-like interface, and the data property returns a serialized form for
    the data callers have stored. The current format for this serialization is
    a zip file.
    The constructor can take a previously serialized form, to prefill the
    dict-like.
    '''
    # Update VERSION when the serialization format is modified.
    VERSION = 2

    def __init__(self, data=None):
        self._data = StringIO(data) if data else StringIO()
        self._obj = {}
        self._zip = ZipFile(self._data, 'r' if data else 'w', ZIP_DEFLATED)

    def __getitem__(self, key):
        if key not in self._obj:
            try:
                with self._zip.open(key, 'r') as obj:
                    self._obj[key] = obj.read()
            except:
                self._obj[key] = ''
        return self._obj[key]

    def __setitem__(self, key, value):
        assert key not in self._obj
        self._obj[key] = value
        if value:
            self._zip.writestr(key, value)

    @property
    def data(self):
        '''
        Return the raw cache data content.
        '''
        self._zip.close()
        return self._data.getvalue()
