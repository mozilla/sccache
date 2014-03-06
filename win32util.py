# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import ctypes
import os

GetShortPathName = ctypes.windll.kernel32.GetShortPathNameW
GetLongPathName = ctypes.windll.kernel32.GetLongPathNameW

# cl.exe likes to print inconsistent paths in the showIncludes output
# (some lowercased, some not, with different directions of slashes),
# and we need the original file case for make/pymake to be happy.
# As this is slow and needs to be called a lot of times, use a cache
# to speed things up.
_normcase_cache = {}

def normcase(path):
    # Get*PathName want paths with backslashes
    path = path.replace('/', os.sep)
    dir = os.path.dirname(path)
    # name is fortunately always going to have the right case,
    # so we can use a cache for the directory part only.
    name = os.path.basename(path)
    if dir in _normcase_cache:
        result = _normcase_cache[dir]
    else:
        path = ctypes.create_unicode_buffer(dir)
        length = GetShortPathName(path, None, 0)
        shortpath = ctypes.create_unicode_buffer(length)
        GetShortPathName(path, shortpath, length)
        length = GetLongPathName(shortpath, None, 0)
        if length > len(path):
            path = ctypes.create_unicode_buffer(length)
        GetLongPathName(shortpath, path, length)
        result = _normcase_cache[dir] = path.value
    return os.path.join(result, name)
