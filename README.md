sccache - Shared Compilation Cache
==================================

Sccache is a ccache-like tool. It is used as a compiler wrapper and avoids compilation when possible, storing a cache in a remote storage using the S3 API.

It works as a client-server. The client spawns a server if one is not running already, and sends the wrapped command line as a request to the server, which then does the work and returns stdout/stderr for the job.  The client-server model allows the server to be more efficient in its handling of the remote storage.  

Sccache can also be used with local storage instead of remote.


Requirements
------------

Sccache is a python 2.7 program. Remote storage requires the boto library. Optionally, it can use dnspython.


Usage
-----

Before using sccache, you need to set one of the following environment variables:

* SCCACHE_BUCKET: sets the S3 bucket name for remote storage.
* SCCACHE_DIR: sets a directory where to store data locally.

Only SCCACHE_DIR will be used if both are set. Those variables are only taken into account when the server starts, so only on the first run.

Running sccache is like running ccache: wrap your compilation commands with it, like so:

> $ sccache.py gcc -o foo.o -c foo.c

Sccache (tries to) support gcc, clang and MSVC.

Running sccache without a compilation command line will terminate the server.


Known caveats
-------------

(and possible future improvements)

* Sccache doesn't try to be smart about the command line arguments it uses when computing a key for a given compilation result (like skipping preprocessor-specific arguments)
* It doesn't support all kinds of compiler flags, and is certainly broken with a few of them. Really only the flags used during Firefox builds have been tested.
* It doesn't support ccache's direct mode.
* Local storage mode doesn't do any kind of cleanup. The cache will keep growing indefinitely.
