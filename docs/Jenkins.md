cachepot on Jenkins
==================

When using `cachepot` on [Jenkins](https://jenkins.io) one has to know about how to deal with the cachepot server process.
Unless specified otherwise, cachepot uses port `4226`. On invocation, cachepot tries to connect to a cachepot server
instance on this port. If no server is running, a new instance is spawned. Jenkins tries to kill *all* spawned processes
once a job is finished.  This results in broken builds when two run in parallel and the first one who spawned the server
is finished and the server is killed. The other job way be in contact with the server (e.g waiting for a cache response)
and fail.

One option to solve this problem is to spawn a always running cachepot server process by setting `CACHEPOT_IDLE_TIMEOUT`
to `0` and start the server beside Jenkins as a system service. This implies that all jobs use the same cachepot
configuration and share the statistics.

If a per-jobs cachepot configuration is needed or preferred (e.g place a local disc cache in `$WORKSPACE`) the [Port
allocator plugin](https://wiki.jenkins.io/display/JENKINS/Port+Allocator+Plugin) does a good job. It assigns a free and
unique port number to a job by exporting a variable. Naming this variable `CACHEPOT_SERVER_PORT` is enough to make the
job spawn it's own cachepot server that is save to terminate upon job termination. This approach has the advantage that
each job (with a dedicated server instance) maintains it's own statistics that might be interesting upon job
finalization.
