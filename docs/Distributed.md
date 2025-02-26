# Distributed sccache

Background:

 - You should read about JSON Web Tokens - https://jwt.io/.
   - HS256 in short: you can sign a piece of (typically unencrypted)
     data with a key. Verification involves signing the data again
     with the same key and comparing the result. As a result, if you
     want two parties to verify each others messages, the key must be
     shared beforehand.
 - Secure token's referenced below should be generated with a CSPRNG
   (your OS random number generator should suffice).
   For example, on Linux this is accessible with: `openssl rand -hex 64`.
 - When relying on random number generators (for generating keys or
   tokens), be aware that a lack of entropy is possible in cloud or
   virtualized environments in some scenarios.

## Overview

Distributed sccache consists of three parts:

 - the client, an sccache binary that wishes to perform a compilation on
   remote machines
 - the scheduler (`sccache-dist` binary), responsible for deciding where
   a compilation job should run
 - the server (`sccache-dist` binary), responsible for actually executing
   a build

All servers are required to be a 64-bit Linux or a FreeBSD install. Clients
may request compilation from Linux, Windows or macOS. Linux compilations will
attempt to automatically package the compiler in use, while Windows and macOS
users will need to specify a toolchain for cross-compilation ahead of time.

## Communication

The HTTP implementation of sccache has the following API, where all HTTP body content is encoded using [`bincode`](http://docs.rs/bincode):

 - scheduler
   - `POST /api/v1/scheduler/alloc_job`
      - Called by a client to submit a compilation request.
      - Returns information on where the job is allocated it should run.
   - `GET /api/v1/scheduler/server_certificate`
      - Called by a client to retrieve the (dynamically created) HTTPS
        certificate for a server, for use in communication with that server.
      - Returns a digest and PEM for the temporary server HTTPS certificate.
   - `POST /api/v1/scheduler/heartbeat_server`
      - Called (repeatedly) by servers to register as available for jobs.
   - `POST /api/v1/scheduler/job_state`
      - Called by servers to inform the scheduler of the state of the job.
   - `GET /api/v1/scheduler/status`
      - Returns information about the scheduler.
 - `server`
   - `POST /api/v1/distserver/assign_job`
      - Called by the scheduler to inform of a new job being assigned to this server.
      - Returns whether the toolchain is already on the server or needs submitting.
   - `POST /api/v1/distserver/submit_toolchain`
      - Called by the client to submit a toolchain.
   - `POST /api/v1/distserver/run_job`
      - Called by the client to run a job.
      - Returns the compilation stdout along with files created.

There are three axes of security in this setup:

1. Can the scheduler trust the servers?
2. Is the client permitted to submit and run jobs?
3. Can third parties see and/or modify traffic?

### Server Trust

If a server is malicious, they can return malicious compilation output to a user.
To protect against this, servers must be authenticated to the scheduler. You have three
means for doing this, and the scheduler and all servers must use the same mechanism.

Once a server has registered itself using the selected authentication, the scheduler
will trust the registered server address and use it for builds.

#### JWT HS256 (preferred)

This method uses secret key to create a per-IP-and-port token for each server.
Acquiring a token will only allow participation as a server if the attacker can
additionally impersonate the IP and port the token was generated for.

You *must* keep the secret key safe.

*To use it*:

Create a scheduler key with `sccache-dist auth generate-jwt-hs256-key` (which will
use your OS random number generator) and put it in your scheduler config file as
follows:

```
server_auth = { type = "jwt_hs256", secret_key = "YOUR_KEY_HERE" }
```

Now generate a token for the server, giving the IP and port the scheduler and clients can
connect to the server on (address `192.168.1.10:10501` here):

```
sccache-dist auth generate-jwt-hs256-server-token \
    --secret-key YOUR_KEY_HERE \
    --server 192.168.1.10:10501
```

*or:*

```
sccache-dist auth generate-jwt-hs256-server-token \
    --config /path/to/scheduler-config.toml \
    --server 192.168.1.10:10501
```

This will output a token (you can examine it with https://jwt.io if you're
curious) that you should add to your server config file as follows:

```
scheduler_auth = { type = "jwt_token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Token

This method simply shares a token between the scheduler and all servers. A token
leak from anywhere allows any attacker to participate as a server.

*To use it*:

Choose a 'secure token' you can share between your scheduler and all servers.

Put the following in your scheduler config file:

```
server_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Put the following in your server config file:

```
scheduler_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Insecure (bad idea)

*This route is not recommended*

This method uses a hardcoded token that effectively disables authentication and
provides no security at all.

*To use it*:

Put the following in your scheduler config file:

```
server_auth = { type = "DANGEROUSLY_INSECURE" }
```

Put the following in your server config file:

```
scheduler_auth = { type = "DANGEROUSLY_INSECURE" }
```

Done!

### Client Trust

If a client is malicious, they can cause a DoS of distributed sccache servers or
explore ways to escape the build sandbox. To protect against this, clients must
be authenticated.

Each client will use an authentication token for the initial job allocation request
to the scheduler. A successful allocation will return a job token that is used
to authorise requests to the appropriate server for that specific job.

This job token is a JWT HS256 token of the job id, signed with a server key.
The key for each server is randomly generated on server startup and given to
the scheduler during registration. This means that the server can verify users
without either a) adding client authentication to every server or b) needing
secret transfer between scheduler and server on every job allocation.

#### OAuth2

This is a group of similar methods for achieving the same thing - the client
retrieves a token from an OAuth2 service, and then submits it to the scheduler
which has a few different options for performing validation on that token.

*To use it*:

Put one of the following settings in your scheduler config file to determine how
the scheduler will validate tokens from the client:

```
# Use the known settings for Mozilla OAuth2 token validation
client_auth = { type = "mozilla" }

# Will forward the valid JWT token onto another URL in the `Bearer` header, with a
# success response indicating the token is valid. Optional `cache_secs` how long
# to cache successful authentication for.
client_auth = { type = "proxy_token", url = "...", cache_secs = 60 }
```

Additionally, each client should set up an OAuth2 configuration in the with one of
the following settings (as appropriate for your OAuth service):

```
# Use the known settings for Mozilla OAuth2 authentication
auth = { type = "mozilla" }

# Use the Authorization Code with PKCE flow. This requires a client id,
# an initial authorize URL (which may have parameters like 'audience' depending
# on your service) and the URL for retrieving a token after the browser flow.
auth = { type = "oauth2_code_grant_pkce", client_id = "...", auth_url = "...", token_url = "..." }

# Use the Implicit flow (typically not recommended due to security issues). This requires
# a client id and an authorize URL (which may have parameters like 'audience' depending
# on your service).
auth = { type = "oauth2_implicit", client_id = "...", auth_url = "..." }
```

The client should then run `sccache --dist-auth` and follow the instructions to retrieve
a token. This will be automatically cached locally for the token expiry period (manual
revalidation will be necessary after expiry).

#### Token

This method simply shares a token between the scheduler and all clients. A token
leak from anywhere allows any attacker to participate as a client.

*To use it*:

Choose a 'secure token' you can share between your scheduler and all clients.

Put the following in your scheduler config file:

```
client_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Put the following in your client config file:

```
auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Insecure (bad idea)

*This route is not recommended*

This method uses a hardcoded token that effectively disables authentication and
provides no security at all.

*To use it*:

Put the following in your scheduler config file:

```
client_auth = { type = "DANGEROUSLY_INSECURE" }
```

Remove any `auth =` setting under the `[dist]` heading in your client config file
(it will default to this insecure mode).

Done!

### Eavesdropping and Tampering Protection

If third parties can see traffic to the servers, source code can be leaked. If third
parties can modify traffic to and from the servers or the scheduler, they can cause
the client to receive malicious compiled objects.

Securing communication with the scheduler is the responsibility of the sccache cluster
administrator - it is recommended to put a webserver with a HTTPS certificate in front
of the scheduler and instruct clients to configure their `scheduler_url` with the
appropriate `https://` address. The scheduler will verify the server's IP in this
configuration by inspecting the `X-Real-IP` header's value, if present. The webserver
used in this case should be configured to set this header to the appropriate value.

Securing communication with the server is performed automatically - HTTPS certificates
are generated dynamically on server startup and communicated to the scheduler during
the heartbeat. If a client does not have the appropriate certificate for communicating
securely with a server (after receiving a job allocation from the scheduler), the
certificate will be requested from the scheduler.

## Configuration

Use the `--config` argument to pass the path to its configuration file to `sccache-dist`.


### scheduler.toml

```toml
# The socket address the scheduler will listen on. It's strongly recommended
# to listen on localhost and put a HTTPS server in front of it.
public_addr = "127.0.0.1:10600"

[client_auth]
type = "token"
token = "my client token"

[server_auth]
type = "jwt_hs256"
secret_key = "my secret key"
```


#### [client_auth]

The `[client_auth]` section can be one of (sorted by authentication method):
```toml
# OAuth2
[client_auth]
type = "mozilla"

client_auth = { type = "proxy_token", url = "...", cache_secs = 60 }

# JWT
[client_auth]
type = "jwt_validate"
audience = "audience"
issuer = "issuer"
jwks_url = "..."

# Token
[client_auth]
type = "token"
token = "preshared token"

# None
[client_auth]
type = "DANGEROUSLY_INSECURE"
```


#### [server_auth]

The `[server_auth]` section can be can be one of:
```toml
[server_auth]
type = "jwt_hs256"
secret_key = "my secret key"

[server_auth]
type = "token"
token = "preshared token"

[server_auth]
type = "DANGEROUSLY_INSECURE"
```

### server.toml


```toml
# This is where client toolchains will be stored.
cache_dir = "/tmp/toolchains"
# The maximum size of the toolchain cache, in bytes.
# If unspecified the default is 10GB.
#toolchain_cache_size = 10737418240
# A public IP address and port that clients will use to connect to this builder.
public_addr = "192.168.1.1:10501"
# The socket address the builder will listen on. Falls back to public_addr.
#bind_address = "0.0.0.0:10501"
# The URL used to connect to the scheduler (should use https, given an ideal
# setup of a HTTPS server in front of the scheduler)
scheduler_url = "https://192.168.1.1"

[builder]
type = "overlay"
# The directory under which a sandboxed filesystem will be created for builds.
build_dir = "/tmp/build"
# The path to the bubblewrap version 0.3.0+ `bwrap` binary.
bwrap_path = "/usr/bin/bwrap"

[scheduler_auth]
type = "jwt_token"
# This will be generated by the `generate-jwt-hs256-server-token` command or
# provided by an administrator of the sccache cluster.
token = "my server's token"
```


#### [builder]

The `[builder]` section can be can be one of:
```toml
[builder]
type = "docker"

[builder]
type = "overlay"
# The directory under which a sandboxed filesystem will be created for builds.
build_dir = "/tmp/build"
# The path to the bubblewrap version 0.3.0+ `bwrap` binary.
bwrap_path = "/usr/bin/bwrap"

[builder]
type = "pot"
# Pot filesystem root
#pot_fs_root = "/opt/pot"
# Reference pot cloned when creating containers
#clone_from = "sccache-template"
# Command to invoke when calling pot
#pot_cmd = "pot"
# Arguments passed to `pot clone` command
#pot_clone_args = ["-i", "lo0|127.0.0.2"]

```


#### [scheduler_auth]

The `[scheduler_auth]` section can be can be one of:
```toml
[scheduler_auth]
type = "jwt_token"
token = "my server's token"

[scheduler_auth]
type = "token"
token = "preshared token"

[scheduler_auth]
type = "DANGEROUSLY_INSECURE"
```

# Logging

## stderr

You can set the `SCCACHE_LOG` environment variable to a comma-separated list of directives that specifies the levels and modules desired. 

For example:
```
SCCACHE_LOG=info,sccache_dist=trace,sccache=trace,sccache_heartbeat=off
```


For more details, consult the [`env_logger`](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) documentation.

## Syslog

Use the `--syslog` argument to enable logging to a syslog daemon. 
The presence of the `SCCACHE_LOG` environment variable takes precedence over this argument.
The same syntax is accepted:

```
--syslog info,sccache_dist=debug,sccache=debug,sccache_heartbeat=off
```


# Building the Distributed Server Binaries

Until these binaries [are included in releases](https://github.com/mozilla/sccache/issues/393) I've put together a Docker container that can be used to easily build a release binary:
```
docker run -ti --rm -v $PWD:/sccache luser/sccache-musl-build:0.1 /bin/bash -c "cd /sccache; cargo build --release --target x86_64-unknown-linux-musl --features=dist-server && strip target/x86_64-unknown-linux-musl/release/sccache-dist && cd target/x86_64-unknown-linux-musl/release/ && tar czf sccache-dist.tar.gz sccache-dist"
```
