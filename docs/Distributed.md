# Distributed sccache

Background:

 - You should read about JSON Web Tokens - https://jwt.io/.
   - HS256 in short: you can sign a piece of (typically unencrypted)
     data with a key. Verification involves signing the data again
     with the same key and comparing the result. As a result, if you
     want two parties to verify each others messages, the key must be
     shared beforehand.
 - 'secure token's referenced below should be generated with a CSPRNG
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

All servers are required to be a 64-bit Linux install. Clients may request
compilation from Linux, Windows or OSX. Linux compilations will attempt to
automatically package the compiler in use, while Windows and OSX users will
need to specify a toolchain for cross-compilation ahead of time.

## Communication

The HTTP implementation of sccache has the following API:

 - scheduler
   - `POST alloc_job`
      - Called by a client to submit a compilation request.
      - Returns information on where the job is allocated it should run.
   - `POST heartbeat_server`
      - Called (repeatedly) by servers to register as available for jobs.
   - `POST state`
      - Called by servers to inform the scheduler of the state of the job.
   - `GET status`
      - Returns information about the scheduler.
 - `server`
   - `POST assign_job`
      - Called by the scheduler to inform of a new job being assigned to this server.
      - Returns whether the toolchain is already on the server or needs submitting.
   - `POST submit_toolchain`
      - Called by the client to submit a toolchain.
   - `POST run_job`
      - Called by the client to run a job.
      - Returns the compilation stdout along with files created.

There are two axes of security in this setup:

1. Can the scheduler trust the servers?
2. Is the client permitted to submit and run jobs?

### Server Trust

If a server is malicious, they can return malicious compilation output to a user.
To protect against this, servers must be authenticated. You have three means for
doing this, and the scheduler and all servers must use the same mechanism.

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

Now generate a token for the server, giving the IP and port the scheduler can
connect to the server on (IP `192.168.1.10` and port `10501` here):

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
be authenticated. You have two means for doing this, and the scheduler and all
clients must use the same mechanism.

Each client will use the authentication for the initial job allocation request
to the scheduler. A successful allocation will return a job token that is used
to authorise requests to the appropriate server for that specific job.

This job token is a JWT HS256 token of the job id, signed with a server key.
The key for each server is randomly generated on server startup and given to
the scheduler during registration. This means that the server can verify users
without either a) adding client authentication to every server or b) needing
secret transfer between scheduler and server on every job allocation.

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
(it will default to insecure).

Done!
