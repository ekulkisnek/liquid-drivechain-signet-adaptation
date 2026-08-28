Secure Drivechain RPC setup
===========================

The native slot-24 network has two RPC trust boundaries. Both fail closed:

1. Elements reads its fully validating Bitcoin parent through a numeric
   loopback address and a rotating Bitcoin Core cookie.
2. Elements submits BMM and withdrawal requests through a CA-verified mutual
   TLS endpoint. It never invokes `grpcurl -plaintext`.

Parent Bitcoin RPC
------------------

Run Bitcoin Core on the same host, bind RPC only to loopback, enable `txindex`,
and do not configure `mainchainrpcuser` or `mainchainrpcpassword` in Elements.
Point Elements at the rotating cookie:

```ini
mainchainrpchost=127.0.0.1
mainchainrpcport=38332
mainchainrpccookiefile=/absolute/path/to/bitcoin/signet/.cookie
```

On POSIX the cookie must be owned by the Elements process user, must not be a
symlink, and must have mode `0600`. Elements also verifies the canonical
`__cookie__:` plus 64-hex-character format. A hostname, LAN address, static
password, or permissive cookie causes native-drivechain startup/use to fail.

Elements' own authenticated JSON-RPC server is also forced to numeric IPv4
`127/8` or IPv6 `::1` bindings on this native network. Its generated cookie is
the recommended credential; existing local `rpcauth` or static credentials
remain supported for Bitwindow compatibility. A wildcard, hostname, LAN, or
public `rpcbind` causes startup to fail. If another machine needs wallet access,
put an authenticated TLS service with a narrow RPC allowlist in front of the
loopback listener rather than exposing the node's HTTP RPC port.

Enforcer mutual TLS
-------------------

The current enforcer serves plaintext gRPC. Keep that listener on
`127.0.0.1:50051` and terminate mutual TLS at `127.0.0.1:55051`. The plaintext
hop must remain inside the same trusted host or an isolated container network.
The bundled helper creates a private CA plus distinct server and client
certificates:

```sh
contrib/drivechain-mtls/generate-certs.sh \
  "$HOME/.elements/elements-v1/enforcer-tls"
```

Protect `ca-key.pem` offline after issuance. Start the local proxy:

```sh
contrib/drivechain-mtls/run-stunnel-proxy.sh \
  "$HOME/.elements/elements-v1/enforcer-tls"
```

Then configure Elements:

```ini
drivechainbmmgrpcaddr=127.0.0.1:55051
drivechainbmmgrpcca=enforcer-tls/ca.pem
drivechainbmmgrpccert=enforcer-tls/elements-client.pem
drivechainbmmgrpckey=enforcer-tls/elements-client-key.pem
drivechainbmmgrpcauthority=enforcer.local
```

Relative credential paths resolve under the network data directory. On POSIX,
all credentials must be owned by the Elements process user and must not be
symlinks. The private key must be mode `0600`; certificates may be `0644` but
must not be group/other writable. Their containing directory must also be owned
by that user and must not be group/other writable. The proxy verifies the CA
chain, server certificate purpose, private-key integrity, and certificate/key
match before opening its listener.

Verify the proxy before enabling automatic block production:

```sh
grpcurl \
  -cacert "$HOME/.elements/elements-v1/enforcer-tls/ca.pem" \
  -cert "$HOME/.elements/elements-v1/enforcer-tls/elements-client.pem" \
  -key "$HOME/.elements/elements-v1/enforcer-tls/elements-client-key.pem" \
  -authority enforcer.local \
  127.0.0.1:55051 list
```

`-drivechainl1blocksync` defaults to off. When enabled, startup requires the
mTLS files to pass validation. `sendtomainchain` can create a local sidechain
burn without the enforcer, but `submitdrivechainwithdrawal` and BMM submission
fail before sending anything if mTLS configuration is absent or invalid.

Operational checks
------------------

Confirm that only loopback listeners exist:

```sh
lsof -nP -iTCP:38332 -iTCP:50051 -iTCP:55051 -sTCP:LISTEN
```

Expected listeners are Bitcoin RPC on `127.0.0.1:38332`, enforcer plaintext
gRPC on `127.0.0.1:50051`, and the mTLS proxy on `127.0.0.1:55051`. Stop Elements
before rotating client credentials. Restart the proxy, verify it with the
authenticated `grpcurl` command, and then restart Elements. Stop the proxy with
Ctrl-C or the process supervisor that launched it; it runs in the foreground so
failure is visible and superviseable.
