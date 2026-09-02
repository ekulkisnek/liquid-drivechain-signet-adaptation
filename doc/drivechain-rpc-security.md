# Secure native Drivechain RPC setup

The current network is `-chain=elements`, data subdirectory `elements-v11`,
slot 24. It is not the historical Liquid-signet chain. See
[identity and peg operations](drivechain-peg-operations.md).

## Parent and wallet RPC

Run the fully validating parent on the same trusted host, with `txindex`
enabled and RPC bound only to loopback. The native default port is 18302:

```ini
mainchainrpchost=127.0.0.1
mainchainrpcport=18302
mainchainrpccookiefile=/absolute/path/to/parent-bitcoin/.cookie
drivechainl1blocksync=0
```

Do not configure `mainchainrpcuser` or `mainchainrpcpassword`. On POSIX the
rotating cookie must be a regular non-symlink file owned by the Elements user,
mode 0600, containing the canonical `__cookie__:` plus 64 hex characters.
The native default cookie location has no `signet/` suffix.
DNS names (including `localhost`), LAN addresses and inline parent credentials
are rejected. An explicit `mainchainrpccredentialfile` is also supported for a
trusted same-host bridge: it must be an owner-only, non-symlink private file
containing `user:password`, and cannot be combined with cookie or inline
credential options. Prefer the rotating cookie for direct parent access.
Verify the frozen parent checkpoint before using funds.

Elements' own authenticated JSON-RPC defaults to port 7065 and is restricted to
numeric loopback (IPv4 127/8 or IPv6 ::1). Use its generated cookie. Local
`rpcauth`/static credentials remain supported for existing clients. Native
`rest=1` is rejected because that listener bypasses RPC authentication.
Do not expose either HTTP listener on a LAN/public interface.

These local HTTP connections are authenticated but **not encrypted**. They
rely on trusted same-host isolation. Remote wallet access needs a separately
authenticated TLS tunnel/proxy with a narrow allowlist; never expose raw RPC.
This configuration does not protect against compromise of the host/user.

## Enforcer mutual TLS

All active enforcer operations, including BMM, withdrawal submission and
validation-data queries, use the same authenticated unary gRPC path. There is
no plaintext ConnectJSON fallback, bearer-cookie alternative, or PATH search.

Install a verified grpcurl binary into a private directory:

```sh
install -d -m 700 "$HOME/.local/libexec/elements"
install -m 700 /absolute/path/to/verified/grpcurl "$HOME/.local/libexec/elements/grpcurl"
```

The configured path must be absolute, regular, non-symlink, executable, owned
by the Elements user and inaccessible to group/others. Its immediate parent
directory must be owned by that user and not group/other writable. Protect the
whole ancestor tree too. The node checks permissions, not a published binary
checksum; verify provenance/hash before installation.

If the enforcer serves plaintext gRPC, bind it to `127.0.0.1:50051` and use
the bundled mTLS proxy on `127.0.0.1:55051`. The proxy-to-enforcer hop is
plaintext on the trusted host; this is not end-to-end TLS inside the enforcer.
Do not forward that plaintext listener to another host or an untrusted network.

```sh
contrib/drivechain-mtls/generate-certs.sh /absolute/path/to/elements-v11/enforcer-tls
contrib/drivechain-mtls/run-stunnel-proxy.sh /absolute/path/to/elements-v11/enforcer-tls
```

Configure absolute paths (relative credential paths resolve under the network
data directory):

```ini
drivechainbmmgrpcaddr=127.0.0.1:55051
drivechainbmmgrpcurl=/absolute/private/path/to/grpcurl
drivechainbmmgrpcca=/absolute/path/to/elements-v11/enforcer-tls/ca.pem
drivechainbmmgrpccert=/absolute/path/to/elements-v11/enforcer-tls/elements-client.pem
drivechainbmmgrpckey=/absolute/path/to/elements-v11/enforcer-tls/elements-client-key.pem
drivechainbmmgrpcauthority=enforcer.local
```

On POSIX, credential files and their immediate directory must be owned by the
Elements user and not group/other writable; files must not be symlinks. The
client private key requires mode 0600. The endpoint must be numeric loopback,
even with TLS. An optional deprecated `drivechainbmmwalletaddr` must exactly
match it; `drivechainbmmconnectauthcookie` is unsupported.
The external authenticated process path fails closed on Windows pending an
equivalent secure executable/credential implementation.

Verify with the installed executable:

```sh
/absolute/private/path/to/grpcurl \
  -cacert /absolute/path/to/elements-v11/enforcer-tls/ca.pem \
  -cert /absolute/path/to/elements-v11/enforcer-tls/elements-client.pem \
  -key /absolute/path/to/elements-v11/enforcer-tls/elements-client-key.pem \
  -authority enforcer.local 127.0.0.1:55051 list
```

Reflection must be enabled for this diagnostic; a service-method call can
instead be used with its descriptors. Missing/wrong client credentials must
fail the TLS handshake. No `-plaintext` or `-insecure` flag is appropriate.

## Production and rotation

Automatic `drivechainl1blocksync` currently defaults **on**. Explicitly set it
to 0 during read-only setup. Enforcer calls fail closed at use when credentials
or the executable are invalid; this is not a guarantee of a startup TLS probe.
A native `sendtomainchain` burn can be created without an available enforcer,
so verify the submission path before burning coins.

The helper issues a 365-day CA and 90-day server/client certificates and refuses
to overwrite existing credentials. Move the CA private key offline. Monitor
expiry in advance:

```sh
openssl x509 -checkend 1209600 -noout -in /absolute/path/to/enforcer-tls/elements-client.pem
openssl x509 -checkend 1209600 -noout -in /absolute/path/to/enforcer-tls/server.pem
```

Rotate using a newly issued private directory. Stop block production/Elements
and the proxy, switch both configurations to the new matching credentials,
start the proxy, verify authentication, then restart Elements. Do not delete
working credentials before verification. Stop the foreground proxy with its
supervisor or Ctrl-C.

Check listeners with `lsof -nP -iTCP -sTCP:LISTEN`: ports 18302, 7065, 50051
and 55051 must not listen publicly. No environment variables may bypass
withdrawal event verification or silently select another fee/slot/endpoint.
The legacy ECX-only `drivechainpegoutmainfeesats` option is not the native
`sendtomainchain` RPC's explicit coin-denominated `mainchainfee` argument.
