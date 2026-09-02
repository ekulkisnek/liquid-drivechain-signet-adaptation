#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 CREDENTIAL_DIRECTORY [LISTEN_HOST:PORT] [UPSTREAM_HOST:PORT]" >&2
  exit 2
fi

command -v stunnel >/dev/null 2>&1 || {
  echo "stunnel is required (macOS: brew install stunnel)" >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}

credentials=$(cd "$1" && pwd -P)
listen=${2:-127.0.0.1:55051}
upstream=${3:-127.0.0.1:50051}
for file in ca.pem server.pem server-key.pem; do
  [[ -f "$credentials/$file" && ! -L "$credentials/$file" ]] || {
    echo "missing non-symlink credential: $credentials/$file" >&2
    exit 1
  }
done

stat_owner_mode() {
  if stat -f '%u %Lp' "$1" >/dev/null 2>&1; then
    stat -f '%u %Lp' "$1"
  else
    stat -c '%u %a' "$1"
  fi
}

read -r directory_owner directory_mode < <(stat_owner_mode "$credentials")
if [[ $directory_owner != "$(id -u)" || $((8#$directory_mode & 8#022)) -ne 0 ]]; then
  echo "credential directory must be owned by the current user and deny group/other write access: $credentials" >&2
  exit 1
fi

for file in ca.pem server.pem; do
  read -r file_owner file_mode < <(stat_owner_mode "$credentials/$file")
  if [[ $file_owner != "$(id -u)" || $((8#$file_mode & 8#022)) -ne 0 ]]; then
    echo "certificate must be owned by the current user and deny group/other write access: $credentials/$file" >&2
    exit 1
  fi
done
read -r key_owner key_mode < <(stat_owner_mode "$credentials/server-key.pem")
if [[ $key_owner != "$(id -u)" || $((8#$key_mode & 8#077)) -ne 0 ]]; then
  echo "server key must be owned by the current user and deny all group/other access: $credentials/server-key.pem" >&2
  exit 1
fi

openssl verify -purpose sslserver -CAfile "$credentials/ca.pem" \
  "$credentials/server.pem" >/dev/null
openssl pkey -in "$credentials/server-key.pem" -check -noout >/dev/null
certificate_key=$(openssl x509 -in "$credentials/server.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
private_key=$(openssl pkey -in "$credentials/server-key.pem" -pubout -outform DER 2>/dev/null | \
  openssl dgst -sha256)
if [[ -z $certificate_key || $certificate_key != "$private_key" ]]; then
  echo "server certificate does not match server private key" >&2
  exit 1
fi

is_loopback_endpoint() {
  local endpoint=$1 octet port
  if [[ $endpoint =~ ^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,5})$ ]]; then
    port=${BASH_REMATCH[4]}
    for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"; do
      [[ $octet == 0 || $octet != 0* ]] || return 1
      ((10#$octet <= 255)) || return 1
    done
  elif [[ $endpoint =~ ^\[::1\]:([0-9]{1,5})$ ]]; then
    port=${BASH_REMATCH[1]}
  else
    return 1
  fi
  ((10#$port >= 1 && 10#$port <= 65535))
}

is_loopback_endpoint "$listen" || {
  echo "refusing non-loopback or invalid TLS listen endpoint: $listen" >&2; exit 1
}
is_loopback_endpoint "$upstream" || {
  echo "refusing non-loopback or invalid plaintext upstream: $upstream" >&2; exit 1
}

configuration=$(mktemp "${TMPDIR:-/tmp}/elements-enforcer-stunnel.XXXXXX")
trap 'rm -f "$configuration"' EXIT
chmod 0600 "$configuration"
cat >"$configuration" <<EOF
foreground = yes
pid =

[elements-enforcer-grpc]
client = no
accept = $listen
connect = $upstream
cert = $credentials/server.pem
key = $credentials/server-key.pem
CAfile = $credentials/ca.pem
verifyChain = yes
requireCert = yes
checkHost = elements-client
TIMEOUTclose = 0
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
EOF

exec stunnel "$configuration"
