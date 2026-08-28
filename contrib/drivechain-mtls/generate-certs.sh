#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 CREDENTIAL_DIRECTORY" >&2
  exit 2
fi

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}

umask 077
destination=$1
mkdir -p "$destination"
destination=$(cd "$destination" && pwd -P)
chmod 0700 "$destination"

files=(
  ca-key.pem ca.pem server-key.pem server.pem
  elements-client-key.pem elements-client.pem
)
for file in "${files[@]}"; do
  if [[ -e "$destination/$file" ]]; then
    echo "refusing to overwrite $destination/$file" >&2
    exit 1
  fi
done

temporary=$(mktemp -d "$destination/.issue.XXXXXX")
trap 'rm -rf "$temporary"' EXIT

openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -subj '/CN=Elements Drivechain Local CA' \
  -keyout "$destination/ca-key.pem" -out "$destination/ca.pem"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=enforcer.local' \
  -keyout "$destination/server-key.pem" -out "$temporary/server.csr"
cat >"$temporary/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:enforcer.local,IP:127.0.0.1
EOF
openssl x509 -req -sha256 -days 825 \
  -in "$temporary/server.csr" -CA "$destination/ca.pem" \
  -CAkey "$destination/ca-key.pem" -CAcreateserial \
  -extfile "$temporary/server.ext" -out "$destination/server.pem"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=elements-client' \
  -keyout "$destination/elements-client-key.pem" \
  -out "$temporary/client.csr"
cat >"$temporary/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:elements-client
EOF
openssl x509 -req -sha256 -days 825 \
  -in "$temporary/client.csr" -CA "$destination/ca.pem" \
  -CAkey "$destination/ca-key.pem" -CAserial "$destination/ca.srl" \
  -extfile "$temporary/client.ext" -out "$destination/elements-client.pem"

chmod 0600 "$destination/ca-key.pem" "$destination/server-key.pem" \
  "$destination/elements-client-key.pem"
chmod 0644 "$destination/ca.pem" "$destination/server.pem" \
  "$destination/elements-client.pem"

openssl verify -CAfile "$destination/ca.pem" \
  "$destination/server.pem" "$destination/elements-client.pem"
openssl x509 -checkend 86400 -noout -in "$destination/server.pem"
openssl x509 -checkend 86400 -noout -in "$destination/elements-client.pem"

echo "created mutually authenticated TLS credentials in $destination"
echo "move ca-key.pem offline after issuing any additional clients"
