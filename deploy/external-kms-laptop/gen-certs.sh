#!/usr/bin/env bash
#
# Generate a private CA + a Vault server TLS certificate (SAN: localhost,
# 127.0.0.1) into ./vault/tls/. Idempotent: does nothing if ca.crt already
# exists. ca.crt is what you copy to the KerPlace host as KP_KMS_CA.
set -e
cd "$(dirname "$0")"
mkdir -p vault/tls
cd vault/tls

[ -f ca.crt ] && { echo "certs already present (vault/tls/ca.crt) — skipping"; exit 0; }

echo "▶ private CA"
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/CN=KerPlace-KMS-CA" -out ca.crt 2>/dev/null

echo "▶ Vault server cert (SAN localhost,127.0.0.1) signed by the CA"
openssl genrsa -out vault.key 2048 2>/dev/null
openssl req -new -key vault.key -subj "/CN=localhost" -out vault.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > san.cnf
openssl x509 -req -in vault.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -sha256 -extfile san.cnf -out vault.crt 2>/dev/null

# in-container vault user (uid 100) must read these; this is a local single-user host
chmod 644 ca.crt vault.crt vault.key
rm -f vault.csr san.cnf
echo "✓ vault/tls/{ca.crt,vault.crt,vault.key} ready (copy ca.crt to the KerPlace host as KP_KMS_CA)"
