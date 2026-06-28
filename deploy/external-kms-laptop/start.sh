#!/usr/bin/env bash
#
# Bring up the persistent + TLS Vault, initialise & unseal it on first run, and
# ensure the Transit engine / key / scoped token are configured. Idempotent —
# also safe to run on every boot (used by the systemd unit) to auto-unseal.
#
# No `set -e`: `vault status` deliberately exits 2 when sealed, which is normal
# here, not a failure.
cd "$(dirname "$0")" || exit 1
C=kerplace-vault
KEY=kerplace
dexec() { docker exec "$C" "$@"; }
dauth() { docker exec -e VAULT_TOKEN="$1" "$C" "${@:2}"; }
jget()  { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null; }

# Generate the private CA + Vault TLS cert on first run (idempotent).
[ -f vault/tls/ca.crt ] || ./gen-certs.sh || { echo "✗ cert generation failed"; exit 1; }

echo "▶ docker compose up -d"
docker compose up -d || exit 1

echo "▶ waiting for Vault to listen (TLS)..."
st=""
for _ in $(seq 1 40); do
  st=$(dexec vault status -format=json 2>/dev/null)
  [ -n "$st" ] && break
  sleep 1
done
[ -z "$st" ] && { echo "✗ Vault did not come up"; docker logs --tail 25 "$C"; exit 1; }

if [ "$(printf '%s' "$st" | jget '["initialized"]')" != "True" ]; then
  echo "▶ initialising Vault (1 unseal key, threshold 1)"
  dexec vault operator init -key-shares=1 -key-threshold=1 -format=json > .vault-init.json || exit 1
  chmod 600 .vault-init.json
  echo "  unseal key + root token saved to ./.vault-init.json (BACK THIS UP)"
else
  echo "▶ Vault already initialised"
fi

UNSEAL=$(jget '["unseal_keys_b64"][0]' < .vault-init.json)
ROOT=$(jget '["root_token"]' < .vault-init.json)
[ -z "$ROOT" ] && { echo "✗ no root token in ./.vault-init.json"; exit 1; }

if [ "$(dexec vault status -format=json 2>/dev/null | jget '["sealed"]')" = "True" ]; then
  echo "▶ unsealing"
  dexec vault operator unseal "$UNSEAL" >/dev/null || exit 1
fi

echo "▶ ensuring Transit engine + key + policy (idempotent)"
dauth "$ROOT" vault secrets enable transit 2>/dev/null || echo "  (transit already enabled)"
dauth "$ROOT" vault write -f "transit/keys/${KEY}" >/dev/null
dauth "$ROOT" sh -c 'cat > /tmp/p.hcl <<EOF
path "transit/datakey/plaintext/kerplace" { capabilities = ["update"] }
path "transit/decrypt/kerplace"           { capabilities = ["update"] }
EOF
vault policy write kerplace-kms /tmp/p.hcl' >/dev/null

if [ ! -s .kms-token ]; then
  echo "▶ minting scoped token for KerPlace"
  TOKEN=$(dauth "$ROOT" vault token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token)
  [ -z "$TOKEN" ] && { echo "✗ failed to mint token"; exit 1; }
  umask 077; printf '%s\n' "$TOKEN" > .kms-token
  echo "  scoped token -> ./.kms-token"
else
  echo "▶ scoped token already present (./.kms-token)"
fi

cat <<EOF

==================================================================
 KerPlace KMS (persistent + TLS) ready & unsealed.
   KP_KEY_PROVIDER = kms
   KP_KMS_ENDPOINT = https://localhost:8200   (via SSH reverse tunnel)
   KP_KMS_KEY      = ${KEY}
   KP_KMS_CA       = vault/tls/ca.crt   (copy to the KerPlace host)
   KP_KMS_TOKEN    = ./.kms-token
 Unseal key + root token: ./.vault-init.json  — BACK THIS UP, losing it = data unrecoverable.
==================================================================
EOF
