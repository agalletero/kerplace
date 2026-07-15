#!/usr/bin/env bash
#
# start.sh — brings up the KMS containers (persistent Vault + TLS).
#
# Two modes, depending on state:
#   - FIRST RUN (Vault uninitialised): full bootstrap — initialise, unseal in
#     memory, and configure Transit + policy + a scoped token. It writes
#     .vault-init.json TO DISK temporarily; move it onto the USB with:
#         ./adminKP.sh --provision-usb <USB_path>
#   - STEADY STATE (already initialised): NO SECRETS — it only runs 'compose up'
#     and leaves Vault SEALED. Unsealing is adminKP.sh's job, from the USB
#     ('./adminKP.sh --enable'). start.sh no longer auto-unseals from disk.
#
# It does not use 'set -e': 'vault status' exits with 2 when sealed, which is
# normal here rather than a failure.
cd "$(dirname "$0")" || exit 1
C=kerplace-vault
KEY=kerplace
dexec() { docker exec "$C" "$@"; }
dauth() { docker exec -e VAULT_TOKEN="$1" "$C" "${@:2}"; }
jget()  { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null; }

# Generate Vault's private CA + TLS cert on the first run (idempotent).
[ -f vault/tls/ca.crt ] || ./gen-certs.sh || { echo "[ERR] failed to generate certificates"; exit 1; }

echo "[INFO] docker compose up -d"
docker compose up -d || exit 1

echo "[INFO] waiting for Vault to listen (TLS)..."
st=""
for _ in $(seq 1 40); do
  st=$(dexec vault status -format=json 2>/dev/null)
  [ -n "$st" ] && break
  sleep 1
done
[ -z "$st" ] && { echo "[ERR] Vault did not start"; docker logs --tail 25 "$C"; exit 1; }

if [ "$(printf '%s' "$st" | jget '["initialized"]')" = "True" ]; then
  # ── Steady state: no secrets. Deliberately left SEALED.
  echo "[INFO] Vault already initialised — leaving it SEALED."
  echo "[INFO] unseal it from the USB with:  ./adminKP.sh --enable"
  exit 0
fi

# ── First run: bootstrap (init + in-memory unseal + Transit + token).
echo "[INFO] initialising Vault (1 unseal key, threshold 1)"
dexec vault operator init -key-shares=1 -key-threshold=1 -format=json > .vault-init.json || exit 1
chmod 600 .vault-init.json
echo "[INFO] unseal key + root token in ./.vault-init.json (TEMPORARY — move it to the USB)"

UNSEAL=$(jget '["unseal_keys_b64"][0]' < .vault-init.json)
ROOT=$(jget '["root_token"]' < .vault-init.json)
[ -z "$ROOT" ] && { echo "[ERR] no root token in ./.vault-init.json"; exit 1; }

echo "[INFO] unsealing (bootstrap only)"
dexec vault operator unseal "$UNSEAL" >/dev/null || exit 1

echo "[INFO] configuring Transit + key + policy (idempotent)"
dauth "$ROOT" vault secrets enable transit 2>/dev/null || echo "[INFO] (transit already enabled)"
dauth "$ROOT" vault write -f "transit/keys/${KEY}" >/dev/null
dauth "$ROOT" sh -c 'cat > /tmp/p.hcl <<EOF
path "transit/datakey/plaintext/kerplace" { capabilities = ["update"] }
path "transit/decrypt/kerplace"           { capabilities = ["update"] }
EOF
vault policy write kerplace-kms /tmp/p.hcl' >/dev/null

if [ ! -s .kms-token ]; then
  echo "[INFO] minting a scoped token for KerPlace"
  TOKEN=$(dauth "$ROOT" vault token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token)
  [ -z "$TOKEN" ] && { echo "[ERR] failed to mint the token"; exit 1; }
  umask 077; printf '%s\n' "$TOKEN" > .kms-token
  echo "[INFO] scoped token -> ./.kms-token"
else
  echo "[INFO] scoped token already present (./.kms-token)"
fi

cat <<EOF

==================================================================
 KerPlace's KMS (persistent + TLS) is ready and unsealed (bootstrap).
   KP_KEY_PROVIDER = kms
   KP_KMS_ENDPOINT = https://localhost:8200   (via the reverse SSH tunnel)
   KP_KMS_KEY      = ${KEY}
   KP_KMS_CA       = vault/tls/ca.crt   (copy it to the KerPlace host)
   KP_KMS_TOKEN    = ./.kms-token
 Unseal key + root token: ./.vault-init.json
==================================================================

 NEXT STEP (required): move the unseal material off the disk and onto the
 custody USB:
   ./adminKP.sh --provision-usb <USB_path>
 From then on start.sh leaves Vault sealed and 'adminKP.sh --enable' unseals it
 from the USB. Take a --backup before deleting anything.
EOF
