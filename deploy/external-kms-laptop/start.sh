#!/usr/bin/env bash
#
# start.sh — levantador de contenedores del KMS (Vault persistente + TLS).
#
# Dos modos, según el estado:
#   - PRIMER ARRANQUE (Vault sin inicializar): bootstrap completo — inicializa,
#     des-sella en memoria, y configura Transit + policy + token scoped. Escribe
#     .vault-init.json EN DISCO temporalmente; muévelo al USB con:
#         ./adminKP.sh --provision-usb <ruta_USB>
#   - ESTADO ESTACIONARIO (ya inicializado): SIN SECRETOS — solo hace 'compose up'
#     y deja el Vault SELLADO. El des-sellado lo hace adminKP.sh desde el USB
#     ('./adminKP.sh --enable'). start.sh ya no auto-unsealea desde el disco.
#
# No usa 'set -e': 'vault status' sale con 2 cuando está sellado, lo cual es
# normal aquí, no un fallo.
cd "$(dirname "$0")" || exit 1
C=kerplace-vault
KEY=kerplace
dexec() { docker exec "$C" "$@"; }
dauth() { docker exec -e VAULT_TOKEN="$1" "$C" "${@:2}"; }
jget()  { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null; }

# Genera la CA privada + cert TLS de Vault en el primer arranque (idempotente).
[ -f vault/tls/ca.crt ] || ./gen-certs.sh || { echo "[ERR] fallo generando certificados"; exit 1; }

echo "[INFO] docker compose up -d"
docker compose up -d || exit 1

echo "[INFO] esperando a que Vault escuche (TLS)..."
st=""
for _ in $(seq 1 40); do
  st=$(dexec vault status -format=json 2>/dev/null)
  [ -n "$st" ] && break
  sleep 1
done
[ -z "$st" ] && { echo "[ERR] Vault no arrancó"; docker logs --tail 25 "$C"; exit 1; }

if [ "$(printf '%s' "$st" | jget '["initialized"]')" = "True" ]; then
  # ── Estado estacionario: sin secretos. Se deja SELLADO adrede.
  echo "[INFO] Vault ya inicializado — se deja SELLADO."
  echo "[INFO] des-séllalo desde el USB con:  ./adminKP.sh --enable"
  exit 0
fi

# ── Primer arranque: bootstrap (init + unseal en memoria + Transit + token).
echo "[INFO] inicializando Vault (1 unseal key, umbral 1)"
dexec vault operator init -key-shares=1 -key-threshold=1 -format=json > .vault-init.json || exit 1
chmod 600 .vault-init.json
echo "[INFO] unseal key + root token en ./.vault-init.json (TEMPORAL — muévelo al USB)"

UNSEAL=$(jget '["unseal_keys_b64"][0]' < .vault-init.json)
ROOT=$(jget '["root_token"]' < .vault-init.json)
[ -z "$ROOT" ] && { echo "[ERR] no hay root token en ./.vault-init.json"; exit 1; }

echo "[INFO] des-sellando (solo en el bootstrap)"
dexec vault operator unseal "$UNSEAL" >/dev/null || exit 1

echo "[INFO] configurando Transit + key + policy (idempotente)"
dauth "$ROOT" vault secrets enable transit 2>/dev/null || echo "[INFO] (transit ya habilitado)"
dauth "$ROOT" vault write -f "transit/keys/${KEY}" >/dev/null
dauth "$ROOT" sh -c 'cat > /tmp/p.hcl <<EOF
path "transit/datakey/plaintext/kerplace" { capabilities = ["update"] }
path "transit/decrypt/kerplace"           { capabilities = ["update"] }
EOF
vault policy write kerplace-kms /tmp/p.hcl' >/dev/null

if [ ! -s .kms-token ]; then
  echo "[INFO] acuñando token scoped para KerPlace"
  TOKEN=$(dauth "$ROOT" vault token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token)
  [ -z "$TOKEN" ] && { echo "[ERR] fallo acuñando token"; exit 1; }
  umask 077; printf '%s\n' "$TOKEN" > .kms-token
  echo "[INFO] token scoped -> ./.kms-token"
else
  echo "[INFO] token scoped ya presente (./.kms-token)"
fi

cat <<EOF

==================================================================
 KMS de KerPlace (persistente + TLS) listo y des-sellado (bootstrap).
   KP_KEY_PROVIDER = kms
   KP_KMS_ENDPOINT = https://localhost:8200   (vía túnel SSH inverso)
   KP_KMS_KEY      = ${KEY}
   KP_KMS_CA       = vault/tls/ca.crt   (cópialo al host de KerPlace)
   KP_KMS_TOKEN    = ./.kms-token
 Unseal key + root token: ./.vault-init.json
==================================================================

 SIGUIENTE PASO (obligatorio): saca el unseal del disco al USB de custodia:
   ./adminKP.sh --provision-usb <ruta_USB>
 A partir de ahí start.sh dejará el Vault sellado y adminKP.sh --enable lo
 des-sellará desde el USB. Haz --backup antes de borrar nada.
EOF
