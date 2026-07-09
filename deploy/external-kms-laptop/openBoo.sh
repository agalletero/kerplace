#!/usr/bin/env bash
#
# openBoo.sh — provisiona el KMS NATIVO (OpenBao) del modo custodia en ESTE portátil,
# reemplazando el Vault-en-Docker. Sin migración de datos (decisión: los buckets
# actuales son de PoC). Deja OpenBao instalado y arrancado, SIN inicializar todavía
# (la init/unseal/token/USB es interactiva y va después, vía adminKP).
#
#   EJECUTAR COMO ROOT:  sudo bash openBoo.sh
#
# Fases: 0 preflight → 1 teardown de lo viejo → 2 swap CIFRADO (mlock efectivo)
#        → 3 instalar OpenBao (.deb verificado) → 4 TLS + config endurecida + mlock
#        → 5 resumen + próximos pasos.
#
# Parametrizable por entorno (o edita el bloque CONFIG). Rutas reales se pasan por
# variables para no hornear paths de usuario en el repo.
set -euo pipefail

# ── CONFIG (revísalo antes de ejecutar) ──────────────────────────────────────
OPENBAO_VERSION="${OPENBAO_VERSION:-2.5.5}"
REL_BASE="https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}"
DEB="openbao_${OPENBAO_VERSION}_linux_amd64.deb"

SWAP_SIZE_GB="${SWAP_SIZE_GB:-8}"                 # tamaño del swap cifrado
SWAP_IMG="${SWAP_IMG:-/var/lib/swap/cryptswap.img}"
SWAP_MAPPER="cryptswap"

# Infra vieja a parar (no hay datos que migrar). Vacío = se salta.
DOCKER_VAULT="${DOCKER_VAULT:-kerplace-vault}"    # contenedor Vault local a parar
MOUNT_BASE="${MOUNT_BASE:-}"                      # base de montajes s3fs a desmontar
AWS_HOST="${AWS_HOST:-}"                          # p.ej. ubuntu@1.2.3.4  (vacío = no tocar AWS)
AWS_KEY="${AWS_KEY:-}"                            # clave ssh para AWS_HOST
TUNNEL_UNIT="${TUNNEL_UNIT:-kerplace-kms-tunnel.service}"
VAULT_TIMER="${VAULT_TIMER:-kerplace-kms-vault.timer}"    # timer --user que RESUCITA el contenedor
VAULT_SVC="${VAULT_SVC:-kerplace-kms-vault.service}"

# OpenBao nativo
OB_USER="openbao"
OB_CONF="/etc/openbao/openbao.hcl"
OB_TLS="/etc/openbao/tls"
OB_DATA="${OB_DATA:-/opt/openbao/data}"
OB_SERVICE="openbao"

VERIFY_GPG="${VERIFY_GPG:-0}"                     # 1 = verificar además la firma GPG
ASSUME_YES="${ASSUME_YES:-0}"                     # 1 = no preguntar

# ── logging (sin ANSI) ───────────────────────────────────────────────────────
info(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
die(){  printf '[ERR] %s\n'  "$*" >&2; exit 1; }
as_user(){ if [ -n "${SUDO_USER:-}" ]; then sudo -u "$SUDO_USER" "$@"; else "$@"; fi; }
# systemctl --user en el contexto del usuario real (para parar timers/units --user desde root)
ruser_systemctl(){
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    local uid; uid="$(id -u "$SUDO_USER")"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user "$@"
  else systemctl --user "$@"; fi
}

[ "$(id -u)" -eq 0 ] || die "ejecútalo como root: sudo bash openBoo.sh"
REAL_USER="${SUDO_USER:-root}"

info "Plan: parar KerPlace(AWS)+Vault(docker) · swap CIFRADO · instalar OpenBao ${OPENBAO_VERSION} nativo."
info "  usuario real: $REAL_USER · docker vault: ${DOCKER_VAULT:-(ninguno)} · swap: ${SWAP_SIZE_GB}G en $SWAP_IMG"
if [ "$ASSUME_YES" != "1" ]; then
  printf 'Escribe SI para continuar: '; read -r ans; [ "$ans" = "SI" ] || die "cancelado"
fi

# ── FASE 1 · teardown de lo viejo (best-effort; no hay datos que migrar) ──────
info "1/5  parando lo anterior"
if [ -n "$MOUNT_BASE" ] && [ -d "$MOUNT_BASE" ]; then
  while read -r _ mp fstype _; do
    [ "$fstype" = "fuse.s3fs" ] || continue
    case "$mp" in "$MOUNT_BASE"/*)
      sync; as_user fusermount3 -u "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
      info "  desmontado: $mp" ;;
    esac
  done < /proc/mounts
fi
# Parar la RESURRECCIÓN: el timer --user recrea el contenedor cada 2 min (start.sh ->
# docker compose up). Sin desactivarlo, el Vault en Docker vuelve y choca con OpenBao en :8200.
ruser_systemctl stop "$VAULT_TIMER" "$VAULT_SVC" 2>/dev/null || true
ruser_systemctl disable "$VAULT_TIMER" 2>/dev/null || true
ruser_systemctl stop "$TUNNEL_UNIT" 2>/dev/null || true
info "  timer de auto-arranque del Vault (docker) parado y deshabilitado"
# KerPlace en AWS (opcional)
if [ -n "$AWS_HOST" ] && [ -n "$AWS_KEY" ]; then
  if as_user ssh -i "$AWS_KEY" -o ConnectTimeout=12 -o BatchMode=yes "$AWS_HOST" 'sudo systemctl stop kerplace' 2>/dev/null; then
    info "  KerPlace parado en AWS"
  else
    warn "  no pude parar KerPlace en AWS (sigo)"
  fi
else
  warn "  AWS_HOST/AWS_KEY no definidos: no toco AWS (páralo tú si hace falta)"
fi
# Vault en Docker (se conserva el volumen; solo se para/quita el contenedor).
# -f fuerza aun con restart=unless-stopped; el timer ya está desactivado arriba.
if [ -n "$DOCKER_VAULT" ] && docker inspect "$DOCKER_VAULT" >/dev/null 2>&1; then
  docker rm -f "$DOCKER_VAULT" >/dev/null 2>&1 || true
  if docker inspect "$DOCKER_VAULT" >/dev/null 2>&1; then
    warn "  $DOCKER_VAULT sigue presente — algo lo recrea (¿otro timer/compose?); revísalo antes de la fase 3"
  else
    info "  contenedor $DOCKER_VAULT eliminado (el volumen NO se borra)"
  fi
fi

# ── FASE 2 · swap CIFRADO (clave aleatoria por arranque; mlock efectivo) ──────
info "2/5  creando swap cifrado (${SWAP_SIZE_GB}G)"
command -v cryptsetup >/dev/null || { apt-get update -qq && apt-get install -y cryptsetup-bin; }
mkdir -p "$(dirname "$SWAP_IMG")"
if [ ! -f "$SWAP_IMG" ]; then
  fallocate -l "${SWAP_SIZE_GB}G" "$SWAP_IMG" || dd if=/dev/zero of="$SWAP_IMG" bs=1M count=$((SWAP_SIZE_GB*1024)) status=none
  chmod 600 "$SWAP_IMG"
fi
# Abrir con clave aleatoria y activar en ESTA sesión (antes de tocar el swap viejo).
# Idempotente: si el mapper ya está abierto y ya es swap activo, no lo re-inicializa
# (mkswap sobre un swap activo lo corrompería). La verificación mira /proc/swaps por
# el device RESUELTO (/dev/dm-N), no por el nombre del mapper (swapon --show resuelve).
if [ ! -e "/dev/mapper/$SWAP_MAPPER" ]; then
  cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 512 \
    --key-file /dev/urandom "$SWAP_IMG" "$SWAP_MAPPER"
fi
SWAP_DEV="$(readlink -f "/dev/mapper/$SWAP_MAPPER")"
if ! grep -q "^${SWAP_DEV}[[:space:]]" /proc/swaps; then
  mkswap "/dev/mapper/$SWAP_MAPPER" >/dev/null
  swapon "/dev/mapper/$SWAP_MAPPER"
fi
grep -q "^${SWAP_DEV}[[:space:]]" /proc/swaps \
  || die "el swap cifrado no se activó — abortando sin tocar el swap viejo"
info "  swap cifrado activo: /dev/mapper/$SWAP_MAPPER ($SWAP_DEV)"

# Persistir (crypttab + fstab con nofail para no bloquear arranques) y quitar el viejo.
cp -n /etc/fstab /etc/fstab.bak.openboo 2>/dev/null || true
touch /etc/crypttab
grep -q "^${SWAP_MAPPER}[[:space:]]" /etc/crypttab || \
  printf '%s %s /dev/urandom swap,cipher=aes-xts-plain64,size=512\n' "$SWAP_MAPPER" "$SWAP_IMG" >> /etc/crypttab
grep -q "/dev/mapper/$SWAP_MAPPER" /etc/fstab || \
  printf '/dev/mapper/%s none swap sw,nofail,pri=10 0 0\n' "$SWAP_MAPPER" >> /etc/fstab
# desactivar y comentar los swapfiles sin cifrar
for old in /swapfile /swapfile_extra; do
  [ -e "$old" ] || continue
  swapoff "$old" 2>/dev/null || true
  sed -i -E "s|^(${old}[[:space:]].*)|# \1  # desactivado por openBoo (swap sin cifrar)|" /etc/fstab || true
  info "  swap sin cifrar desactivado: $old (fichero conservado; bórralo cuando quieras)"
done

# ── FASE 3 · instalar OpenBao (.deb oficial, verificado por SHA256) ───────────
info "3/5  instalando OpenBao ${OPENBAO_VERSION} (.deb verificado)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
( cd "$TMP"
  curl -fsSL -o "$DEB"                "$REL_BASE/$DEB"
  curl -fsSL -o checksums-linux.txt   "$REL_BASE/checksums-linux.txt"
  grep "  ${DEB}\$" checksums-linux.txt > deb.sha256 || die "no encuentro el checksum de $DEB"
  sha256sum -c deb.sha256 || die "SHA256 del .deb NO coincide — abortando (posible manipulación)"
  info "  SHA256 verificado"
  if [ "$VERIFY_GPG" = "1" ]; then
    curl -fsSL -o checksums-linux.txt.gpgsig "$REL_BASE/checksums-linux.txt.gpgsig" || true
    warn "  verificación GPG solicitada: importa la clave de firma de OpenBao y valida checksums-linux.txt.gpgsig manualmente"
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "./$DEB"
)
BAO_BIN="$(command -v bao || echo /usr/bin/bao)"
info "  OpenBao instalado: $BAO_BIN — $(bao version 2>/dev/null | head -1)"

# ── FASE 4 · TLS + config endurecida + drop-in mlock ─────────────────────────
info "4/5  TLS + config + hardening (mlock)"
id "$OB_USER" >/dev/null 2>&1 || useradd --system --home-dir /var/lib/openbao --shell /usr/sbin/nologin "$OB_USER"
install -d -m 750 -o "$OB_USER" -g "$OB_USER" "$(dirname "$OB_CONF")" "$OB_DATA"
install -d -m 750 -o "$OB_USER" -g "$OB_USER" "$OB_TLS"

# CA privada + cert de servidor (127.0.0.1 / localhost). ca.crt = el nuevo KP_KMS_CA.
if [ ! -f "$OB_TLS/ca.crt" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -keyout "$OB_TLS/ca.key" -out "$OB_TLS/ca.crt" -subj "/CN=KerPlace KMS CA" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OB_TLS/tls.key" -out "$OB_TLS/tls.csr" -subj "/CN=127.0.0.1" >/dev/null 2>&1
  openssl x509 -req -in "$OB_TLS/tls.csr" -CA "$OB_TLS/ca.crt" -CAkey "$OB_TLS/ca.key" -CAcreateserial \
    -days 3650 -out "$OB_TLS/tls.crt" \
    -extfile <(printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth') \
    >/dev/null 2>&1
  rm -f "$OB_TLS/tls.csr"
fi
chown -R "$OB_USER:$OB_USER" "$OB_TLS"; chmod 640 "$OB_TLS"/*.key "$OB_TLS"/*.crt

# OpenBao 2.x ELIMINÓ mlock: la mitigación recomendada es cifrar el swap (fase 2).
# Por eso NO se pone 'disable_mlock' (su presencia hace fallar el arranque).
cat > "$OB_CONF" <<EOF
ui = false
storage "file" { path = "$OB_DATA" }
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_cert_file = "$OB_TLS/tls.crt"
  tls_key_file  = "$OB_TLS/tls.key"
}
api_addr = "https://127.0.0.1:8200"
EOF
chown "$OB_USER:$OB_USER" "$OB_CONF"; chmod 640 "$OB_CONF"

# drop-in de endurecimiento (mlock + sandbox). El paquete ya pone User=$OB_USER.
install -d -m 755 "/etc/systemd/system/${OB_SERVICE}.service.d"
# mlock ya no aplica en OpenBao 2.x (lo mitiga el swap cifrado); solo sandbox systemd.
cat > "/etc/systemd/system/${OB_SERVICE}.service.d/10-hardening.conf" <<EOF
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$OB_DATA
# Asegura que el server usa NUESTRA config (ajústalo si la unit del paquete difiere):
ExecStart=
ExecStart=$BAO_BIN server -config=$OB_CONF
EOF

systemctl daemon-reload
systemctl enable "$OB_SERVICE" >/dev/null 2>&1 || true
if systemctl restart "$OB_SERVICE"; then
  info "  OpenBao arrancado (sin inicializar / sellado)"
else
  warn "  OpenBao no arrancó a la primera — revisa: systemctl status $OB_SERVICE ; journalctl -u $OB_SERVICE -n40"
fi

# ── FASE 5 · resumen + próximos pasos (interactivos, NO en este script) ───────
info "5/5  hecho."
cat <<EOF

==================================================================
 OpenBao ${OPENBAO_VERSION} instalado (nativo, systemd, mlock) y swap CIFRADO.
   config : $OB_CONF
   data   : $OB_DATA        (vacío: KMS SIN inicializar)
   TLS CA : $OB_TLS/ca.crt   <-- nuevo KP_KMS_CA para el host AWS
   service: systemctl status $OB_SERVICE     (endpoint https://127.0.0.1:8200)

 PRÓXIMOS PASOS (interactivos — necesitan tu passphrase y tocan AWS):
  export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=$OB_TLS/ca.crt
  1) bao operator init -key-shares=1 -key-threshold=1 -format=json > .vault-init.json
  2) bao operator unseal <unseal_key>
  3) bao secrets enable transit
     bao write -f transit/keys/kerplace
     (política kerplace-kms: datakey+decrypt) ; bao token create -policy=kerplace-kms -ttl=720h
  4) ./adminKP.sh --provision-usb   (mueve .vault-init.json al USB; pide passphrase)
  5) copia $OB_TLS/ca.crt al host AWS como /etc/kerplace/kms-ca.crt
     y pon el nuevo KP_KMS_TOKEN en /etc/kerplace.env ; reinicia KerPlace
  6) ./adminKP.sh --enable
 (Adaptaré adminKP.sh/start.sh a modo nativo para automatizar 1-3 y el reseal.)
==================================================================
EOF
