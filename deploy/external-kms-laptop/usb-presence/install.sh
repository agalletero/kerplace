#!/usr/bin/env bash
# Instala el sistema de presencia USB de custodia (sella el KMS al retirar el USB).
#   Uso:  sudo ./install.sh <USB_FS_UUID>
#   Obtén el UUID:  lsblk -o NAME,LABEL,UUID   (usa el del FILESYSTEM, no PARTUUID)
set -euo pipefail
UUID="${1:?uso: sudo ./install.sh <USB_FS_UUID>   (lsblk -o NAME,LABEL,UUID)}"
D="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "ejecútalo como root (sudo)"; exit 1; }

install -d /etc/kerplace
if [ ! -f /etc/kerplace/custody.env ]; then
  cat > /etc/kerplace/custody.env <<EOF
KP_CUSTODY_USB_UUID=$UUID
KP_KMS_ADDR=https://127.0.0.1:8200
KP_KMS_CACERT=/etc/openbao/tls/ca.crt
KP_KMS_SERVICE=openbao
KP_CUSTODY_POLL=2
EOF
else
  sed -i "s|^KP_CUSTODY_USB_UUID=.*|KP_CUSTODY_USB_UUID=$UUID|" /etc/kerplace/custody.env
fi

install -m 755 "$D/kerplace-kms-seal" "$D/kerplace-kms-presence" /usr/local/sbin/
install -m 644 "$D/kerplace-kms-seal.service" "$D/kerplace-kms-presence.service" /etc/systemd/system/
sed "s/@USB_FS_UUID@/$UUID/" "$D/99-kerplace-custody.rules.template" > /etc/udev/rules.d/99-kerplace-custody.rules

udevadm control --reload-rules
systemctl daemon-reload
systemctl enable --now kerplace-kms-presence.service

echo "[OK] presencia USB instalada. USB UUID=$UUID"
echo "     Recomendado en los HOSTS KerPlace: KP_KMS_CACHE_TTL=0 (bloqueo inmediato al sellar)."
echo "     Prueba: retira el USB -> el KMS debe sellarse y los s3fs desmontarse."
