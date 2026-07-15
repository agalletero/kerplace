#!/usr/bin/env bash
# Installs the custody USB presence system (seals the KMS when the USB is pulled).
#   Usage:  sudo ./install.sh <USB_FS_UUID>
#   Get the UUID:  lsblk -o NAME,LABEL,UUID   (use the FILESYSTEM's, not PARTUUID)
set -euo pipefail
UUID="${1:?usage: sudo ./install.sh <USB_FS_UUID>   (lsblk -o NAME,LABEL,UUID)}"
D="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run it as root (sudo)"; exit 1; }

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

echo "[OK] USB presence installed. USB UUID=$UUID"
echo "     Recommended on the KerPlace HOSTS: KP_KMS_CACHE_TTL=0 (immediate lockout on seal)."
echo "     Test it: pull the USB -> the KMS must seal and the s3fs mounts must go."
