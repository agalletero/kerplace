#!/usr/bin/env bash
#
# adminKP.sh — control estilo "VPN" de un KerPlace remoto cuyas claves viven en
# ESTE portátil (custodia KMS off-host). Ver docs/OFFHOST_KMS_CUSTODY.md.
#
# Toda la configuración se lee de un fichero de entorno (variables KP_ADMIN_*):
#   ${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env   (o --config <ruta>)
# Copia adminkp.env.example, rellénalo y protégelo (chmod 600).
#
# Subcomandos:
#   --enable                 conectar: Vault up -> unseal (USB) -> túnel ->
#                            arrancar KerPlace en el host -> montar buckets (s3fs)
#   --disable                desconectar: desmontar -> parar KerPlace -> bajar túnel
#                            -> borrar el passwd de s3fs del disco
#   --mount  <bucket> [pt]   montar UN bucket (pt por defecto: <MOUNT_BASE>/<bucket>)
#   --umount <bucket|pt>     desmontar UN bucket (por nombre o por ruta)
#   --backup [dir]           snapshot cifrado del KMS en DOS artefactos (datos /
#                            unseal) con passphrases independientes (+ RESTORE.md)
#   --provision-usb [ruta]   migrar el material de unseal del disco al USB cifrado
#   --status                 mostrar qué está activo / montado
#   --config <ruta>          usar otro fichero de configuración (flag global)
#
set -u

# ── logging (sin colores; prefijos [INFO]/[WARN]/[ERR]/[DEBUG]) ───────────────
info(){ printf '[INFO] %s\n'  "$*"; }
warn(){ printf '[WARN] %s\n'  "$*" >&2; }
err(){  printf '[ERR] %s\n'   "$*" >&2; }
dbg(){  [ -n "${KP_ADMIN_DEBUG:-}" ] && printf '[DEBUG] %s\n' "$*" >&2 || true; }
die(){  err "$*"; exit 1; }

# ── flag global --config (debe ir el primero) ────────────────────────────────
CONFIG_PATH="${KP_ADMIN_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env}"
if [ "${1:-}" = "--config" ]; then
  [ -n "${2:-}" ] || die "--config requiere una ruta"
  CONFIG_PATH="$2"; shift 2
fi

usage(){ cat <<'U'
adminKP.sh — control "VPN" de un KerPlace remoto con custodia de claves local.
Ver docs/OFFHOST_KMS_CUSTODY.md. Configuración: <XDG_CONFIG_HOME>/kerplace/adminkp.env

  --enable                 Vault up -> unseal(USB) -> túnel -> arrancar KerPlace
                           -> montar CADA bucket bajo <MOUNT_BASE>/<name>
  --disable                desmontar -> parar KerPlace -> bajar túnel -> borrar passwd
  --mount  <bucket> [pt]   montar UN bucket (pt por defecto: <MOUNT_BASE>/<bucket>)
  --umount <bucket|pt>     desmontar UN bucket (por nombre o por ruta)
  --backup [dir]           snapshot cifrado del KMS en 2 artefactos (+ RESTORE.md)
  --provision-usb [ruta]   mover el material de unseal del disco al USB cifrado
  --status                 mostrar qué está activo / montado
  --config <ruta>          usar otro fichero de configuración (flag global)
U
}

case "${1:---help}" in
  --help|-h|help) usage; exit 0 ;;
esac

# ── carga y validación de la configuración ───────────────────────────────────
[ -f "$CONFIG_PATH" ] || die "configuración no encontrada: $CONFIG_PATH
Copia adminkp.env.example ahí y rellena las variables KP_ADMIN_* (chmod 600)."
# shellcheck source=/dev/null
. "$CONFIG_PATH"

CONFIG_DIR="$(dirname "$CONFIG_PATH")"
# Valores por defecto (los obligatorios NO tienen default; ver validación abajo).
: "${KP_ADMIN_S3_ENDPOINT:=http://127.0.0.1:9000}"     # loopback: el cifrado en tránsito lo da el túnel SSH (T1)
: "${KP_ADMIN_MOUNT_BASE:=$HOME/buckets}"
: "${KP_ADMIN_TUNNEL_UNIT:=kerplace-kms-tunnel.service}"
: "${KP_ADMIN_USB_LABEL:=KPCUSTODY}"
: "${KP_ADMIN_USB_FILE:=kerplace-custody/unseal.json.gpg}"
: "${KP_ADMIN_KNOWN_HOSTS:=$CONFIG_DIR/known_hosts}"
: "${KP_ADMIN_KEX:=mlkem768x25519-sha256}"             # KEX PQC fijado por política (T4)
: "${KP_ADMIN_VAULT_CONTAINER:=kerplace-vault}"
: "${KP_ADMIN_VAULT_VOLUME:=kerplace-kms_vault-data}"
: "${KP_ADMIN_PASSWD_S3FS:=$HOME/.passwd-s3fs-adminkp}"

_missing=""
for _v in KP_ADMIN_HOST KP_ADMIN_SSH_KEY KP_ADMIN_ACCESS_KEY KP_ADMIN_SECRET_FILE KP_ADMIN_KMS_DIR; do
  [ -n "${!_v:-}" ] || _missing="$_missing $_v"
done
[ -z "$_missing" ] || die "faltan variables obligatorias en $CONFIG_PATH:$_missing"

# Opciones SSH endurecidas (T4): KEX post-cuántico por política + host key pinning
# (sin TOFU) contra un known_hosts dedicado. Si el servidor no ofrece PQC, o la
# clave de host no coincide, la conexión FALLA (fail-closed), no degrada.
SSH_OPTS=(
  -i "$KP_ADMIN_SSH_KEY"
  -o "KexAlgorithms=$KP_ADMIN_KEX"
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$KP_ADMIN_KNOWN_HOSTS"
  -o ConnectTimeout=12
  -o BatchMode=yes
)

# ── helpers ──────────────────────────────────────────────────────────────────
# El comando se envía como literal para ejecutarse en el HOST remoto; la expansión
# del lado cliente es la intención (no hay variables locales que interpolar aquí).
# shellcheck disable=SC2029
ssh_aws(){ ssh "${SSH_OPTS[@]}" "$KP_ADMIN_HOST" "$@"; }
secret(){ cat "$KP_ADMIN_SECRET_FILE" 2>/dev/null; }

# ¿Está el known_hosts poblado? (T4: sin él, StrictHostKeyChecking=yes falla feo)
require_known_hosts(){
  [ -s "$KP_ADMIN_KNOWN_HOSTS" ] || die "known_hosts vacío o ausente: $KP_ADMIN_KNOWN_HOSTS
Poblalo en el aprovisionamiento (una sola vez, en red de confianza):
  ssh-keyscan -t ed25519 <HOST> >> $KP_ADMIN_KNOWN_HOSTS   # y VERIFICA el fingerprint"
}

# Estado sellado del Vault local: 'False' des-sellado, 'True' sellado, '' caído.
vault_sealed(){ docker exec "$KP_ADMIN_VAULT_CONTAINER" vault status -format=json 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["sealed"])' 2>/dev/null; }

# ¿Alcanza el host el Vault local a través del túnel (−R)?
kms_reachable_from_aws(){
  [ "$(ssh_aws 'curl -s -o /dev/null -w "%{http_code}" --max-time 6 --cacert /etc/kerplace/kms-ca.crt https://localhost:8200/v1/sys/health 2>/dev/null')" = "200" ]
}

# Descifra un fichero GPG a stdout. Passphrase interactiva (pinentry) salvo que
# ADMINKP_PASSPHRASE esté definida (escape para automatización; queda expuesta en
# /proc/<pid>/environ — usar solo conscientemente).
gpg_decrypt(){
  if [ -n "${ADMINKP_PASSPHRASE:-}" ]; then
    gpg --batch --pinentry-mode loopback --passphrase "$ADMINKP_PASSPHRASE" -d "$1" 2>/dev/null
  else
    gpg -d "$1"
  fi
}

# Localiza el punto de montaje del USB de custodia por LABEL de filesystem.
usb_mount(){
  command -v findmnt >/dev/null || { warn "findmnt no disponible; no puedo localizar el USB por LABEL"; return 1; }
  local t; t="$(findmnt -rn -S "LABEL=$KP_ADMIN_USB_LABEL" -o TARGET 2>/dev/null | head -n1)"
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# Des-sella el Vault con el material del USB, descifrado EN MEMORIA (nunca a disco):
# gpg -> extrae unseal key -> 'vault operator unseal -' por stdin. (T2)
usb_unseal(){
  command -v gpg >/dev/null || die "gpg no encontrado"
  local mnt f
  mnt="$(usb_mount)" || die "USB de custodia '$KP_ADMIN_USB_LABEL' no presente — insértalo (fail-closed)"
  f="$mnt/$KP_ADMIN_USB_FILE"
  [ -f "$f" ] || die "material de unseal no encontrado en el USB: $f"
  info "descifrando el material de unseal desde el USB (en memoria, nunca a disco)"
  gpg_decrypt "$f" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["unseal_keys_b64"][0])' \
    | docker exec -i "$KP_ADMIN_VAULT_CONTAINER" vault operator unseal - >/dev/null 2>&1 || true
  [ "$(vault_sealed)" = "False" ] || die "unseal falló (¿passphrase incorrecta, USB inválido o Vault caído?)"
  info "Vault des-sellado desde el USB"
}

# Registra el alias 'adminkp' de mc contra el endpoint S3 (loopback vía túnel).
s3_alias(){ mc alias set adminkp "$KP_ADMIN_S3_ENDPOINT" "$KP_ADMIN_ACCESS_KEY" "$(secret)" >/dev/null 2>&1; }

# ¿Plano de datos S3 vivo? túnel activo + 'mc ls' real (reemplaza el health-check
# por 403 del endpoint público, que ya no existe tras T1).
s3_ready(){
  [ "$(systemctl --user is-active "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null)" = "active" ] \
    && s3_alias && mc ls adminkp >/dev/null 2>&1
}

bucket_list(){ s3_alias || return 1; mc ls adminkp 2>/dev/null | awk '{print $NF}' | sed 's#/$##'; }

# Escribe el passwd de s3fs con umask 077 desde el inicio (nunca chmod a posteriori). (T3)
ensure_passwd(){ ( umask 077; printf '%s:%s\n' "$KP_ADMIN_ACCESS_KEY" "$(secret)" > "$KP_ADMIN_PASSWD_S3FS" ); }

# Borra el passwd de s3fs del disco (shred si está disponible). (T3)
wipe_passwd(){
  [ -f "$KP_ADMIN_PASSWD_S3FS" ] || return 0
  if command -v shred >/dev/null; then shred -u "$KP_ADMIN_PASSWD_S3FS" 2>/dev/null; else rm -f "$KP_ADMIN_PASSWD_S3FS"; fi
  info "passwd de s3fs borrado del disco"
}

# Monta un bucket en una ruta (idempotente). Args: <bucket> <mount_point>
mount_one(){
  local b="$1" mp="$2"
  mkdir -p "$mp"
  if mountpoint -q "$mp" 2>/dev/null; then info "ya montado: $b -> $mp"; return 0; fi
  if s3fs "$b" "$mp" -o url="$KP_ADMIN_S3_ENDPOINT" -o use_path_request_style \
          -o passwd_file="$KP_ADMIN_PASSWD_S3FS" -o dbglevel=err 2>/dev/null; then
    info "montado: $b -> $mp"; return 0
  fi
  warn "no pude montar $b en $mp"; return 1
}

# Desmonta una ruta limpiamente (sync + fallback lazy). Arg: <mount_point>
umount_one(){
  local mp="$1"
  mountpoint -q "$mp" 2>/dev/null || { warn "no montado: $mp"; return 0; }
  sync
  fusermount3 -u "$mp" 2>/dev/null || { sleep 1; fusermount3 -z -u "$mp" 2>/dev/null; }
  if mountpoint -q "$mp" 2>/dev/null; then warn "no pude desmontar $mp"; return 1; fi
  info "desmontado: $mp"; return 0
}

# ── enable ───────────────────────────────────────────────────────────────────
do_enable(){
  require_known_hosts

  info "1/5  levantando el KMS (Vault) y des-sellándolo desde el USB"
  ( cd "$KP_ADMIN_KMS_DIR" && ./start.sh >/dev/null 2>&1 ) || die "no pude levantar el contenedor Vault ($KP_ADMIN_KMS_DIR/start.sh)"
  if [ "$(vault_sealed)" != "False" ]; then usb_unseal; else info "Vault ya estaba des-sellado"; fi
  [ "$(vault_sealed)" = "False" ] || die "Vault no está des-sellado"

  info "2/5  levantando el túnel SSH (custodia −R 8200 + datos −L 9000)"
  systemctl --user start "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null
  for _ in $(seq 1 15); do kms_reachable_from_aws && break; sleep 1; done
  kms_reachable_from_aws || die "el host no alcanza el KMS a través del túnel"
  info "túnel activo — el host alcanza el KMS (TLS)"

  info "3/5  arrancando KerPlace en el host"
  ssh_aws 'sudo systemctl start kerplace' || die "no pude arrancar KerPlace"
  for _ in $(seq 1 15); do
    [ "$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)" = "active" ] && break; sleep 1
  done
  [ "$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)" = "active" ] \
    || die "KerPlace no llegó a activo (¿KMS inalcanzable? revisa el túnel)"
  info "KerPlace activo en el host (arrancado sobre el KMS off-host)"

  info "4/5  preparando credenciales de s3fs"
  ensure_passwd

  info "5/5  montando buckets bajo $KP_ADMIN_MOUNT_BASE"
  mkdir -p "$KP_ADMIN_MOUNT_BASE"
  local b n=0
  for b in $(bucket_list); do mount_one "$b" "$KP_ADMIN_MOUNT_BASE/$b" && n=$((n+1)); done
  info "ENABLED — $n bucket(s) montado(s). Tu KerPlace remoto está online y local."
}

# ── disable ──────────────────────────────────────────────────────────────────
do_disable(){
  info "1/4  desmontando buckets limpiamente"
  local mp
  if [ -d "$KP_ADMIN_MOUNT_BASE" ]; then
    for mp in "$KP_ADMIN_MOUNT_BASE"/*/; do
      [ -d "$mp" ] || continue; mp="${mp%/}"
      mountpoint -q "$mp" 2>/dev/null && umount_one "$mp"
    done
  fi

  info "2/4  parando KerPlace en el host"
  if ssh_aws 'sudo systemctl stop kerplace' 2>/dev/null; then info "KerPlace parado"; else warn "no pude alcanzar el host para parar KerPlace"; fi

  info "3/4  bajando el túnel y re-sellando el Vault local"
  systemctl --user stop "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null
  # Re-sellar reiniciando el contenedor (storage de fichero -> arranca sellado): no
  # necesita token, y obliga a presentar el USB en el próximo --enable (posesión por
  # sesión). El contenedor sigue UP; solo queda sellado.
  if docker restart "$KP_ADMIN_VAULT_CONTAINER" >/dev/null 2>&1; then
    info "Vault re-sellado (el próximo --enable requerirá el USB)"
  else
    warn "no pude re-sellar el Vault local"
  fi

  info "4/4  borrando el passwd de s3fs del disco"
  wipe_passwd
  info "DISABLED — KerPlace remoto offline; ningún host alcanza tus claves."
}

# ── provisión del USB (migrar unseal del disco al USB cifrado) ────────────────
do_provision_usb(){
  command -v gpg >/dev/null || die "gpg no encontrado"
  local target="${1:-}" mnt f src="$KP_ADMIN_KMS_DIR/.vault-init.json"
  [ -f "$src" ] || die "no hay material de unseal en disco ($src) — ¿ya provisionado? nada que hacer"
  if [ -n "$target" ]; then mnt="$target"; else mnt="$(usb_mount)" || die "USB '$KP_ADMIN_USB_LABEL' no presente; pasa la ruta como argumento"; fi
  [ -d "$mnt" ] || die "el destino no es un directorio: $mnt"
  f="$mnt/$KP_ADMIN_USB_FILE"
  mkdir -p "$(dirname "$f")" || die "no puedo crear $(dirname "$f") en el USB"

  info "cifrando el material de unseal al USB (AES-256): $f"
  local gpgenc=(--symmetric --cipher-algo AES256 --yes)
  [ -n "${ADMINKP_PASSPHRASE:-}" ] && gpgenc=(--batch --pinentry-mode loopback --passphrase "$ADMINKP_PASSPHRASE" "${gpgenc[@]}")
  ( umask 077; gpg "${gpgenc[@]}" -o "$f" "$src" ) || die "cifrado falló"
  chmod 600 "$f" 2>/dev/null || true

  info "verificando round-trip (descifra y compara con el original)"
  local a b
  a="$(python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));print(d["unseal_keys_b64"][0]+"|"+d.get("root_token",""))' "$src" 2>/dev/null)"
  b="$(gpg_decrypt "$f" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["unseal_keys_b64"][0]+"|"+d.get("root_token",""))' 2>/dev/null)"
  [ -n "$a" ] && [ "$a" = "$b" ] || die "round-trip NO coincide — NO borres el original"
  info "round-trip OK — el USB contiene el mismo material que el disco"

  warn "antes de borrar el original, ten un --backup reciente (el USB es ahora tu factor de posesión)"
  printf '[INFO] ¿borrar el original del disco (%s)? escribe BORRAR para confirmar: ' "$src"
  local ans; read -r ans
  if [ "$ans" = "BORRAR" ]; then
    if command -v shred >/dev/null; then shred -u "$src"; else rm -f "$src"; fi
    info "original borrado; el unseal vive ahora solo en el USB (+ tu passphrase)"
  else
    info "original conservado en disco; vuelve a ejecutar --provision-usb cuando quieras completar la migración"
  fi
}

# ── backup del KMS: DOS artefactos con passphrases independientes (T7) ─────────
do_backup(){
  command -v gpg >/dev/null || die "gpg no encontrado"
  local outdir="${1:-$HOME}" ts
  ts="$(date +%Y%m%d-%H%M%S)"
  [ -d "$outdir" ] || die "directorio de salida inexistente: $outdir"
  local data_out="$outdir/kms-data-$ts.tar.gz.gpg"
  local unseal_out="$outdir/kms-unseal-$ts.tar.gz.gpg"

  local stage; stage="$(mktemp -d)"; trap 'rm -rf "$stage"' RETURN

  # ── Artefacto 1: DATOS (volumen Vault + config + certs). Grande, rota a menudo.
  info "snapshot del volumen Vault (aquí vive la Transit key no exportable)"
  docker run --rm -v "${KP_ADMIN_VAULT_VOLUME}:/data:ro" -v "$stage:/backup" alpine \
    tar czf /backup/vault-data.tar.gz -C /data . 2>/dev/null || die "no pude snapshotear $KP_ADMIN_VAULT_VOLUME"
  mkdir -p "$stage/data/vault/config" "$stage/data/vault/tls"
  mv "$stage/vault-data.tar.gz" "$stage/data/"
  cp "$KP_ADMIN_KMS_DIR/docker-compose.yml" "$KP_ADMIN_KMS_DIR/start.sh" "$KP_ADMIN_KMS_DIR/gen-certs.sh" "$stage/data/" 2>/dev/null || true
  cp "$KP_ADMIN_KMS_DIR/vault/config/vault.hcl" "$stage/data/vault/config/" 2>/dev/null || true
  cp "$KP_ADMIN_KMS_DIR"/vault/tls/* "$stage/data/vault/tls/" 2>/dev/null || true
  write_restore_md > "$stage/data/RESTORE.md"

  # ── Artefacto 2: UNSEAL (solo material de sellado + token). Pequeño, custodia
  #    separada, cambia casi nunca. Preferencia: del disco; si ya se migró al USB
  #    (T2), se toma de ahí para que el DR siga completo.
  mkdir -p "$stage/unseal"
  if [ -f "$KP_ADMIN_KMS_DIR/.vault-init.json" ]; then
    cp "$KP_ADMIN_KMS_DIR/.vault-init.json" "$stage/unseal/"
    cp "$KP_ADMIN_KMS_DIR/.kms-token" "$stage/unseal/" 2>/dev/null || true
  else
    info "material de unseal no está en disco; extrayéndolo del USB para el backup"
    local mnt; mnt="$(usb_mount)" || die "sin USB y sin .vault-init.json en disco: no puedo respaldar el unseal"
    gpg_decrypt "$mnt/$KP_ADMIN_USB_FILE" > "$stage/unseal/.vault-init.json" \
      || die "no pude descifrar el unseal del USB"
    cp "$KP_ADMIN_KMS_DIR/.kms-token" "$stage/unseal/" 2>/dev/null || true
  fi

  info "cifrando artefacto de DATOS (AES-256) — passphrase de datos"
  backup_encrypt "$stage/data" "$data_out" "${ADMINKP_PASSPHRASE:-}"
  info "cifrando artefacto de UNSEAL (AES-256) — passphrase de unseal (independiente)"
  backup_encrypt "$stage/unseal" "$unseal_out" "${ADMINKP_UNSEAL_PASSPHRASE:-}"

  info "BACKUP -> $data_out"
  info "BACKUP -> $unseal_out"
  warn "guarda los dos artefactos en custodias SEPARADAS. El de unseal solo (con su"
  warn "passphrase) permite des-sellar; sepáralo del de datos. La DATA de los buckets"
  warn "se respalda aparte, desde $KP_ADMIN_MOUNT_BASE mientras estás --enabled."
}

# Cifra un directorio a un .tar.gz.gpg. Args: <dir> <out> <passphrase|"">
backup_encrypt(){
  local dir="$1" out="$2" pass="$3"
  local gpgargs=(--symmetric --cipher-algo AES256)
  [ -n "$pass" ] && gpgargs=(--batch --pinentry-mode loopback --passphrase "$pass" "${gpgargs[@]}")
  ( cd "$dir" && tar czf - . ) | gpg "${gpgargs[@]}" -o "$out" || die "cifrado falló: $out"
  chmod 600 "$out"
}

# ── status ───────────────────────────────────────────────────────────────────
do_status(){
  local sealed tun ker
  sealed="$(vault_sealed)"; [ "$sealed" = "False" ] && sealed="up & des-sellado" || sealed="ABAJO/sellado"
  tun="$(systemctl --user is-active "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null)"
  if [ -s "$KP_ADMIN_KNOWN_HOSTS" ]; then
    ker="$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)"; [ -z "$ker" ] && ker="inalcanzable"
  else
    ker="(known_hosts sin poblar)"
  fi
  printf '  KMS local (Vault) : %s\n' "$sealed"
  printf '  túnel al host     : %s\n' "$tun"
  printf '  KerPlace remoto   : %s\n' "$ker"
  printf '  montajes s3fs:\n'
  local found=0 mpt fstype
  while read -r _ mpt fstype _; do
    [ "$fstype" = "fuse.s3fs" ] || continue
    case "$mpt" in
      "$KP_ADMIN_MOUNT_BASE"/*) printf '    - %s\n' "$mpt" ;;
      *)                        printf '    - %s  (custom)\n' "$mpt" ;;
    esac
    found=1
  done < /proc/mounts
  [ "$found" -eq 0 ] && printf '    (ninguno montado)\n'
  return 0
}

# ── mount / umount de un solo bucket ─────────────────────────────────────────
do_mount(){   # <bucket> [mount_point]
  local b="$1" mp="${2:-$KP_ADMIN_MOUNT_BASE/$1}"
  [ -n "$b" ] || die "uso: --mount <bucket> [mount_point]   (por defecto: $KP_ADMIN_MOUNT_BASE/<bucket>)"
  s3_ready || warn "plano de datos S3 no disponible (¿túnel abajo? ¿--enable primero?) — la E/S fallará"
  ensure_passwd
  mount_one "$b" "$mp" || die "montaje fallido (¿nombre de bucket correcto? ¿KerPlace --enabled?)"
}

do_umount(){  # <bucket|mount_point>
  local arg="$1" mp
  [ -n "$arg" ] || die "uso: --umount <bucket|mount_point>"
  if mountpoint -q "$arg" 2>/dev/null; then mp="$arg"
  elif mountpoint -q "$KP_ADMIN_MOUNT_BASE/$arg" 2>/dev/null; then mp="$KP_ADMIN_MOUNT_BASE/$arg"
  else die "no es un montaje actual: $arg (ver --status)"; fi
  umount_one "$mp"
}

# Texto de RESTORE.md (usado por el artefacto de DATOS). Referencia el flujo de
# dos artefactos y conserva el aviso de expiración del token (720h).
write_restore_md(){ cat <<'EOF'
# Restaurar el KMS de KerPlace en un portátil nuevo

Necesitas: Docker, los DOS artefactos del backup, y sus dos passphrases.

  - kms-data-<ts>.tar.gz.gpg    -> volumen Vault + config + certs (este archivo)
  - kms-unseal-<ts>.tar.gz.gpg  -> .vault-init.json (unseal key + root token) + token

1. Descifra + desempaqueta ambos:
     gpg -d kms-data-<ts>.tar.gz.gpg   | tar xz          # -> vault-data.tar.gz, config, certs, RESTORE.md
     gpg -d kms-unseal-<ts>.tar.gz.gpg | tar xz          # -> .vault-init.json, .kms-token
2. Recrea el volumen de datos de Vault desde vault-data.tar.gz:
     docker volume create kerplace-kms_vault-data
     docker run --rm -v kerplace-kms_vault-data:/data -v "$PWD:/b" alpine \
       sh -c 'cd /data && tar xzf /b/vault-data.tar.gz'
3. Coloca la config donde adminKP/start.sh la esperan (p.ej. <KMS_DIR>/):
   docker-compose.yml, start.sh, gen-certs.sh, vault/config/vault.hcl, vault/tls/*
   y el material de unseal: .vault-init.json, .kms-token
4. Levanta el contenedor:  ./start.sh   (deja el Vault SELLADO; ya no auto-unsealea)
   Luego migra el unseal al USB y des-sella:
     ./adminKP.sh --provision-usb <ruta_USB>     (mueve .vault-init.json al USB)
     ./adminKP.sh --enable                       (unsealea desde el USB)
   La misma Transit key vuelve -> tus buckets descifran de nuevo. La CA en
   vault/tls/ca.crt no cambió, así que KP_KMS_CA en el host sigue coincidiendo.

5. Expiración del token (solo si pasaron MÁS de ~30 días desde el último backup):
   el token scoped (KP_KMS_TOKEN en el host) tiene TTL 720h y puede haber caducado.
   Acuña uno nuevo en el portátil tras el unseal:
     ROOT=$(python3 -c 'import json;print(json.load(open(".vault-init.json"))["root_token"])')
     docker exec -e VAULT_TOKEN="$ROOT" kerplace-vault \
       vault token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token
   pon ese valor como KP_KMS_TOKEN en /etc/kerplace.env del host y reinícialo.
   La Transit key y la CA no cambian, así que la data sigue descifrando.

GUARDA EL ARTEFACTO DE UNSEAL POR SEPARADO: contiene la unseal key. Quien lo tenga
(+ su passphrase) + acceso de red al KMS puede descifrar tus datos.
EOF
}

# ── dispatcher ───────────────────────────────────────────────────────────────
case "${1:---help}" in
  --enable)        do_enable ;;
  --disable)       do_disable ;;
  --mount)         do_mount "${2:-}" "${3:-}" ;;
  --umount)        do_umount "${2:-}" ;;
  --backup)        do_backup "${2:-}" ;;
  --provision-usb) do_provision_usb "${2:-}" ;;
  --status)        do_status ;;
  *) usage; exit 1 ;;
esac
