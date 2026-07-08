# Guía de operador — modo custodia endurecido (hardening)

Runbook del despliegue **custody-tethered** de KerPlace endurecido: plano de datos
por el túnel, unseal desde USB, canal SSH fijado a PQC y credenciales scoped. El
*concepto* está en [`docs/OFFHOST_KMS_CUSTODY.md`](../../docs/OFFHOST_KMS_CUSTODY.md);
aquí van los **pasos de aprovisionamiento** y el ciclo de vida endurecido.

Piezas: `adminKP.sh` (orquestador, único on/off), `start.sh` (levanta el contenedor
Vault; sin secretos en estado estacionario), la unit `systemd --user` del túnel y
un USB de custodia con el material de unseal.

---

## 0. Configuración (una vez)

Toda la config sale de un fichero de entorno; el script aborta si falta:

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/kerplace"
cp deploy/external-kms-laptop/adminkp.env.example \
   "${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env"
# edita las 5 variables obligatorias (KP_ADMIN_HOST, _SSH_KEY, _ACCESS_KEY,
# _SECRET_FILE, _KMS_DIR). El resto tiene defaults.
```

Ruta alternativa: `./adminKP.sh --config <ruta> <subcomando>`.

---

## 1. Plano de datos por el túnel + cerrar el puerto S3 (T1)

El tráfico S3 (el contenido de los objetos) ya **no** viaja por Internet: entra por
el mismo canal SSH que la custodia, en sentido inverso.

- La unit del túnel publica dos forwards (ver §5):
  `-R 127.0.0.1:8200` (custodia) y `-L 127.0.0.1:9000` (datos).
- `KP_ADMIN_S3_ENDPOINT=http://127.0.0.1:9000` (loopback; el cifrado en tránsito lo
  da SSH/ML-KEM).
- **En el host**, KerPlace escucha solo en loopback y se cierra el puerto público:
  ```bash
  # /etc/kerplace.env en el host
  KP_ADDRESS=127.0.0.1:9000
  # luego, en el security group / firewall del host: CERRAR el 9000 entrante.
  ```
  `KP_ADDRESS` es configuración pura (no toca el core). Con esto la superficie S3
  pública es cero: sin túnel no hay endpoint alcanzable.

---

## 2. Pin criptográfico y de identidad del canal SSH (T4)

1. **KEX post-cuántico por política.** Tanto la unit como `ssh_aws()` fuerzan
   `KexAlgorithms=mlkem768x25519-sha256` (variable `KP_ADMIN_KEX`). Si el servidor
   no ofrece ML-KEM, la conexión **falla** (no degrada a clásico).

2. **Host key pinning (sin TOFU).** `StrictHostKeyChecking=yes` contra un
   `known_hosts` dedicado (`KP_ADMIN_KNOWN_HOSTS`). Poblarlo una vez, en red de
   confianza, y **verificar el fingerprint** por un canal aparte:
   ```bash
   ssh-keyscan -t ed25519 <HOST> >> "$HOME/.config/kerplace/known_hosts"
   ssh-keygen -lf "$HOME/.config/kerplace/known_hosts"   # compara el fingerprint
   ```

3. **Clave del túnel restringida en el host.** En `~/.ssh/authorized_keys` del
   usuario del host, la clave de custodia va con restricciones (nada de shell, pty,
   agent, X11; solo los dos forwards del modo):
   ```
   restrict,port-forwarding,permitlisten="127.0.0.1:8200",permitopen="127.0.0.1:9000" ssh-ed25519 AAAA...clave-de-custodia... custodia
   ```
   `permitlisten` habilita el −R (custodia); `permitopen` habilita el −L (datos).

---

## 3. Credenciales del plano S3 (T3)

1. **Usuario S3 scoped `kp-mounter`** (no el root de KerPlace). Créalo con una
   política limitada a los buckets a montar (list/get/put/delete sobre esos ARN,
   nada de admin):
   ```bash
   mc admin user add   <alias-root> kp-mounter <SECRET>
   mc admin policy create <alias-root> kp-mounter kp-mounter-policy.json
   mc admin policy attach <alias-root> kp-mounter --user kp-mounter
   ```
   `kp-mounter-policy.json` (ajusta los ARN a tus buckets):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow",
         "Action": ["s3:ListBucket"],
         "Resource": ["arn:aws:s3:::mybucket"] },
       { "Effect": "Allow",
         "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject"],
         "Resource": ["arn:aws:s3:::mybucket/*"] }
     ]
   }
   ```
   Pon ese usuario en la config: `KP_ADMIN_ACCESS_KEY=kp-mounter` y su secret en
   `KP_ADMIN_SECRET_FILE` (chmod 600). El root queda solo para admin explícito.

2. **Higiene del passwd de s3fs.** `adminKP.sh` lo crea con `umask 077` y lo
   **borra** (`shred -u`) en `--disable`. Tras `--disable` no debe existir
   `~/.passwd-s3fs*`.

---

## 4. Unseal desde USB, no desde disco (T2)

El material de unseal (unseal key + root token) **no reside en el disco del
portátil**: vive cifrado con GPG simétrico (AES-256) en un USB de custodia. Factores
= posesión (USB) + conocimiento (passphrase).

**Migración inicial** (tras el primer `start.sh`, que aún deja `.vault-init.json` en
disco temporalmente):

```bash
# haz un backup ANTES (ver §6)
./adminKP.sh --backup
# formatea/etiqueta el USB con LABEL=KPCUSTODY (o ajusta KP_ADMIN_USB_LABEL)
./adminKP.sh --provision-usb            # localiza el USB por LABEL, cifra, verifica
#   round-trip (cifra→descifra→compara), y OFRECE borrar el original con shred.
```

`--provision-usb` es idempotente y solo ofrece borrar el original tras verificar el
round-trip. También acepta una ruta explícita: `--provision-usb /media/$USER/KPCUSTODY`.

**En cada `--enable`**: si el Vault está sellado, el material se descifra **en
memoria** (nunca a disco) y se alimenta a `vault operator unseal -` por stdin.
Passphrase interactiva (pinentry). Sin USB presente ⇒ `[ERR]` y aborta (el túnel no
se levanta si el unseal falla). El escape `ADMINKP_PASSPHRASE` existe solo para
automatización (queda expuesto en `/proc/<pid>/environ`).

> **Fase 2 (no implementada, evolución):** upgrade a YubiKey/FIDO2 con clave
> residente (`sk-ssh-ed25519`) para posesión no clonable, y regla udev para
> auto-enable al insertar / auto-disable al extraer.

---

## 5. Unit systemd del túnel (T6)

Plantilla en [`systemd/kerplace-kms-tunnel.service`](systemd/kerplace-kms-tunnel.service):
los dos forwards de §1, el pin KEX + known_hosts de §2, `ExitOnForwardFailure=yes`,
`ServerAliveInterval=15`/`CountMax=3`, `ConnectTimeout=10`, `Restart=on-failure`,
`RestartSec=5s`. Instálala como unit de usuario y activa linger para que sobreviva a
logout/reboot:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/external-kms-laptop/systemd/*.service \
   deploy/external-kms-laptop/systemd/*.timer   ~/.config/systemd/user/
# edita YOUR_USER@YOUR_HOST y las rutas de clave/known_hosts (%h = tu home)
loginctl enable-linger "$USER"                 # servicios de usuario al arranque
systemctl --user daemon-reload
systemctl --user enable --now kerplace-kms-vault.timer   # mantiene el contenedor up (sellado)
```

**No** habilites la unit del túnel para auto-arranque: `adminKP.sh` es el único
interruptor y la arranca/para en `--enable`/`--disable` (`systemctl --user start/stop`).
El Vault local sí es persistente (el timer lo mantiene up, sellado).

---

## 6. Backup: dos artefactos separados (T7)

`--backup` produce **dos** ficheros con **passphrases independientes**, para
custodiarlos por separado:

```bash
./adminKP.sh --backup [dir]     # dir por defecto: $HOME
#   kms-data-<ts>.tar.gz.gpg    -> volumen Vault + config + certs (grande, rota a menudo)
#   kms-unseal-<ts>.tar.gz.gpg  -> .vault-init.json + token (pequeño, cambia casi nunca)
```

El de **unseal** solo (con su passphrase) permite des-sellar: guárdalo en una
custodia distinta a la del de datos. Si ya migraste el unseal al USB, el backup lo
extrae del USB para que el DR siga completo. Restauración y aviso de expiración del
token (720h): ver el `RESTORE.md` incluido en el artefacto de datos.

Passphrases por variable (automatización): `ADMINKP_PASSPHRASE` (datos) y
`ADMINKP_UNSEAL_PASSPHRASE` (unseal).

---

## 7. Garantías fail-closed (checklist)

- Túnel caído ⇒ `mc ls` falla, KerPlace no sirve datos (bind loopback + puerto
  cerrado), `--status` lo refleja. Ninguna ruta desde Internet alcanza el S3.
- sshd sin ML-KEM ⇒ la conexión **falla** (KEX fijado por política), no degrada.
- Sin USB ⇒ `--enable` aborta en el unseal; el túnel no queda levantado.
- Tras `--disable` ⇒ no hay `~/.passwd-s3fs*`, ni montajes, el túnel está parado y
  el Vault local sigue up (sellado). El material de unseal descifrado nunca toca el
  disco.

> **Limitación conocida (no cubierta por este modo).** El endurecimiento anterior
> cierra el *plano de despliegue*. Persiste un hueco en el *core* fuera del alcance
> de esta guía: una escritura (`PUT`) que llegue con el KMS inalcanzable **a mitad
> de sesión** puede responder `200` con un objeto de 0 bytes en lugar de fallar en
> cerrado (la ruta de lectura ya se cerró en v0.1.1; la de escritura no). Requiere
> cambio de core; se aborda por separado. Con el puerto cerrado y bind en loopback,
> el vector solo aplica a un cliente ya dentro del túnel cuando el KMS cae.
