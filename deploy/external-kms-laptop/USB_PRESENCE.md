# Presencia continua del USB — sellar el KMS al retirar el USB

Cierra el círculo de la custodia: **quitar el USB ⇒ el KMS se sella y los datos quedan
inaccesibles al instante**; volver a ponerlo + passphrase ⇒ acceso. Los dos factores
son **posesión** (USB) + **conocimiento** (passphrase, tecleada a mano al reinsertar —
sin auto-unseal, para no debilitar el factor conocimiento).

Todo esto está versionado en [`usb-presence/`](usb-presence/) y se instala con un
comando. Diseñado para **replicarse** en cualquier máquina con el KMS nativo (OpenBao).

## Qué hace, exactamente

Al **RETIRAR** el USB de custodia se dispara la **acción de sellado**
(`kerplace-kms-seal`), que es idempotente y hace dos cosas:

1. **`umount -l` (lazy) de todos los mounts `fuse.s3fs`** — para que un mount roto no
   cuelgue `df -h` / `ls` hasta un timeout. Al desmontar en lazy desaparece de
   `/proc/mounts` al instante.
2. **`systemctl restart openbao`** — OpenBao (file storage) arranca **sellado**, así
   que ya no puede desenvolver claves. Los hosts KerPlace reciben `503` del KMS.

Se dispara por **dos caminos** (defensa en profundidad):

- **udev (instantáneo):** una regla `ACTION=="remove"` keyada al UUID del USB llama al
  servicio de sellado en cuanto se retira el dispositivo.
- **monitor (backstop, sondeo 2s):** un servicio que comprueba la presencia del USB
  (`/dev/disk/by-uuid/<UUID>`) y sella si desaparece — cubre eventos udev perdidos
  (suspend/resume, replug rápido).

> **1 USB ↔ 1 KMS.** La regla y el monitor van keyados al **UUID de UN USB** y sellan
> **UNA** instancia KMS. Para no "poner todas las llaves en el mismo sitio", cada
> KerPlace debería tener su propio KMS con su propio USB: se replica este conjunto por
> instancia, cada una con su UUID (encaja con el JSON multi-instancia del cliente admin).

## Componentes (todos en `usb-presence/`)

| Fichero | Destino en el sistema | Qué es |
|---|---|---|
| `kerplace-kms-seal` | `/usr/local/sbin/` | acción de sellado (lazy-umount + seal) |
| `kerplace-kms-presence` | `/usr/local/sbin/` | monitor de sondeo (backstop) |
| `kerplace-kms-seal.service` | `/etc/systemd/system/` | oneshot que ejecuta el sellado |
| `kerplace-kms-presence.service` | `/etc/systemd/system/` | servicio del monitor (Restart=always) |
| `99-kerplace-custody.rules.template` | `/etc/udev/rules.d/99-kerplace-custody.rules` | regla udev (con el UUID sustituido) |
| `install.sh` | — | instalador (parametriza el UUID) |
| config generada | `/etc/kerplace/custody.env` | `KP_CUSTODY_USB_UUID`, endpoint/CA/servicio del KMS |

## Instalación / replicación (en la máquina con el KMS nativo)

1. **Averigua el UUID del filesystem del USB** (el del FS, no el PARTUUID):
   ```bash
   lsblk -o NAME,LABEL,UUID       # ó: sudo blkid
   # ej.:  sde1  Ventoy  3431-7DD1     <-- ese 3431-7DD1
   ```
2. **Instala:**
   ```bash
   cd deploy/external-kms-laptop/usb-presence
   sudo ./install.sh 3431-7DD1
   ```
   Crea `/etc/kerplace/custody.env`, copia los scripts/units, sustituye el UUID en la
   regla udev, recarga udev + systemd y habilita el monitor.
3. **En cada HOST KerPlace** pon `KP_KMS_CACHE_TTL=0` en `/etc/kerplace.env` y reinicia
   KerPlace — así al sellar el bloqueo es **inmediato** (sin lecturas cacheadas del DEK).

## Probar

```bash
# retira el USB físicamente, luego:
ls /dev/disk/by-uuid/<UUID>        # debe fallar (ausente)
bao status | grep Sealed           # Sealed  true
df -h                              # SIN el mount s3fs, y sin colgarse
# en un host: mc cat <alias>/<bucket>/<obj>   -> falla con KMS 503
# reinserta el USB y des-sella:
bash ~/.config/kerplace/usb-unseal.sh
```

## Solución de problemas

**Al reinsertar el USB, el FS no se vuelve a montar (y parece que el ciclo no
recupera) — casi siempre es porque tenías una terminal DENTRO de la carpeta montada.**

Es comportamiento normal de FUSE, no un fallo: si un proceso (tu shell, un editor, un
gestor de archivos) tiene el *cwd* o ficheros abiertos **dentro** del punto de montaje,
ese montaje queda **ocupado**. Al quitar el USB, el `umount -l` (lazy) lo desengancha
para que `df -h`/`ls` no se cuelguen, pero el punto de montaje **sigue retenido** por
ese proceso. Al reinsertar, `kpc enable` intenta montar s3fs sobre el mismo punto y
**falla porque está ocupado**.

- **Solución:** sal de la carpeta antes de tocar el USB, o si ya te ha pasado:
  ```bash
  cd ~            # (o cualquier ruta fuera de ~/kerplace/<bucket>)
  kpc enable      # re-monta (o simplemente vuelve a insertar el USB)
  ```
- **Regla práctica para el usuario final:** trabaja con los ficheros del bucket, pero
  **no dejes una terminal “plantada” dentro** de la carpeta montada mientras conectas/
  desconectas el USB. Cierra los ficheros abiertos de esa carpeta antes de quitar el USB.

*(No es corregible desde el software: ningún proceso puede desmontar limpiamente un FS
que otro proceso está usando. `kpc mount` avisa si detecta el punto de montaje ocupado.)*

## Notas

- **Re-montaje tras des-sellar:** hoy es manual (el sellado desmonta; `usb-unseal.sh`
  solo des-sella). El re-montaje automático llegará con `adminKP` nativo / `--enable`.
- **No hay auto-unseal al insertar**, a propósito: la passphrase se teclea a mano
  (factor conocimiento). El monitor solo SELLA en ausencia; nunca des-sella.
- **Presencia autoritativa:** se usa `/dev/disk/by-uuid/<UUID>` (symlink que udev
  quita al instante al desconectar), no `blkid` (que cachea).
- **Verificado en vivo** (2026-07-09): quitar USB → `Sealed=true` + mounts fuera de
  `df -h` sin cuelgue + host `503`; reinsertar + unseal → acceso restaurado.
