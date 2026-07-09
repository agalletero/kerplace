# kpc — KerPlaceClient

Cliente de administración de **KerPlace en modo custodia**: un solo binario en el
path del sistema para operar el KMS off-host (OpenBao) y los buckets cifrados.
Pensado para el día a día y, sobre todo, para **DR**: cualquier admin con `kpc` y
`kpc --help` sabe qué hacer, sin buscar scripts sueltos.

```
kpc status         ¿KMS sellado? ¿USB presente? ¿túneles? ¿montajes?
kpc unseal         des-sella el KMS con el USB (pide passphrase)   [sin root]
kpc seal           sella YA: desmonta buckets + reinicia el KMS    [sudo]
kpc mount <bucket> monta un bucket por FUSE
kpc umount <bucket>
kpc provision-usb  migra el unseal al USB            [aún vía script]
kpc enable/disable levanta/baja una instancia entera [parcial]
kpc backup         backup de DR                      [aún vía script]
```

Orquesta herramientas estándar (curl, gpg, systemctl, findmnt, s3fs), así que es un
binario pequeño y autocontenido. La clave de unseal se descifra en memoria y se
envía al KMS por la API (nunca aparece en `ps`).

## Instalar

```bash
cargo build --release
sudo install -m 755 target/release/kpc /usr/local/bin/kpc
sudo install -D -m 644 kpc.toml.example /etc/kerplace/kpc.toml   # y edítalo
```

## Config

`/etc/kerplace/kpc.toml` (o `~/.config/kerplace/kpc.toml`, o `--config <ruta>`).
Ver [`kpc.toml.example`](kpc.toml.example): `[kms]` (endpoint/CA/servicio),
`[usb]` (label/uuid/fichero), y una o más `[[instances]]` con sus buckets.

## Estado

- **Nativo:** `status`, `unseal`, `seal`, `enable`, `disable`, `mount`, `umount`, `watch`.
- **Aún vía script** (se portarán a nativo): `provision-usb`, `backup`.

`kpc watch` es un agente (systemd --user) que **liga la presencia del USB**: al
**insertar** ejecuta `enable` (levanta túnel + des-sella con prompt gráfico + monta);
al **retirar** para el túnel. El sellado + desmontaje instantáneos los hace el servicio
de sistema (udev + `kerplace-kms-presence`, ver `../deploy/external-kms-laptop/usb-presence/`).
Units de ejemplo en [`../deploy/external-kms-laptop/systemd-user/`](../deploy/external-kms-laptop/systemd-user/).

Ver la doc de custodia: [`../deploy/external-kms-laptop/`](../deploy/external-kms-laptop/).
