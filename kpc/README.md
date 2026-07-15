# kpc — KerPlaceClient

Administration client for **KerPlace in custody mode**: a single binary on the
system path that operates the off-host key store (OpenBao) and the encrypted
buckets it protects. Built for daily use and, above all, for **disaster
recovery** — an admin holding the USB should recover the service from `kpc
--help` alone, without hunting for scripts.

> 📖 **[docs/KPC.md](../docs/KPC.md) is the manual**: what `kpc` is, where it
> coexists with `mc` and where it does not, the operational lifecycle, and its
> design properties. This file is the quick reference.

```
kpc status          seal state? USB present? tunnels? mounts?
kpc enable          bring it all up: tunnel(s) + unseal + mount
kpc disable         take it all down: unmount + stop tunnel(s) + seal   [sudo]
kpc unseal          release the key from the USB (prompts for the passphrase)
kpc seal            seal NOW: unmount buckets + restart the key store   [sudo]
kpc mount <bucket>  mount a bucket over FUSE
kpc umount <bucket>
kpc watch           agent: bind the USB's presence to enable/disable
kpc provision-usb   migrate the unseal material onto the USB   [script-backed]
kpc backup          disaster-recovery backup                   [script-backed]
```

**It does not replace `mc`.** `mc`/`aws`/`rclone` own the data plane (buckets,
objects, users, policies); `kpc` owns everything the S3 protocol cannot express —
seal state, the USB, the tunnel and the mount. See
[docs/KPC.md §3](../docs/KPC.md#3-coexistence-with-mc).

It orchestrates standard tools (`curl`, `gpg`, `systemctl`, `findmnt`, `s3fs`)
rather than reimplementing them, so the binary stays small and auditable. The
unseal material is decrypted in memory and delivered to the key store over its
API — it never appears in `ps`.

## Install

```bash
cargo build --release
sudo install -m 755 target/release/kpc /usr/local/bin/kpc
sudo install -D -m 644 kpc.toml.example /etc/kerplace/kpc.toml   # then edit it
```

## Configuration

`/etc/kerplace/kpc.toml` (or `~/.config/kerplace/kpc.toml`, or `--config <path>`).
See [`kpc.toml.example`](kpc.toml.example): `[kms]` (endpoint / CA / service),
`[usb]` (label / uuid / material path), and one or more `[[instances]]` with their
buckets. Paths must be absolute.

## Status

- **Native:** `status`, `unseal`, `seal`, `enable`, `disable`, `mount`, `umount`, `watch`.
- **Script-backed** (to be ported): `provision-usb`, `backup`.

`kpc watch` is a `systemd --user` agent that **binds the USB's presence**: on
**insert** it runs `enable` (tunnel + unseal + mount); on **removal** it stops the
tunnel. The instantaneous seal and unmount are performed by a system service
(udev + `kerplace-kms-presence`, see
[`../deploy/external-kms-laptop/usb-presence/`](../deploy/external-kms-laptop/usb-presence/)).
Example units live in
[`../deploy/external-kms-laptop/systemd-user/`](../deploy/external-kms-laptop/systemd-user/).
