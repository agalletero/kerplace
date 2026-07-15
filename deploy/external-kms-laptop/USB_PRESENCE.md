# Continuous USB presence — seal the KMS when the USB is pulled

This closes the custody loop: **pull the USB ⇒ the KMS seals and the data becomes
inaccessible instantly**; plug it back in + passphrase ⇒ access. The two factors are
**possession** (USB) + **knowledge** (passphrase, typed by hand on reinsertion — no
auto-unseal, so the knowledge factor is not weakened).

All of this is versioned under [`usb-presence/`](usb-presence/) and installs with a
single command. Designed to be **replicated** on any machine running the native KMS
(OpenBao).

## What it does, exactly

**PULLING** the custody USB triggers the **seal action** (`kerplace-kms-seal`), which is
idempotent and does two things:

1. **`umount -l` (lazy) of every `fuse.s3fs` mount** — so that a broken mount doesn't
   hang `df -h` / `ls` until a timeout. A lazy unmount makes it disappear from
   `/proc/mounts` instantly.
2. **`systemctl restart openbao`** — OpenBao (file storage) starts up **sealed**, so it
   can no longer unwrap keys. KerPlace hosts get a `503` from the KMS.

It is triggered by **two paths** (defence in depth):

- **udev (instantaneous):** an `ACTION=="remove"` rule keyed to the USB's UUID calls the
  seal service as soon as the device is removed.
- **monitor (backstop, 2s polling):** a service that checks for USB presence
  (`/dev/disk/by-uuid/<UUID>`) and seals if it disappears — this covers missed udev
  events (suspend/resume, fast replug).

> **1 USB ↔ 1 KMS.** The rule and the monitor are keyed to the **UUID of ONE USB** and
> seal **ONE** KMS instance. To avoid "putting all the keys in one place", each KerPlace
> should have its own KMS with its own USB: replicate this set per instance, each with
> its own UUID (this fits the admin client's multi-instance JSON).

## Components (all in `usb-presence/`)

| File | Destination on the system | What it is |
|---|---|---|
| `kerplace-kms-seal` | `/usr/local/sbin/` | seal action (lazy-umount + seal) |
| `kerplace-kms-presence` | `/usr/local/sbin/` | polling monitor (backstop) |
| `kerplace-kms-seal.service` | `/etc/systemd/system/` | oneshot that runs the seal |
| `kerplace-kms-presence.service` | `/etc/systemd/system/` | monitor service (Restart=always) |
| `99-kerplace-custody.rules.template` | `/etc/udev/rules.d/99-kerplace-custody.rules` | udev rule (with the UUID substituted in) |
| `install.sh` | — | installer (parameterises the UUID) |
| generated config | `/etc/kerplace/custody.env` | `KP_CUSTODY_USB_UUID`, KMS endpoint/CA/service |

## Install / replicate (on the machine running the native KMS)

1. **Find the UUID of the USB's filesystem** (the FS one, not the PARTUUID):
   ```bash
   lsblk -o NAME,LABEL,UUID       # or: sudo blkid
   # e.g.:  sde1  Ventoy  3431-7DD1     <-- that 3431-7DD1
   ```
2. **Install:**
   ```bash
   cd deploy/external-kms-laptop/usb-presence
   sudo ./install.sh 3431-7DD1
   ```
   It creates `/etc/kerplace/custody.env`, copies the scripts/units, substitutes the UUID
   in the udev rule, reloads udev + systemd and enables the monitor.
3. **On every KerPlace HOST** set `KP_KMS_CACHE_TTL=0` in `/etc/kerplace.env` and restart
   KerPlace — that way sealing blocks access **immediately** (no cached DEK reads).

## Testing

```bash
# physically pull the USB, then:
ls /dev/disk/by-uuid/<UUID>        # must fail (absent)
bao status | grep Sealed           # Sealed  true
df -h                              # WITHOUT the s3fs mount, and without hanging
# on a host: mc cat <alias>/<bucket>/<obj>   -> fails with KMS 503
# reinsert the USB and unseal:
bash ~/.config/kerplace/usb-unseal.sh
```

## Troubleshooting

**On reinserting the USB, the FS does not get mounted again (and it looks like the cycle
doesn't recover) — this is almost always because you had a terminal INSIDE the mounted
folder.**

This is normal FUSE behaviour, not a bug: if a process (your shell, an editor, a file
manager) has its *cwd* or open files **inside** the mount point, that mount is **busy**.
When you pull the USB, the lazy `umount -l` detaches it so that `df -h`/`ls` don't hang,
but the mount point is **still held** by that process. On reinsertion, `kpc enable` tries
to mount s3fs on the same point and **fails because it is busy**.

- **Fix:** leave the folder before touching the USB, or if it has already happened to you:
  ```bash
  cd ~            # (or any path outside ~/kerplace/<bucket>)
  kpc enable      # remounts (or simply plug the USB back in)
  ```
- **Rule of thumb for the end user:** work with the bucket's files, but **don't leave a
  terminal "parked" inside** the mounted folder while you plug/unplug the USB. Close any
  open files from that folder before pulling the USB.

*(This can't be fixed in software: no process can cleanly unmount a FS that another
process is using. `kpc mount` warns if it detects that the mount point is busy.)*

## Notes

- **Remounting after unsealing:** today this is manual (sealing unmounts; `usb-unseal.sh`
  only unseals). Automatic remounting will come with native `adminKP` / `--enable`.
- **There is no auto-unseal on insertion**, by design: the passphrase is typed by hand
  (knowledge factor). The monitor only SEALS on absence; it never unseals.
- **Authoritative presence:** `/dev/disk/by-uuid/<UUID>` is used (a symlink that udev
  removes instantly on disconnect), not `blkid` (which caches).
- **Verified live** (2026-07-09): pull USB → `Sealed=true` + mounts gone from `df -h`
  with no hang + host `503`; reinsert + unseal → access restored.
