# Provisionar un host de custodia NUEVO (GCP u otro servidor)

Lista de comandas exactas para convertir un servidor nuevo en un **host de custodia
KerPlace** que habla con el KMS (OpenBao) de tu portátil. Dos lados: el **host**
(sirve S3, guarda solo ciphertext) y el **portátil** (tiene las claves). Sustituye
los `<PLACEHOLDERS>`. Referencia viva: el despliegue AWS actual.

Placeholders:
- `<NEW_HOST>` = `usuario@ip` del servidor nuevo (p.ej. `alex@34.x.x.x` en GCP)
- `<SSH_KEY>` = clave SSH privada para ese host (en el portátil)
- `<SCOPED_TOKEN>` = token scoped nuevo (se acuña en el paso P2)

---

## A · En el HOST nuevo

### 1. Binario de KerPlace (musl estático)
Opción rápida — copiar el binario que ya funciona desde el host actual:
```bash
# desde el PORTÁTIL:
scp -i <SSH_KEY_ACTUAL> <HOST_ACTUAL>:/usr/local/bin/kerplace /tmp/kerplace
scp -i <SSH_KEY> /tmp/kerplace <NEW_HOST>:/tmp/kerplace
```
O bajarlo de releases (verifica el checksum publicado):
```bash
curl -fsSL -o /tmp/kerplace https://github.com/agalletero/kerplace/releases/latest/download/kerplace-x86_64-unknown-linux-musl
```
Instalar en el host:
```bash
sudo install -m 755 /tmp/kerplace /usr/local/bin/kerplace && rm -f /tmp/kerplace
/usr/local/bin/kerplace --version 2>/dev/null || true
```

### 2. Data dir
```bash
sudo mkdir -p /kerplace && sudo chown "$USER:$USER" /kerplace
```

### 3. Config `/etc/kerplace.env`
```bash
sudo install -d /etc/kerplace
sudo tee /etc/kerplace.env >/dev/null <<EOF
KP_DATA_DIR=/kerplace
KP_ENCRYPT=true
KP_ADDRESS=127.0.0.1:9000          # loopback: sin superficie S3 pública (T1)
KP_CONSOLE_ADDRESS=127.0.0.1:9001
KP_KEY_PROVIDER=kms
KP_KMS_ENDPOINT=https://localhost:8200   # el Vault del portátil, vía túnel -R
KP_KMS_KEY=kerplace
KP_KMS_CA=/etc/kerplace/kms-ca.crt
KP_KMS_TOKEN=<SCOPED_TOKEN>
KP_ROOT_USER=kpadmin
KP_ROOT_PASSWORD=$(openssl rand -hex 12)
EOF
sudo chmod 600 /etc/kerplace.env
```

### 4. La CA del KMS
El portátil te la copia (paso P1). Debe quedar en `/etc/kerplace/kms-ca.crt`.

### 5. Unit systemd
```bash
sudo tee /etc/systemd/system/kerplace.service >/dev/null <<'EOF'
[Unit]
Description=KerPlace (S3) with external KMS custody
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/kerplace.env
ExecStart=/usr/local/bin/kerplace
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
# NO lo habilites para auto-arranque: adminKP.sh lo arranca/para. Sin KMS, falla-cerrado.
```

### 6. SSH endurecido (T4)
Confirma que el sshd del host ofrece ML-KEM (si no, el túnel PQC no montará):
```bash
ssh -Q kex | grep mlkem768x25519-sha256    # debe aparecer
```
Restringe la clave del túnel en `~/.ssh/authorized_keys` del host (una sola línea;
nada de shell/pty/agent, solo los dos forwards del modo):
```
restrict,port-forwarding,permitlisten="127.0.0.1:8200",permitopen="127.0.0.1:9000" ssh-ed25519 AAAA...clave-de-custodia... custodia
```

### 7. Firewall — cerrar el 9000 público (GCP)
Con `KP_ADDRESS=127.0.0.1:9000` el S3 solo se alcanza por el túnel; cierra el puerto:
```bash
# GCP: NO abras 9000/9001 en las reglas de firewall. Si hubiera una regla, quítala:
gcloud compute firewall-rules delete allow-kerplace-9000 2>/dev/null || true
# deja abierto solo el 22 (SSH). Todo lo demás va por el túnel.
```

---

## B · En el PORTÁTIL (lado KMS)

### P1. Copiar la CA al host nuevo
```bash
scp -i <SSH_KEY> /home/alex/.config/kerplace/kms-ca.crt <NEW_HOST>:/tmp/kms-ca.crt
ssh -i <SSH_KEY> <NEW_HOST> 'sudo install -D -m 644 /tmp/kms-ca.crt /etc/kerplace/kms-ca.crt && rm -f /tmp/kms-ca.crt'
```

### P2. Acuñar un token scoped NUEVO para este host
Un token por host (revocable de forma independiente). En el portátil, con OpenBao
des-sellado:
```bash
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/home/alex/.config/kerplace/kms-ca.crt
export VAULT_TOKEN=$(sudo python3 -c 'import json;print(json.load(open("/etc/openbao/.vault-init.json"))["root_token"])')
bao token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token
# ese valor -> <SCOPED_TOKEN> en /etc/kerplace.env del host (paso A3):
#   ssh <NEW_HOST> "sudo sed -i 's|^KP_KMS_TOKEN=.*|KP_KMS_TOKEN=<SCOPED_TOKEN>|' /etc/kerplace.env"
```

### P3. Fijar la identidad del host (pin, sin TOFU — T4)
```bash
ssh-keyscan -t ed25519 <IP_DEL_HOST> >> "$HOME/.config/kerplace/known_hosts"
ssh-keygen -lf "$HOME/.config/kerplace/known_hosts"    # VERIFICA el fingerprint aparte
```
Y apunta la config de adminKP al host nuevo (`adminkp.env`):
```
KP_ADMIN_HOST=<NEW_HOST>
KP_ADMIN_SSH_KEY=<SSH_KEY>
```

### P4. Túnel + arranque
```bash
./adminKP.sh --enable
# levanta el túnel (-R 8200 custodia + -L 9000 datos, KEX ML-KEM),
# arranca KerPlace en el host (su check fail-closed pasa porque el KMS llega),
# y monta los buckets.
```

---

## C · Verificación (fail-closed)
- Con el túnel abajo: `mc ls` falla y KerPlace no arranca (o no sirve). El 9000 público
  está cerrado, así que no hay ruta desde Internet.
- sshd sin ML-KEM ⇒ el túnel no monta (no degrada).
- `--status` refleja: KMS des-sellado (USB), túnel activo, KerPlace activo.

> **Migración de datos:** el host nuevo empieza vacío. Los objetos del host viejo son
> ciphertext atado a la MISMA Transit key (sigue en tu OpenBao), así que se copian con
> `mc mirror <viejo> <nuevo>` mientras ambos están `--enabled` — se descifran al leer del
> viejo y se re-cifran al escribir en el nuevo, con la misma custodia.
