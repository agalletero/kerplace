//! kpc — KerPlaceClient. CLI de administración de KerPlace en modo custodia.
//!
//! Un solo comando, autoexplicado, para operar el KMS off-host y los buckets:
//! `status`, `unseal`, `seal`, `provision-usb`, `enable`/`disable`, `mount`/`umount`,
//! `backup`. Pensado para el día a día y, sobre todo, para DR: cualquier admin con
//! `kpc` en el path y `kpc --help` sabe qué hacer, sin buscar scripts sueltos.
//!
//! Orquesta herramientas de sistema estándar (curl, gpg, systemctl, findmnt, s3fs),
//! así que es un binario pequeño y autocontenido. Config en TOML.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── CLI ──────────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(
    name = "kpc",
    version,
    about = "KerPlaceClient — administración de custodia (KMS off-host + buckets cifrados).",
    long_about = "kpc controla el KMS de custodia (OpenBao) y los buckets de KerPlace.\n\
    En custodia, los datos solo se leen si el KMS está des-sellado, y el KMS solo se\n\
    des-sella con el USB de custodia + passphrase. kpc es el único comando que necesitas:\n\
      kpc status         ¿sellado? ¿USB? ¿túneles? ¿montajes?\n\
      kpc unseal         des-sella con el USB (pide passphrase)\n\
      kpc seal           sella YA (desmonta + reinicia el KMS)   [sudo]\n\
      kpc mount <bucket> monta un bucket por FUSE\n\
    Config: /etc/kerplace/kpc.toml (o ~/.config/kerplace/kpc.toml)."
)]
struct Cli {
    /// Ruta al fichero de config TOML (default: /etc/kerplace/kpc.toml o ~/.config/kerplace/kpc.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Estado: KMS (sellado?), USB de custodia presente?, túneles y montajes.
    Status,
    /// Des-sella el KMS con el material del USB (pide passphrase). No necesita root.
    Unseal,
    /// Sella el KMS AHORA: desmonta los buckets y reinicia el KMS. Necesita root (sudo).
    Seal,
    /// Monta un bucket por FUSE (s3fs) según la config.
    Mount {
        /// Nombre del bucket (tal como está en la config).
        bucket: String,
    },
    /// Desmonta un bucket.
    Umount {
        /// Nombre del bucket.
        bucket: String,
    },
    /// Migra el material de unseal del disco al USB cifrado. [aún vía script]
    ProvisionUsb { path: Option<String> },
    /// Levanta todo: túnel(es) + unseal (si sellado) + montar buckets. Un solo comando.
    Enable {
        /// Instancia concreta (por defecto: todas).
        instance: Option<String>,
    },
    /// Baja todo: desmontar buckets + parar túnel(es) + sellar el KMS.
    Disable {
        /// Instancia concreta (por defecto: todas).
        instance: Option<String>,
    },
    /// Backup de DR del KMS (dos artefactos). [aún vía script]
    Backup { dir: Option<String> },
    /// (agente) Vigila la inserción del USB y ejecuta 'enable' al insertarlo. Para systemd --user.
    Watch,
}

// ── Config ───────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct Config {
    kms: Kms,
    usb: Usb,
    #[serde(default)]
    instances: Vec<Instance>,
}
#[derive(Deserialize)]
struct Kms {
    addr: String,
    cacert: String,
    #[serde(default = "def_service")]
    service: String,
}
fn def_service() -> String {
    "openbao".into()
}
#[derive(Deserialize)]
struct Usb {
    label: String,
    #[serde(default)]
    uuid: String,
    #[serde(default = "def_unseal_file")]
    unseal_file: String,
}
fn def_unseal_file() -> String {
    "kerplace-custody/unseal.json.gpg".into()
}
#[derive(Deserialize)]
struct Instance {
    name: String,
    #[serde(default)]
    tunnel_unit: String,
    #[serde(default)]
    s3_endpoint: String,
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    secret_file: String,
    #[serde(default)]
    buckets: Vec<Bucket>,
}
#[derive(Deserialize)]
struct Bucket {
    name: String,
    mountpoint: String,
}

fn load_config(explicit: Option<&Path>) -> Result<Config> {
    let path = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let sys = PathBuf::from("/etc/kerplace/kpc.toml");
        if sys.exists() {
            sys
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(format!("{home}/.config/kerplace/kpc.toml"))
        }
    };
    let s = std::fs::read_to_string(&path).with_context(|| {
        format!("no puedo leer la config {path:?} (crea /etc/kerplace/kpc.toml o ~/.config/kerplace/kpc.toml)")
    })?;
    toml::from_str(&s).context("config TOML inválida")
}

// ── helpers ──────────────────────────────────────────────────────────────────
fn sh(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("ejecutando '{cmd}'"))
}
fn sh_trim(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// ¿El KMS está sellado? (curl a /v1/sys/seal-status con la CA privada.)
fn kms_sealed(k: &Kms) -> Option<bool> {
    let url = format!("{}/v1/sys/seal-status", k.addr);
    let out = sh("curl", &["-s", "--cacert", &k.cacert, "--max-time", "6", &url]).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.get("sealed").and_then(|x| x.as_bool())
}

fn usb_present(u: &Usb) -> bool {
    if !u.uuid.is_empty() && Path::new(&format!("/dev/disk/by-uuid/{}", u.uuid)).exists() {
        return true;
    }
    Path::new(&format!("/dev/disk/by-label/{}", u.label)).exists()
}

fn usb_mount(u: &Usb) -> Option<String> {
    let t = sh_trim("findmnt", &["-rn", "-S", &format!("LABEL={}", u.label), "-o", "TARGET"]);
    t.lines().next().map(|s| s.to_string()).filter(|s| !s.is_empty())
}

/// Espera hasta `secs` a que el USB esté MONTADO (al insertarlo, el auto-montaje del
/// escritorio tarda un instante tras aparecer el device).
fn usb_mount_wait(u: &Usb, secs: u64) -> Option<String> {
    for _ in 0..secs {
        if let Some(m) = usb_mount(u) {
            return Some(m);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    usb_mount(u)
}

fn find_bucket<'a>(c: &'a Config, name: &str) -> Option<(&'a Instance, &'a Bucket)> {
    for i in &c.instances {
        for b in &i.buckets {
            if b.name == name {
                return Some((i, b));
            }
        }
    }
    None
}

fn is_mounted(mounts: &str, mp: &str) -> bool {
    mounts.lines().any(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        f.len() > 2 && f[1] == mp && f[2] == "fuse.s3fs"
    })
}

// ── comandos ─────────────────────────────────────────────────────────────────
fn cmd_status(c: &Config) -> Result<()> {
    let sealed = match kms_sealed(&c.kms) {
        Some(true) => "SELLADO",
        Some(false) => "des-sellado",
        None => "sin respuesta",
    };
    println!("KMS   {:<14} {}", sealed, c.kms.addr);
    println!(
        "USB   {:<14} LABEL={} UUID={}",
        if usb_present(&c.usb) { "presente" } else { "AUSENTE" },
        c.usb.label,
        c.usb.uuid
    );
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    for inst in &c.instances {
        let tun = if inst.tunnel_unit.is_empty() {
            "—".to_string()
        } else {
            let s = sh_trim("systemctl", &["--user", "is-active", &inst.tunnel_unit]);
            if s.is_empty() { "?".into() } else { s }
        };
        println!("inst  {:<14} túnel:{}", inst.name, tun);
        for b in &inst.buckets {
            println!(
                "        bucket {:<12} {:<9} {}",
                b.name,
                if is_mounted(&mounts, &b.mountpoint) { "montado" } else { "—" },
                b.mountpoint
            );
        }
    }
    Ok(())
}

fn cmd_unseal(c: &Config) -> Result<()> {
    let mount = usb_mount_wait(&c.usb, 15).context("USB de custodia no montado (LABEL no encontrado)")?;
    let file = format!("{}/{}", mount, c.usb.unseal_file);
    if !Path::new(&file).exists() {
        bail!("no encuentro el material de unseal en el USB: {file}");
    }
    let pass = get_passphrase("Passphrase del USB de custodia:")?;

    // gpg -d en loopback, passphrase por stdin. La salida (JSON) va a memoria.
    let mut gpg = Command::new("gpg")
        .args(["--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "-d", &file])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("no pude lanzar gpg")?;
    gpg.stdin.take().unwrap().write_all(pass.as_bytes())?;
    let out = gpg.wait_with_output()?;
    if !out.status.success() || out.stdout.is_empty() {
        bail!("descifrado vacío — passphrase incorrecta o USB inválido");
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).context("JSON de unseal inválido")?;
    let key = v["unseal_keys_b64"][0]
        .as_str()
        .context("el material no contiene unseal_keys_b64")?;

    // PUT /v1/sys/unseal con el cuerpo por stdin (evita exponer la clave en 'ps').
    let body = serde_json::json!({ "key": key }).to_string();
    let url = format!("{}/v1/sys/unseal", c.kms.addr);
    let mut curl = Command::new("curl")
        .args(["-s", "--cacert", &c.kms.cacert, "-X", "PUT", "--data", "@-", &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("no pude lanzar curl")?;
    curl.stdin.take().unwrap().write_all(body.as_bytes())?;
    let resp = curl.wait_with_output()?;
    let rv: serde_json::Value = serde_json::from_slice(&resp.stdout).unwrap_or_default();
    match rv.get("sealed").and_then(|x| x.as_bool()) {
        Some(false) => {
            println!("KMS des-sellado ✓");
            Ok(())
        }
        Some(true) => bail!("el KMS sigue sellado (¿umbral de claves > 1?)"),
        None => bail!(
            "respuesta inesperada del KMS: {}",
            String::from_utf8_lossy(&resp.stdout)
        ),
    }
}

/// Pide la passphrase. Desde un terminal usa rpassword; sin TTY (p.ej. lanzado por
/// systemd al insertar el USB) usa systemd-ask-password (prompt gráfico en KDE/GNOME).
fn get_passphrase(prompt: &str) -> Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(rpassword::prompt_password(format!("{prompt} "))?);
    }
    // Sin TTY (lanzado por systemd al insertar el USB): prueba prompts gráficos.
    let try_gui = |cmd: &str, args: &[&str]| -> Option<String> {
        let o = Command::new(cmd).args(args).output().ok()?;
        if !o.status.success() {
            return None;
        }
        let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if p.is_empty() { None } else { Some(p) }
    };
    try_gui("kdialog", &["--password", prompt])
        .or_else(|| try_gui("zenity", &["--password", "--title", prompt]))
        .or_else(|| try_gui("systemd-ask-password", &["--no-tty", "--timeout=90", prompt]))
        .context("no pude solicitar la passphrase (sin TTY y sin prompt gráfico)")
}

/// Desmonta un bucket: fusermount3 (usuario) y, si falla, umount -l vía sudo.
fn unmount_bucket(mp: &str) {
    if sh("fusermount3", &["-u", mp]).map(|s| s.status.success()).unwrap_or(false) {
        return;
    }
    let _ = sh("sudo", &["umount", "-l", mp]);
}

/// Sella el KMS reiniciando su servicio (arranca sellado). Usa sudo (solo esto es root).
fn seal_kms(c: &Config) -> Result<()> {
    let st = sh("sudo", &["systemctl", "restart", &c.kms.service])?;
    if !st.status.success() {
        bail!("no pude reiniciar '{}' (sudo): {}", c.kms.service, String::from_utf8_lossy(&st.stderr));
    }
    Ok(())
}

/// Instancias seleccionadas (todas, o una por nombre).
fn instances<'a>(c: &'a Config, name: Option<&str>) -> Vec<&'a Instance> {
    match name {
        Some(n) => c.instances.iter().filter(|i| i.name == n).collect(),
        None => c.instances.iter().collect(),
    }
}

fn cmd_seal(c: &Config) -> Result<()> {
    for inst in &c.instances {
        for b in &inst.buckets {
            unmount_bucket(&b.mountpoint);
        }
    }
    seal_kms(c)?;
    println!("KMS sellado + buckets desmontados.");
    Ok(())
}

/// enable = túnel(es) arriba + unseal si está sellado + montar buckets. Corre como usuario.
fn cmd_enable(c: &Config, name: Option<&str>) -> Result<()> {
    for inst in instances(c, name) {
        if !inst.tunnel_unit.is_empty()
            && sh_trim("systemctl", &["--user", "is-active", &inst.tunnel_unit]) != "active"
        {
            println!("levantando túnel {}", inst.tunnel_unit);
            let _ = sh("systemctl", &["--user", "start", &inst.tunnel_unit]);
        }
    }
    if kms_sealed(&c.kms) == Some(true) {
        cmd_unseal(c)?;
    } else {
        println!("KMS ya des-sellado.");
    }
    for inst in instances(c, name) {
        for b in &inst.buckets {
            if let Err(e) = cmd_mount(c, &b.name) {
                eprintln!("  aviso: no pude montar '{}': {e}", b.name);
            }
        }
    }
    println!("---");
    cmd_status(c)
}

/// disable = desmontar buckets + parar túnel(es) + sellar el KMS.
fn cmd_disable(c: &Config, name: Option<&str>) -> Result<()> {
    for inst in instances(c, name) {
        for b in &inst.buckets {
            unmount_bucket(&b.mountpoint);
        }
    }
    for inst in instances(c, name) {
        if !inst.tunnel_unit.is_empty() {
            let _ = sh("systemctl", &["--user", "stop", &inst.tunnel_unit]);
        }
    }
    seal_kms(c)?;
    println!("Abajo: buckets desmontados, túnel parado, KMS sellado.");
    Ok(())
}

fn write_passwd(inst: &Instance) -> Result<String> {
    let secret = std::fs::read_to_string(&inst.secret_file)
        .with_context(|| format!("leyendo secret_file {}", inst.secret_file))?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = format!("{home}/.config/kerplace");
    std::fs::create_dir_all(&dir).ok();
    let passwd = format!("{dir}/.kpc-passwd-{}", inst.name);
    std::fs::write(&passwd, format!("{}:{}\n", inst.access_key, secret.trim()))?;
    std::fs::set_permissions(&passwd, std::fs::Permissions::from_mode(0o600))?;
    Ok(passwd)
}

fn cmd_mount(c: &Config, name: &str) -> Result<()> {
    let (inst, b) = find_bucket(c, name).with_context(|| format!("bucket '{name}' no está en la config"))?;
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    if is_mounted(&mounts, &b.mountpoint) {
        println!("ya montado: {} @ {}", b.name, b.mountpoint);
        return Ok(());
    }
    let passwd = write_passwd(inst)?;
    std::fs::create_dir_all(&b.mountpoint)?;
    let st = sh(
        "s3fs",
        &[
            &b.name,
            &b.mountpoint,
            "-o",
            &format!("url={}", inst.s3_endpoint),
            "-o",
            "use_path_request_style",
            "-o",
            &format!("passwd_file={passwd}"),
            "-o",
            "dbglevel=err",
        ],
    )?;
    if !st.status.success() {
        bail!(
            "s3fs falló montando '{}': {}\n  pista: ¿alguna terminal/proceso con el cwd DENTRO de {}? sal (cd ~) y reintenta.",
            b.name,
            String::from_utf8_lossy(&st.stderr).trim(),
            b.mountpoint
        );
    }
    println!("montado '{}' @ {}", b.name, b.mountpoint);
    Ok(())
}

fn cmd_umount(c: &Config, name: &str) -> Result<()> {
    let (_i, b) = find_bucket(c, name).with_context(|| format!("bucket '{name}' no está en la config"))?;
    let st = sh("fusermount3", &["-u", &b.mountpoint]);
    if st.map(|s| s.status.success()).unwrap_or(false) {
        println!("desmontado {}", b.mountpoint);
        return Ok(());
    }
    let _ = sh("umount", &["-l", &b.mountpoint]);
    println!("desmontado (lazy) {}", b.mountpoint);
    Ok(())
}

/// Agente de inserción: detecta el FLANCO ausente→presente del USB (por UUID) y
/// ejecuta enable. Edge-triggered (sin bucle como el .path). Corre como servicio
/// systemd --user, así que hereda el entorno gráfico (kdialog funciona).
fn cmd_watch(c: &Config) -> Result<()> {
    let uuid_path = format!("/dev/disk/by-uuid/{}", c.usb.uuid);
    // Init a `false`: si el USB ya está puesto al arrancar (p.ej. tras boot con el KMS
    // sellado), el primer ciclo lo trata como inserción y lanza enable.
    let mut present = false;
    eprintln!("[kpc watch] vigilando {uuid_path}");
    loop {
        let now = Path::new(&uuid_path).exists();
        if now && !present {
            eprintln!("[kpc watch] USB insertado -> enable");
            if let Err(e) = cmd_enable(c, None) {
                eprintln!("[kpc watch] enable falló: {e}");
            }
        } else if !now && present {
            // Retirada: el sellado + desmontaje ya los hace el servicio de sistema;
            // aquí paramos el/los túnel(es), que son units --user (contexto usuario).
            eprintln!("[kpc watch] USB retirado -> parando túnel(es)");
            for inst in &c.instances {
                if !inst.tunnel_unit.is_empty() {
                    let _ = sh("systemctl", &["--user", "stop", &inst.tunnel_unit]);
                }
            }
        }
        present = now;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn stub(name: &str, hint: &str) -> Result<()> {
    println!("[kpc] '{name}' aún no está portado a Rust nativo.");
    println!("      De momento: {hint}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(cli.config.as_deref())?;
    match cli.cmd {
        Cmd::Status => cmd_status(&cfg),
        Cmd::Unseal => cmd_unseal(&cfg),
        Cmd::Seal => cmd_seal(&cfg),
        Cmd::Mount { bucket } => cmd_mount(&cfg, &bucket),
        Cmd::Umount { bucket } => cmd_umount(&cfg, &bucket),
        Cmd::Enable { instance } => cmd_enable(&cfg, instance.as_deref()),
        Cmd::Disable { instance } => cmd_disable(&cfg, instance.as_deref()),
        Cmd::ProvisionUsb { .. } => stub("provision-usb", "usa ~/.config/kerplace/usb-reprovision.sh"),
        Cmd::Backup { .. } => stub("backup", "usa ~/.config/kerplace/dr-backup.sh"),
        Cmd::Watch => cmd_watch(&cfg),
    }
}
