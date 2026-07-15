//! kpc — KerPlaceClient. Administration CLI for KerPlace in custody mode.
//!
//! One self-explaining command to operate the off-host KMS and the buckets it
//! protects: `status`, `unseal`, `seal`, `provision-usb`, `enable`/`disable`,
//! `mount`/`umount`, `backup`. Built for daily use and, above all, for disaster
//! recovery: any admin with `kpc` on the path and `kpc --help` knows what to do,
//! without hunting for loose scripts.
//!
//! It orchestrates standard system tools (curl, gpg, systemctl, findmnt, s3fs),
//! so the binary stays small and self-contained. Configuration is TOML.

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
    about = "KerPlaceClient — custody administration (off-host KMS + encrypted buckets).",
    long_about = "kpc drives the custody KMS (OpenBao) and KerPlace's buckets.\n\
    In custody mode the data is readable only while the KMS is unsealed, and the KMS\n\
    unseals only with the custody USB + passphrase. kpc is the only command you need:\n\
      kpc status         sealed? USB? tunnels? mounts?\n\
      kpc unseal         unseal with the USB (prompts for the passphrase)\n\
      kpc seal           seal NOW (unmount + restart the KMS)      [sudo]\n\
      kpc mount <bucket> mount a bucket over FUSE\n\
    Config: /etc/kerplace/kpc.toml (or ~/.config/kerplace/kpc.toml)."
)]
struct Cli {
    /// Path to the TOML config (default: /etc/kerplace/kpc.toml or ~/.config/kerplace/kpc.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Status: is the KMS sealed? is the custody USB present? tunnels and mounts.
    Status,
    /// Unseal the KMS with the USB material (prompts for the passphrase). No root needed.
    Unseal,
    /// Seal the KMS NOW: unmount the buckets and restart the KMS. Needs root (sudo).
    Seal,
    /// Mount a bucket over FUSE (s3fs) as declared in the config.
    Mount {
        /// Bucket name (as it appears in the config).
        bucket: String,
    },
    /// Unmount a bucket.
    Umount {
        /// Bucket name.
        bucket: String,
    },
    /// Migrate the unseal material from disk onto the encrypted USB. [still script-backed]
    ProvisionUsb { path: Option<String> },
    /// Bring everything up: tunnel(s) + unseal (if sealed) + mount buckets. One command.
    Enable {
        /// A specific instance (default: all of them).
        instance: Option<String>,
    },
    /// Take everything down: unmount buckets + stop tunnel(s) + seal the KMS.
    Disable {
        /// A specific instance (default: all of them).
        instance: Option<String>,
    },
    /// Disaster-recovery backup of the KMS (two artifacts). [still script-backed]
    Backup { dir: Option<String> },
    /// (agent) Watch for the USB being inserted and run 'enable'. For systemd --user.
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
        format!("cannot read the config {path:?} (create /etc/kerplace/kpc.toml or ~/.config/kerplace/kpc.toml)")
    })?;
    toml::from_str(&s).context("invalid TOML config")
}

// ── helpers ──────────────────────────────────────────────────────────────────
fn sh(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running '{cmd}'"))
}
fn sh_trim(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Is the KMS sealed? (curl to /v1/sys/seal-status with the private CA.)
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

/// Wait up to `secs` for the USB to be MOUNTED (on insertion the desktop's
/// auto-mount takes a moment after the device node appears).
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

// ── commands ─────────────────────────────────────────────────────────────────
fn cmd_status(c: &Config) -> Result<()> {
    let sealed = match kms_sealed(&c.kms) {
        Some(true) => "SEALED",
        Some(false) => "unsealed",
        None => "no answer",
    };
    println!("KMS   {:<14} {}", sealed, c.kms.addr);
    println!(
        "USB   {:<14} LABEL={} UUID={}",
        if usb_present(&c.usb) { "present" } else { "ABSENT" },
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
        println!("inst  {:<14} tunnel:{}", inst.name, tun);
        for b in &inst.buckets {
            println!(
                "        bucket {:<12} {:<9} {}",
                b.name,
                if is_mounted(&mounts, &b.mountpoint) { "mounted" } else { "—" },
                b.mountpoint
            );
        }
    }
    Ok(())
}

fn cmd_unseal(c: &Config) -> Result<()> {
    let mount = usb_mount_wait(&c.usb, 15).context("custody USB not mounted (LABEL not found)")?;
    let file = format!("{}/{}", mount, c.usb.unseal_file);
    if !Path::new(&file).exists() {
        bail!("cannot find the unseal material on the USB: {file}");
    }
    let pass = get_passphrase("Custody USB passphrase:")?;

    // gpg -d in loopback mode, passphrase over stdin. The output (JSON) stays in memory.
    let mut gpg = Command::new("gpg")
        .args(["--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "-d", &file])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not launch gpg")?;
    gpg.stdin.take().unwrap().write_all(pass.as_bytes())?;
    let out = gpg.wait_with_output()?;
    if !out.status.success() || out.stdout.is_empty() {
        bail!("empty decryption — wrong passphrase or invalid USB");
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).context("invalid unseal JSON")?;
    let key = v["unseal_keys_b64"][0]
        .as_str()
        .context("the material carries no unseal_keys_b64")?;

    // PUT /v1/sys/unseal with the body over stdin (keeps the key out of 'ps').
    let body = serde_json::json!({ "key": key }).to_string();
    let url = format!("{}/v1/sys/unseal", c.kms.addr);
    let mut curl = Command::new("curl")
        .args(["-s", "--cacert", &c.kms.cacert, "-X", "PUT", "--data", "@-", &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not launch curl")?;
    curl.stdin.take().unwrap().write_all(body.as_bytes())?;
    let resp = curl.wait_with_output()?;
    let rv: serde_json::Value = serde_json::from_slice(&resp.stdout).unwrap_or_default();
    match rv.get("sealed").and_then(|x| x.as_bool()) {
        Some(false) => {
            println!("KMS unsealed ✓");
            Ok(())
        }
        Some(true) => bail!("the KMS is still sealed (key threshold > 1?)"),
        None => bail!(
            "unexpected response from the KMS: {}",
            String::from_utf8_lossy(&resp.stdout)
        ),
    }
}

/// Ask for the passphrase. From a terminal it uses rpassword; with no TTY (e.g.
/// launched by systemd on USB insertion) it falls back to a graphical prompt.
fn get_passphrase(prompt: &str) -> Result<String> {
    // TERMINAL first: rpassword reads /dev/tty, so this works over SSH on a
    // headless host (no desktop). Only when there is NO controlling terminal
    // (e.g. `kpc watch` started by systemd on insertion) do we fall back to a GUI.
    if let Ok(p) = rpassword::prompt_password(format!("{prompt} ")) {
        return Ok(p);
    }
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
        .context("could not ask for the passphrase (no TTY and no graphical prompt)")
}

/// Unmount a bucket: fusermount3 (as the user) and, failing that, umount -l via sudo.
fn unmount_bucket(mp: &str) {
    if sh("fusermount3", &["-u", mp]).map(|s| s.status.success()).unwrap_or(false) {
        return;
    }
    let _ = sh("sudo", &["umount", "-l", mp]);
}

/// Seal the KMS by restarting its service (it starts sealed). Uses sudo — the only root step.
fn seal_kms(c: &Config) -> Result<()> {
    let st = sh("sudo", &["systemctl", "restart", &c.kms.service])?;
    if !st.status.success() {
        bail!("could not restart '{}' (sudo): {}", c.kms.service, String::from_utf8_lossy(&st.stderr));
    }
    Ok(())
}

/// The selected instances (all of them, or one by name).
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
    println!("KMS sealed + buckets unmounted.");
    Ok(())
}

/// enable = tunnel(s) up + unseal if sealed + mount buckets. Runs as the user.
fn cmd_enable(c: &Config, name: Option<&str>) -> Result<()> {
    for inst in instances(c, name) {
        if !inst.tunnel_unit.is_empty()
            && sh_trim("systemctl", &["--user", "is-active", &inst.tunnel_unit]) != "active"
        {
            println!("bringing up tunnel {}", inst.tunnel_unit);
            let _ = sh("systemctl", &["--user", "start", &inst.tunnel_unit]);
        }
    }
    if kms_sealed(&c.kms) == Some(true) {
        cmd_unseal(c)?;
    } else {
        println!("KMS already unsealed.");
    }
    for inst in instances(c, name) {
        for b in &inst.buckets {
            if let Err(e) = cmd_mount(c, &b.name) {
                eprintln!("  warning: could not mount '{}': {e}", b.name);
            }
        }
    }
    println!("---");
    cmd_status(c)
}

/// disable = unmount buckets + stop tunnel(s) + seal the KMS.
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
    println!("Down: buckets unmounted, tunnel stopped, KMS sealed.");
    Ok(())
}

fn write_passwd(inst: &Instance) -> Result<String> {
    let secret = std::fs::read_to_string(&inst.secret_file)
        .with_context(|| format!("reading secret_file {}", inst.secret_file))?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = format!("{home}/.config/kerplace");
    std::fs::create_dir_all(&dir).ok();
    let passwd = format!("{dir}/.kpc-passwd-{}", inst.name);
    std::fs::write(&passwd, format!("{}:{}\n", inst.access_key, secret.trim()))?;
    std::fs::set_permissions(&passwd, std::fs::Permissions::from_mode(0o600))?;
    Ok(passwd)
}

fn cmd_mount(c: &Config, name: &str) -> Result<()> {
    let (inst, b) = find_bucket(c, name).with_context(|| format!("bucket '{name}' is not in the config"))?;
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    if is_mounted(&mounts, &b.mountpoint) {
        println!("already mounted: {} @ {}", b.name, b.mountpoint);
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
            "s3fs failed to mount '{}': {}\n  hint: is any terminal/process sitting with its cwd INSIDE {}? leave it (cd ~) and retry.",
            b.name,
            String::from_utf8_lossy(&st.stderr).trim(),
            b.mountpoint
        );
    }
    println!("mounted '{}' @ {}", b.name, b.mountpoint);
    Ok(())
}

fn cmd_umount(c: &Config, name: &str) -> Result<()> {
    let (_i, b) = find_bucket(c, name).with_context(|| format!("bucket '{name}' is not in the config"))?;
    let st = sh("fusermount3", &["-u", &b.mountpoint]);
    if st.map(|s| s.status.success()).unwrap_or(false) {
        println!("unmounted {}", b.mountpoint);
        return Ok(());
    }
    let _ = sh("umount", &["-l", &b.mountpoint]);
    println!("unmounted (lazy) {}", b.mountpoint);
    Ok(())
}

/// Insertion agent: detects the absent→present EDGE of the USB (by UUID) and runs
/// enable. Edge-triggered (no polling loop like the .path unit did). Runs as a
/// systemd --user service, so it inherits the graphical session (kdialog works).
fn cmd_watch(c: &Config) -> Result<()> {
    let uuid_path = format!("/dev/disk/by-uuid/{}", c.usb.uuid);
    // Init to `false`: if the USB is already in at startup (e.g. after a boot with
    // the KMS sealed), the first cycle treats it as an insertion and runs enable.
    let mut present = false;
    eprintln!("[kpc watch] watching {uuid_path}");
    loop {
        let now = Path::new(&uuid_path).exists();
        if now && !present {
            eprintln!("[kpc watch] USB inserted -> enable");
            if let Err(e) = cmd_enable(c, None) {
                eprintln!("[kpc watch] enable failed: {e}");
            }
        } else if !now && present {
            // Removal: sealing and unmounting are already done by the system
            // service; here we stop the tunnel(s), which are --user units and so
            // live in the user's context.
            eprintln!("[kpc watch] USB removed -> stopping tunnel(s)");
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
    println!("[kpc] '{name}' is not ported to native Rust yet.");
    println!("      For now: {hint}");
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
        Cmd::ProvisionUsb { .. } => stub("provision-usb", "use ~/.config/kerplace/usb-reprovision.sh"),
        Cmd::Backup { .. } => stub("backup", "use ~/.config/kerplace/dr-backup.sh"),
        Cmd::Watch => cmd_watch(&cfg),
    }
}
