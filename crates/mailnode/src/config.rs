//! Node configuration (JSON). Relative paths are relative to the config file's folder.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mailcore::keys::Seed;
use mailcore::MemberList;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Compat API, e.g. "127.0.0.1:8787"
    #[serde(default = "default_api")]
    pub api_listen: String,
    /// UDP port for iroh (0 = any)
    #[serde(default)]
    pub iroh_port: u16,
    /// Hex seed file of this node's Ed25519 key (= its iroh endpoint id). Created on first run if missing.
    pub node_key_file: PathBuf,
    pub members_file: PathBuf,
    /// Optional folder of islandmail.py identity files ({name, seed, …}) of the agents on this host. Their keys let
    /// this node read "private" mail addressed to them. Seeds are read, never logged or copied.
    #[serde(default)]
    pub identities_dir: Option<PathBuf>,
    #[serde(default = "default_sync")]
    pub sync_secs: u64,
    /// Base URL for attachment links in formatted mail (default http://<api_listen>).
    #[serde(default)]
    pub public_url: Option<String>,
}

fn default_api() -> String {
    "127.0.0.1:8787".into()
}
fn default_sync() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut c: Config = serde_json::from_str(&raw).context("config is not valid JSON")?;
        let base = path.parent().unwrap_or(Path::new("."));
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut c.data_dir);
        fix(&mut c.node_key_file);
        fix(&mut c.members_file);
        if let Some(d) = c.identities_dir.as_mut() {
            fix(d);
        }
        Ok(c)
    }

    pub fn members(&self) -> Result<MemberList> {
        let raw = std::fs::read_to_string(&self.members_file)
            .with_context(|| format!("reading {}", self.members_file.display()))?;
        let list: MemberList = serde_json::from_str(&raw).context("member list is not valid JSON")?;
        list.validate()?;
        Ok(list)
    }

    pub fn node_seed(&self) -> Result<Seed> {
        read_or_create_seed(&self.node_key_file)
    }

    /// (name, seed) of each local identity file. Files that do not parse, and files other users could read (group or
    /// world bits set), are skipped with a warning.
    pub fn identities(&self) -> Vec<(String, Seed)> {
        let Some(dir) = &self.identities_dir else { return vec![] };
        let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let raw = match read_private(&p) {
                Ok(raw) => raw,
                Err(e) => {
                    tracing::warn!("skipping identity file: {e:#}");
                    continue;
                }
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };
            let (Some(name), Some(seed)) = (v["name"].as_str(), v["seed"].as_str()) else { continue };
            if let Ok(s) = Seed::from_hex(seed) {
                out.push((name.to_string(), s));
            }
        }
        out
    }
}

/// Refuses a key file other users could read or write: any group or world permission bit, or not a regular file.
pub fn read_private(path: &Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path).with_context(|| format!("opening {}", path.display()))?;
    let md = file.metadata()?;
    if !md.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!("{} holds a private key but has mode {mode:o}; run chmod 600 on it", path.display());
    }
    let mut text = String::new();
    file.take(16_385).read_to_string(&mut text)?;
    anyhow::ensure!(text.len() <= 16_384, "private key file too large");
    Ok(text)
}

pub fn read_seed(path: &Path) -> Result<Seed> {
    Seed::from_hex(&read_private(path)?)
}

pub fn write_seed(path: &Path, seed: &Seed) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(seed.to_hex().as_bytes())?;
    f.sync_all()?;
    Ok(())
}

pub fn read_or_create_seed(path: &Path) -> Result<Seed> {
    if path.exists() {
        return read_seed(path);
    }
    let s = Seed::generate();
    write_seed(path, &s)?;
    Ok(s)
}
