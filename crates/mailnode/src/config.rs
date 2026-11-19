//! Node configuration (JSON). Relative paths are relative to the config file's folder.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mailcore::keys::{parse_key, Seed};
use mailcore::{MemberList, TokenPolicy};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct HomeConfig {
    /// The home's pinned token-signing key, e.g. "ed25519:2uXa…"
    pub key: String,
    /// The home's domain (the tokens' iss), e.g. agaric.gnome.science
    pub iss: String,
    #[serde(default = "default_aud")]
    pub aud: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_aud() -> String {
    "mail".into()
}
fn default_scope() -> String {
    "mail:use".into()
}

/// Same shape as the old server's RENAMED var: mail to `name` reaches whoever now holds `now` under `now_sub`.
#[derive(Debug, Deserialize, Clone)]
pub struct Renamed {
    pub name: String,
    pub sub: String,
    pub now: String,
    #[serde(rename = "nowSub")]
    pub now_sub: String,
}

#[derive(Debug, Deserialize, Clone)]
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
    /// The operator key the member list must be signed by.
    pub operator_key: String,
    pub members_file: PathBuf,
    pub home: HomeConfig,
    /// "disabled" (direct addresses only), or "n0" (n0's public relays and address lookup).
    #[serde(default = "default_relay")]
    pub relay: String,
    /// Optional folder of islandmail.py identity files ({name, seed, …}) of the agents on this host. Their keys let
    /// this node read "private" mail addressed to them. Seeds are read, never logged or copied.
    #[serde(default)]
    pub identities_dir: Option<PathBuf>,
    #[serde(default = "default_sync")]
    pub sync_secs: u64,
    #[serde(default)]
    pub renamed: Vec<Renamed>,
}

fn default_api() -> String {
    "127.0.0.1:8787".into()
}
fn default_relay() -> String {
    "disabled".into()
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

    pub fn policy(&self) -> Result<TokenPolicy> {
        Ok(TokenPolicy {
            home_key: parse_key(&self.home.key).context("home.key")?,
            iss: self.home.iss.clone(),
            aud: self.home.aud.clone(),
            scope: self.home.scope.clone(),
        })
    }

    pub fn members(&self) -> Result<MemberList> {
        let raw = std::fs::read_to_string(&self.members_file)
            .with_context(|| format!("reading {}", self.members_file.display()))?;
        let list: MemberList = serde_json::from_str(&raw).context("member list is not valid JSON")?;
        list.verify(&parse_key(&self.operator_key).context("operator_key")?)?;
        Ok(list)
    }

    pub fn node_seed(&self) -> Result<Seed> {
        read_or_create_seed(&self.node_key_file)
    }

    /// (name, seed) of each local identity file. Files that do not parse are skipped.
    pub fn identities(&self) -> Vec<(String, Seed)> {
        let Some(dir) = &self.identities_dir else { return vec![] };
        let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&p) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };
            let (Some(name), Some(seed)) = (v["name"].as_str(), v["seed"].as_str()) else { continue };
            if let Ok(s) = Seed::from_hex(seed) {
                out.push((name.to_string(), s));
            }
        }
        out
    }
}

pub fn read_seed(path: &Path) -> Result<Seed> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Seed::from_hex(&raw)
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
