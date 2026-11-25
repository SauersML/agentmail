//! Node configuration (JSON). Relative paths are relative to the config file's folder.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mailcore::keys::{parse_key, Seed};
use mailcore::MemberList;
use serde::Deserialize;

/// Keys of earlier config formats. A config that still has any of them is refused at load.
const RETIRED_FIELDS: &[&str] = &["home", "renamed", "refuse_token_only", "id_floor", "bridge"];

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Where the store and the adopted member list live (default "data").
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Local HTTP API, e.g. "127.0.0.1:8787"
    #[serde(default = "default_api")]
    pub api_listen: String,
    /// UDP port for iroh (0 = any)
    #[serde(default)]
    pub iroh_port: u16,
    /// Hex seed file of this node's Ed25519 key (= its iroh endpoint id). Created on first run if missing.
    #[serde(default = "default_node_key_file")]
    pub node_key_file: PathBuf,
    /// The operator key the member list must be signed by.
    pub operator_key: String,
    /// The operator-signed member list (default "members.json").
    #[serde(default = "default_members_file")]
    pub members_file: PathBuf,
    /// "disabled" (direct addresses only), "n0" (n0's public relays and address lookup), the URL of our own
    /// iroh-relay (e.g. "http://203.0.113.7:3340"), or a list mixing URLs and "n0" (our relays first, n0 as fallback).
    #[serde(default = "default_relay")]
    pub relay: Relay,
    /// Optional folder of identity files ({name, seed, …}, mode 600) of agents on this host whose keys this node
    /// holds. Each one in this node's namespace gets a certificate from this node at startup, and an unsigned post
    /// from it is signed by the node with its key. Seeds are read, never logged or copied.
    #[serde(default)]
    pub identities_dir: Option<PathBuf>,
    #[serde(default = "default_sync")]
    pub sync_secs: u64,
    /// Base URL for attachment links in formatted mail (default http://<api_listen>).
    #[serde(default)]
    pub public_url: Option<String>,
}

fn default_data_dir() -> PathBuf {
    "data".into()
}
fn default_node_key_file() -> PathBuf {
    "node.seed".into()
}
fn default_members_file() -> PathBuf {
    "members.json".into()
}
fn default_api() -> String {
    "127.0.0.1:8787".into()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Relay {
    One(String),
    Many(Vec<String>),
}

impl Relay {
    pub fn entries(&self) -> Vec<String> {
        match self {
            Relay::One(s) => vec![s.clone()],
            Relay::Many(v) => v.clone(),
        }
    }
}

fn default_relay() -> Relay {
    Relay::One("n0".into())
}
fn default_sync() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut c = Config::parse(&raw)?;
        let base = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
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

    /// Parses config JSON (paths as written). Refuses fields of earlier formats by name.
    pub fn parse(raw: &str) -> Result<Config> {
        let v: serde_json::Value = serde_json::from_str(raw).context("config is not valid JSON")?;
        let obj = v.as_object().context("config must be a JSON object")?;
        let old: Vec<&str> = RETIRED_FIELDS.iter().copied().filter(|k| obj.contains_key(*k)).collect();
        if !old.is_empty() {
            anyhow::bail!(
                "config has fields from the old setup that no longer exist: {}. Delete them; agents now get a \
                 certificate from this node on first use.",
                old.join(", ")
            );
        }
        serde_json::from_value(v).context("config does not have the expected fields")
    }

    pub fn adopted_members_path(&self) -> PathBuf {
        self.data_dir.join("members.latest.json")
    }

    /// The configured member list, or the newer one this node adopted from the network earlier.
    pub fn best_members(&self) -> Result<MemberList> {
        let file = self.members()?;
        let op = parse_key(&self.operator_key)?;
        let adopted = std::fs::read_to_string(self.adopted_members_path())
            .ok()
            .and_then(|r| serde_json::from_str::<MemberList>(&r).ok())
            .filter(|l| l.verify(&op).is_ok() && l.network == file.network);
        Ok(match adopted {
            Some(a) if a.seq > file.seq => a,
            _ => file,
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

    /// (name, seed) of each identity file in `identities_dir`. Files that do not parse, and files other users could
    /// read (group or world bits set), are skipped with a warning.
    pub fn identities(&self) -> Vec<(String, Seed)> {
        let Some(dir) = &self.identities_dir else { return vec![] };
        read_identities(dir)
    }
}

/// (name, seed) of each `*.json` identity file in `dir` (see `Config::identities`).
pub fn read_identities(dir: &Path) -> Vec<(String, Seed)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        tracing::warn!("identities_dir {} cannot be read", dir.display());
        return vec![];
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        if let Err(e) = check_private(&p) {
            tracing::warn!("skipping identity file: {e:#}");
            continue;
        }
        let parsed = std::fs::read_to_string(&p)
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|v| {
                let name = v["name"].as_str()?.to_string();
                let seed = Seed::from_hex(v["seed"].as_str()?).ok()?;
                Some((name, seed))
            });
        match parsed {
            Some(x) => out.push(x),
            None => tracing::warn!("skipping identity file {}: it needs a \"name\" and a hex \"seed\"", p.display()),
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Refuses a key file other users could read or write: any group or world permission bit, or not a regular file.
pub fn check_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !md.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!("{} holds a private key but has mode {mode:o}; run chmod 600 on it", path.display());
    }
    Ok(())
}

pub fn read_seed(path: &Path) -> Result<Seed> {
    check_private(path)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::parse(r#"{"operator_key": "ed25519:AAAA"}"#).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("data"));
        assert_eq!(c.node_key_file, PathBuf::from("node.seed"));
        assert_eq!(c.members_file, PathBuf::from("members.json"));
        assert_eq!(c.relay.entries(), vec!["n0".to_string()]);
        assert_eq!(c.api_listen, "127.0.0.1:8787");
        assert!(c.identities_dir.is_none());
    }

    #[test]
    fn retired_fields_refused_by_name() {
        let e = Config::parse(r#"{"operator_key": "ed25519:AAAA", "home": {}, "id_floor": 5}"#).unwrap_err();
        let m = format!("{e:#}");
        assert!(m.contains("home, id_floor"), "{m}");
        assert!(m.contains("Delete them"), "{m}");
    }

    #[test]
    fn relative_paths_follow_the_config_folder() {
        let dir = std::env::temp_dir().join(format!("mailnode-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.json");
        std::fs::write(&p, r#"{"operator_key": "ed25519:AAAA", "identities_dir": "ids"}"#).unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.data_dir, dir.join("data"));
        assert_eq!(c.members_file, dir.join("members.json"));
        assert_eq!(c.identities_dir, Some(dir.join("ids")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
