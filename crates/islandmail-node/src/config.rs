//! Node configuration (JSON). Relative paths are relative to the config file's folder.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use islandmail_core::keys::Seed;
use islandmail_core::MemberList;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Loopback HTTP API, e.g. "127.0.0.1:8787"
    #[serde(default = "default_api")]
    pub api_listen: String,
    /// UDP port for iroh (0 = any)
    #[serde(default)]
    pub iroh_port: u16,
    /// Relay origins shared by peers, or "n0" for iroh's public relay set. Empty means direct only.
    #[serde(default)]
    pub relay: Vec<String>,
    #[serde(default = "default_key_retention")]
    pub encryption_key_retention_days: u32,
    /// Hex seed file of this node's Ed25519 key (= its iroh endpoint id). Created on first run if missing.
    pub node_key_file: PathBuf,
    pub members_file: PathBuf,
    /// Optional folder of islandmail.py identity files ({name, seed, …}) of the agents on this host. Their keys let
    /// this node read "private" mail addressed to them. Seeds are read, never logged or copied.
    #[serde(default)]
    pub identities_dir: Option<PathBuf>,
    /// Who may get a certificate here: "open" (default: any local user or process, through POST /api/agents) or
    /// "identities_dir" (only the identity files the operator put in identities_dir; POST /api/agents is refused).
    #[serde(default)]
    pub certify: Certify,
    #[serde(default = "default_sync")]
    pub sync_secs: u64,
    /// Base URL for attachment links in formatted mail (default http://<api_listen>).
    #[serde(default)]
    pub public_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Certify {
    #[default]
    Open,
    IdentitiesDir,
}

fn default_api() -> String {
    "127.0.0.1:8787".into()
}
fn default_key_retention() -> u32 { 14 }
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
        let raw = std::fs::read(&self.members_file)
            .with_context(|| format!("reading {}", self.members_file.display()))?;
        Self::parse_members(&raw)
    }

    pub fn parse_members(raw: &[u8]) -> Result<MemberList> {
        let list: MemberList = serde_json::from_slice(raw).context("member list is not valid JSON")?;
        list.validate()?;
        Ok(list)
    }

    pub fn node_seed(&self) -> Result<Seed> {
        read_or_create_seed(&self.node_key_file)
    }

    /// (name, sub, path, seed) of each local identity file. Files that do not parse, and files other users could read
    /// (group or world bits set), are skipped with a warning.
    pub fn identities(&self) -> Vec<(String, String, PathBuf, Seed)> {
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
                out.push((name.to_string(), v["sub"].as_str().unwrap_or("").to_string(), p.clone(), s));
            }
        }
        out
    }
}

/// Refuses a key file other users could read or write (see private_fs), or one that is not a regular file.
pub fn read_private(path: &Path) -> Result<String> {
    use std::io::Read;
    let file = crate::private_fs::options().read(true).open(path).with_context(|| format!("opening {}", path.display()))?;
    let md = file.metadata()?;
    if !md.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    crate::private_fs::check_file(&file, path)?;
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
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".islandmail-node-{}.tmp", islandmail_core::b64u(&islandmail_core::random_bytes::<16>())));
    let mut f = crate::private_fs::options().write(true).create_new(true).open(&tmp)?;
    // Publish the complete file without replacing a key another process just created.
    let result = (|| -> Result<()> {
        crate::private_fs::restrict_file(&f, &tmp)?;
        f.write_all(seed.to_hex().as_bytes())?;
        f.sync_all()?;
        Ok(std::fs::hard_link(&tmp, path)?)
    })();
    drop(f);
    let cleanup = std::fs::remove_file(&tmp);
    result.with_context(|| format!("creating {}", path.display()))?;
    cleanup?;
    crate::private_fs::sync_dir(dir)
}

pub fn read_or_create_seed(path: &Path) -> Result<Seed> {
    use std::io::{Error, ErrorKind};
    match read_seed(path) {
        Err(e) if e.downcast_ref::<Error>().is_some_and(|e| e.kind() == ErrorKind::NotFound) => {}
        result => return result,
    }
    let seed = Seed::generate();
    match write_seed(path, &seed) {
        Ok(()) => Ok(seed),
        Err(e) if e.downcast_ref::<Error>().is_some_and(|e| e.kind() == ErrorKind::AlreadyExists) => read_seed(path),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_first_starts_share_one_complete_private_seed() {
        let dir = std::env::temp_dir().join(format!("islandmail-node-key-{}", islandmail_core::b64u(&islandmail_core::random_bytes::<12>())));
        let path = dir.join("node.seed");
        let start = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            let writers: Vec<_> = (0..4).map(|_| scope.spawn(|| {
                start.wait();
                read_or_create_seed(&path).unwrap().public()
            })).collect();
            let keys: Vec<_> = writers.into_iter().map(|w| w.join().unwrap()).collect();
            assert!(keys.iter().all(|k| *k == keys[0]));
        });
        let original = read_seed(&path).unwrap().public();
        assert!(write_seed(&path, &Seed::generate()).is_err());
        assert_eq!(read_seed(&path).unwrap().public(), original);
        crate::private_fs::check_file(&std::fs::File::open(&path).unwrap(), &path).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
