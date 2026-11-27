//! Node configuration (JSON). Relative paths are relative to the config file's folder.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use islandmail_core::keys::Seed;
use islandmail_core::MemberList;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
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
    /// Hex seed file of this node's Ed25519 key (= its iroh endpoint id). Created on first run if missing.
    pub node_key_file: PathBuf,
    pub members_file: PathBuf,
    /// Optional folder of islandmail.py identity files ({name, seed, …}) of the agents on this host. Their keys let
    /// this node read "private" mail addressed to them. Seeds are read, never logged or copied.
    #[serde(default)]
    pub identities_dir: Option<PathBuf>,
    /// Seconds between anti-entropy rounds with every peer.
    #[serde(default = "default_sync")]
    pub sync_secs: u64,
}

const KEYS: [&str; 8] = ["data_dir", "api_listen", "iroh_port", "relay", "node_key_file", "members_file", "identities_dir", "sync_secs"];

fn default_api() -> String {
    "127.0.0.1:8787".into()
}

fn default_sync() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        // Whoever can change the config or the trust file decides what this node trusts: only this user (or root).
        crate::private_fs::check_writers(path).context("refusing the config")?;
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let v: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&raw).context("config is not valid")?;
        let unknown: Vec<&str> = v.keys().map(String::as_str).filter(|k| !KEYS.contains(k)).collect();
        if !unknown.is_empty() {
            tracing::warn!("config {}: ignoring unknown keys {}", path.display(), unknown.join(", "));
        }
        let mut c: Config = serde_json::from_value(v.into()).context("config is not valid")?;
        let base = path.parent().unwrap_or(Path::new("."));
        let fix = |p: &mut PathBuf| if p.is_relative() { *p = base.join(&*p) };
        fix(&mut c.data_dir);
        fix(&mut c.node_key_file);
        fix(&mut c.members_file);
        if let Some(d) = c.identities_dir.as_mut() { fix(d) }
        Ok(c)
    }

    pub fn members(&self) -> Result<MemberList> {
        crate::private_fs::check_writers(&self.members_file).context("refusing the trust file")?;
        let raw = std::fs::read(&self.members_file).with_context(|| format!("reading {}", self.members_file.display()))?;
        Self::parse_members(&raw)
    }

    /// A trust file's bytes as a member list.
    pub fn parse_members(raw: &[u8]) -> Result<MemberList> {
        let list: MemberList = serde_json::from_slice(raw).context("member list is not valid")?;
        list.validate()?;
        Ok(list)
    }

    /// (name, seed) of each identity file the node may hold: those whose sub is the one this host knows the name by
    /// (its pin's, else agent:NAME, what the node certifies). Any other would sign tokens the node then refuses ("known
    /// here with another sub"), so it is refused here with a log line naming the file and the fix. Files that do not
    /// parse, and files other users could read (group or world bits set), are skipped with a warning.
    pub fn held(&self, members: &MemberList) -> Vec<(String, Seed)> {
        let Some(dir) = &self.identities_dir else { return vec![] };
        let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
        let norm = islandmail_core::addr::norm;
        let mut out = Vec::new();
        for path in rd.flatten().map(|e| e.path()) {
            if path.extension().and_then(|x| x.to_str()) != Some("json") { continue; }
            let raw = match read_private(&path) {
                Ok(raw) => raw,
                Err(e) => { tracing::warn!("skipping identity file: {e:#}"); continue; }
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };
            let (Some(name), Some(Ok(seed))) = (v["name"].as_str(), v["seed"].as_str().map(Seed::from_hex)) else { continue };
            let sub = v["sub"].as_str().unwrap_or("");
            let pin = members.members.iter().find(|m| norm(&m.name) == norm(name));
            let want = pin.map_or_else(|| islandmail_core::cert::agent_sub(name), |m| m.sub.clone());
            if sub == want { out.push((name.to_string(), seed)); continue; }
            tracing::warn!("refusing identity file {}: its sub is {sub:?}, but {name}'s must be {want:?}; rewrite \"sub\" \
                            to {want:?} (the node re-reads identities_dir within seconds)", path.display());
        }
        out
    }

    /// Names, sizes and modification times in identities_dir: a change means the files need reading again.
    pub fn identities_stamp(&self) -> Vec<(std::ffi::OsString, u64, Option<std::time::SystemTime>)> {
        let Some(dir) = &self.identities_dir else { return vec![] };
        let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
        let mut v: Vec<_> = rd.flatten()
            .map(|e| { let m = e.metadata().ok(); (e.file_name(), m.as_ref().map_or(0, |m| m.len()), m.and_then(|m| m.modified().ok())) })
            .collect();
        v.sort();
        v
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
    fn unknown_config_keys_are_ignored() {
        let dir = std::env::temp_dir().join(format!("islandmail-config-{}", islandmail_core::b64u(&islandmail_core::random_bytes::<9>())));
        crate::private_fs::create_dir(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"data_dir": "d", "node_key_file": "k", "members_file": "m", "certify": "open"}"#).unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!((c.data_dir, c.sync_secs), (dir.join("d"), 30));
        std::fs::remove_dir_all(dir).unwrap();
    }

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
