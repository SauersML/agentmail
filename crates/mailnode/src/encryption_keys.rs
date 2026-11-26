//! Private encryption seeds live in a dedicated owner-only directory. Only signed public records leave it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use mailcore::keys::Seed;
use mailcore::node_key::{NodeEncryptionKey, ROTATION_MS};

pub struct EncryptionKeys {
    dir: PathBuf,
    retention_epochs: i64,
}

impl EncryptionKeys {
    pub fn new(data_dir: &Path, days: u32) -> Result<Self> {
        ensure!(days > 0, "encryption_key_retention_days must be positive");
        let dir = data_dir.join("encryption-keys");
        crate::private_fs::create_dir(&dir)?;
        crate::private_fs::check_dir(&dir).context("encryption key directory must be private")?;
        Ok(Self { dir, retention_epochs: i64::from(days) * 4 })
    }

    pub fn rotate(&self, identity: &Seed, network: &str, now: i64) -> Result<NodeEncryptionKey> {
        let epoch = now.div_euclid(ROTATION_MS);
        ensure!(epoch >= 0, "invalid system clock");
        let cutoff = epoch - self.retention_epochs;
        let mut removed = false;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // A crash during atomic publication can leave a second link to a private key.
            let unpublished = name.starts_with(".mailnode-") && name.ends_with(".tmp");
            let stored = name.strip_suffix(".seed").and_then(|n| n.parse::<i64>().ok());
            if unpublished || stored.is_some_and(|e| e <= cutoff) {
                fs::remove_file(entry.path())?;
                removed = true;
            } else if stored.is_some_and(|e| e > epoch) {
                anyhow::bail!("clock precedes a stored encryption key");
            }
        }
        if removed { crate::private_fs::sync_dir(&self.dir)?; }
        let secret = crate::config::read_or_create_seed(&self.dir.join(format!("{epoch}.seed")))?;
        Ok(NodeEncryptionKey::issue(identity, network, epoch, &secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_reopen_and_retire_at_the_configured_boundary() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("agentmail-rotation-{}", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let identity = Seed::generate();
        let keys = EncryptionKeys::new(&dir, 1)?;
        let first = keys.rotate(&identity, "net", 0)?;
        assert_eq!(EncryptionKeys::new(&dir, 1)?.rotate(&identity, "net", ROTATION_MS - 1)?, first);
        let second = keys.rotate(&identity, "net", ROTATION_MS)?;
        assert_ne!(first.x25519, second.x25519);
        assert!(keys.rotate(&identity, "net", 0).is_err());
        let old = keys.dir.join("0.seed");
        fs::hard_link(&old, keys.dir.join(".mailnode-interrupted.tmp"))?;
        keys.rotate(&identity, "net", 4 * ROTATION_MS - 1)?;
        assert!(old.is_file());
        keys.rotate(&identity, "net", 4 * ROTATION_MS)?;
        assert!(!old.exists() && !keys.dir.join(".mailnode-interrupted.tmp").exists());
        assert!(keys.dir.join("1.seed").is_file());
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
