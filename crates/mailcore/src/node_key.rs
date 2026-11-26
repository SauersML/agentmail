//! A node identity signs a fresh encryption key for one network and one six-hour UTC interval.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::keys::{self, fmt_key, PublicKey, Seed};
use crate::{b64u, b64u_decode, paseto::pae};

pub const ROTATION_MS: i64 = 6 * 60 * 60 * 1000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEncryptionKey {
    pub node: String,
    pub network: String,
    pub epoch: i64,
    pub x25519: String,
    pub sig: String,
}

impl NodeEncryptionKey {
    pub fn issue(identity: &Seed, network: &str, epoch: i64, encryption_seed: &Seed) -> Self {
        let public = XPublic::from(&encryption_seed.x25519_secret());
        let mut record = Self {
            node: fmt_key(&identity.public()), network: network.into(), epoch, x25519: b64u(public.as_bytes()), sig: String::new(),
        };
        record.sig = b64u(&identity.sign(&record.statement()));
        record
    }

    fn statement(&self) -> Vec<u8> {
        pae(&[b"agent-mail/node-x25519/v1", self.network.as_bytes(), self.node.as_bytes(),
              &self.epoch.to_le_bytes(), self.x25519.as_bytes()])
    }

    pub fn verify(&self, pinned: &PublicKey, network: &str, now: i64) -> Result<[u8; 32]> {
        ensure!(self.node == fmt_key(pinned) && self.network == network, "wrong node or network for encryption key");
        ensure!(self.epoch >= 0 && self.epoch == now.div_euclid(ROTATION_MS), "encryption key outside its sending interval");
        let raw: [u8; 32] = b64u_decode(&self.x25519).and_then(|b| b.try_into().ok()).context("invalid X25519 key")?;
        ensure!(b64u(&raw) == self.x25519, "noncanonical encryption key encoding");
        let sig = b64u_decode(&self.sig).context("invalid encryption key signature")?;
        ensure!(keys::verify(pinned, &self.statement(), &sig), "invalid encryption key signature");
        ensure!(StaticSecret::from([0x42; 32]).diffie_hellman(&XPublic::from(raw)).was_contributory(), "low-order encryption key");
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_bind_identity_network_interval_and_key() {
        let node = Seed::generate();
        let next = Seed::generate();
        let key = NodeEncryptionKey::issue(&node, "net", 3, &next);
        let now = 3 * ROTATION_MS;
        assert_eq!(key.verify(&node.public(), "net", now).unwrap(), *XPublic::from(&next.x25519_secret()).as_bytes());
        assert!(key.verify(&next.public(), "net", now).is_err());
        assert!(key.verify(&node.public(), "other", now).is_err());
        assert!(key.verify(&node.public(), "net", now - 1).is_err());
        assert!(key.verify(&node.public(), "net", now + ROTATION_MS).is_err());
        let mut altered = key;
        altered.x25519 = b64u(XPublic::from(&Seed::generate().x25519_secret()).as_bytes());
        assert!(altered.verify(&node.public(), "net", now).is_err());
    }
}
