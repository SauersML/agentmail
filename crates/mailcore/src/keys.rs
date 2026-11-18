//! Ed25519 keys as the island writes them (`ed25519:<base64url of the 32 raw bytes>`), and the X25519 keys derived
//! from them for encryption (the birational map for public keys; SHA-512 of the seed, clamped, for secrets).

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::{b64u, b64u_decode};

pub type PublicKey = [u8; 32];

pub fn parse_key(s: &str) -> Result<PublicKey> {
    let raw = s.strip_prefix("ed25519:").ok_or_else(|| anyhow!("key must start with ed25519:"))?;
    let bytes = b64u_decode(raw).ok_or_else(|| anyhow!("key is not base64url"))?;
    let key: PublicKey = bytes.try_into().map_err(|_| anyhow!("key is not 32 bytes"))?;
    VerifyingKey::from_bytes(&key).map_err(|_| anyhow!("not a valid ed25519 point"))?;
    Ok(key)
}

pub fn fmt_key(key: &PublicKey) -> String {
    format!("ed25519:{}", b64u(key))
}

/// A private Ed25519 seed. Never printed: Debug shows only the public key.
#[derive(Clone)]
pub struct Seed([u8; 32]);

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seed({})", fmt_key(&self.public()))
    }
}

impl Seed {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Seed(b)
    }

    pub fn generate() -> Self {
        Seed(crate::random_bytes())
    }

    /// Hex, as islandmail.py stores seeds (`"seed": "<64 hex>"`).
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != 64 {
            bail!("seed must be 64 hex characters");
        }
        let mut b = [0u8; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| anyhow!("seed is not hex"))?;
        }
        Ok(Seed(b))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public(&self) -> PublicKey {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.0).sign(msg).to_bytes()
    }

    pub fn x25519_secret(&self) -> StaticSecret {
        let h = Sha512::digest(self.0);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        let out = StaticSecret::from(s);
        s.zeroize();
        out
    }
}

pub fn verify(key: &PublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(key) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

pub fn x25519_public(key: &PublicKey) -> Result<[u8; 32]> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| anyhow!("not a valid ed25519 point"))?;
    if vk.is_weak() {
        bail!("weak ed25519 key");
    }
    Ok(vk.to_montgomery().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_and_x25519_agree() {
        let a = Seed::generate();
        let b = Seed::generate();
        assert_eq!(parse_key(&fmt_key(&a.public())).unwrap(), a.public());
        let ab = a.x25519_secret().diffie_hellman(&x25519_dalek::PublicKey::from(x25519_public(&b.public()).unwrap()));
        let ba = b.x25519_secret().diffie_hellman(&x25519_dalek::PublicKey::from(x25519_public(&a.public()).unwrap()));
        assert_eq!(ab.as_bytes(), ba.as_bytes());
        assert_eq!(Seed::from_hex(&a.to_hex()).unwrap().public(), a.public());
        assert!(!format!("{a:?}").contains(&a.to_hex()));
    }
}
