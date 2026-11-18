//! Body encryption. A fresh 32-byte content key encrypts the body (XChaCha20-Poly1305, random 24-byte nonce, the
//! envelope header as associated data). The content key is wrapped once per recipient key: one ephemeral X25519 key per
//! envelope, a per-recipient wrap key = BLAKE3-derive_key("agent-mail v1 key wrap", epk || recipient_x || shared),
//! and ChaCha20-Poly1305 with a zero nonce (each wrap key is used once) and the recipient's Ed25519 key as AD.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

use crate::keys::{x25519_public, PublicKey, Seed};

const WRAP_CONTEXT: &str = "agent-mail v1 key wrap";

#[derive(Clone, Debug, PartialEq)]
pub struct Wrapped {
    /// Recipient's Ed25519 key.
    pub to: PublicKey,
    /// The content key under that recipient's wrap key: 32 bytes + 16-byte tag.
    pub k: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Sealed {
    /// nonce (24) || ciphertext || tag (16)
    pub ciphertext: Vec<u8>,
    pub epk: [u8; 32],
    pub keys: Vec<Wrapped>,
}

fn wrap_key(epk: &[u8; 32], recipient_x: &[u8; 32], shared: &[u8; 32]) -> [u8; 32] {
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(epk);
    material[32..64].copy_from_slice(recipient_x);
    material[64..].copy_from_slice(shared);
    let k = blake3::derive_key(WRAP_CONTEXT, &material);
    material.zeroize();
    k
}

pub fn seal(plain: &[u8], ad: &[u8], recipients: &[PublicKey]) -> Result<Sealed> {
    if recipients.is_empty() {
        bail!("no recipient keys");
    }
    let mut ck: [u8; 32] = crate::random_bytes();
    let nonce: [u8; 24] = crate::random_bytes();
    let body = XChaCha20Poly1305::new((&ck).into())
        .encrypt((&nonce).into(), Payload { msg: plain, aad: ad })
        .map_err(|_| anyhow!("encrypt failed"))?;
    let mut ciphertext = nonce.to_vec();
    ciphertext.extend_from_slice(&body);

    let esk = StaticSecret::from(crate::random_bytes::<32>());
    let epk = XPublic::from(&esk).to_bytes();
    let mut keys = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for r in recipients {
        if !seen.insert(*r) {
            continue;
        }
        let rx = x25519_public(r)?;
        let shared = esk.diffie_hellman(&XPublic::from(rx));
        if !shared.was_contributory() {
            bail!("recipient key is low order");
        }
        let mut wk = wrap_key(&epk, &rx, shared.as_bytes());
        let k = ChaCha20Poly1305::new((&wk).into())
            .encrypt(&[0u8; 12].into(), Payload { msg: &ck, aad: r })
            .map_err(|_| anyhow!("wrap failed"))?;
        wk.zeroize();
        keys.push(Wrapped { to: *r, k });
    }
    ck.zeroize();
    Ok(Sealed { ciphertext, epk, keys })
}

/// Opens the body with `me`'s key if one of the wraps is for it. `Ok(None)`: not addressed to this key.
pub fn open(ciphertext: &[u8], ad: &[u8], epk: &[u8; 32], keys: &[Wrapped], me: &Seed) -> Result<Option<Vec<u8>>> {
    let my_pub = me.public();
    let Some(w) = keys.iter().find(|w| w.to == my_pub) else { return Ok(None) };
    if ciphertext.len() < 24 + 16 {
        bail!("ciphertext too short");
    }
    let sk = me.x25519_secret();
    let shared = sk.diffie_hellman(&XPublic::from(*epk));
    if !shared.was_contributory() {
        bail!("ephemeral key is low order");
    }
    let rx = XPublic::from(&sk).to_bytes();
    let mut wk = wrap_key(epk, &rx, shared.as_bytes());
    let ck = ChaCha20Poly1305::new((&wk).into())
        .decrypt(&[0u8; 12].into(), Payload { msg: &w.k, aad: &my_pub })
        .map_err(|_| anyhow!("key unwrap failed"));
    wk.zeroize();
    let mut ck: [u8; 32] = ck?.try_into().map_err(|_| anyhow!("bad content key"))?;
    let (nonce, body) = ciphertext.split_at(24);
    let plain = XChaCha20Poly1305::new((&ck).into())
        .decrypt(nonce.into(), Payload { msg: body, aad: ad })
        .map_err(|_| anyhow!("body decrypt failed"));
    ck.zeroize();
    Ok(Some(plain?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_wrapped_recipients_open() {
        let a = Seed::generate();
        let b = Seed::generate();
        let c = Seed::generate();
        let s = seal(b"hello", b"hdr", &[a.public(), b.public()]).unwrap();
        assert_eq!(s.keys.len(), 2);
        assert_eq!(open(&s.ciphertext, b"hdr", &s.epk, &s.keys, &a).unwrap().unwrap(), b"hello");
        assert_eq!(open(&s.ciphertext, b"hdr", &s.epk, &s.keys, &b).unwrap().unwrap(), b"hello");
        assert!(open(&s.ciphertext, b"hdr", &s.epk, &s.keys, &c).unwrap().is_none());
        // Changed header (AD) fails.
        assert!(open(&s.ciphertext, b"other", &s.epk, &s.keys, &a).is_err());
        // A wrap re-labelled for c (c's key, a's wrapped bytes) does not open for c.
        let mut keys = s.keys.clone();
        keys[0].to = c.public();
        assert!(open(&s.ciphertext, b"hdr", &s.epk, &keys, &c).is_err());
    }
}
