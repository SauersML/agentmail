//! Body encryption. A fresh 32-byte content key encrypts the body (XChaCha20-Poly1305, random 24-byte nonce, the
//! envelope header as associated data). The content key is wrapped once per recipient key: one ephemeral X25519 key per
//! envelope, a per-recipient wrap key = BLAKE3-derive_key("agent-mail v1 key wrap", epk || recipient_x || shared),
//! and ChaCha20-Poly1305 with a zero nonce (each wrap key is used once) and the recipient's Ed25519 key as AD.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

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
    let ck = Zeroizing::new(crate::random_bytes::<32>());
    let nonce = crate::random_bytes::<24>();
    let body = XChaCha20Poly1305::new((&*ck).into())
        .encrypt((&nonce).into(), Payload { msg: plain, aad: ad })
        .map_err(|_| anyhow!("encrypt failed"))?;
    let mut ciphertext = nonce.to_vec();
    ciphertext.extend_from_slice(&body);

    let esk = StaticSecret::from(crate::random_bytes::<32>());
    let epk = XPublic::from(&esk).to_bytes();
    let mut keys = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut exchanges = std::collections::BTreeSet::new();
    for r in recipients {
        if !seen.insert(*r) {
            continue;
        }
        let rx = x25519_public(r)?;
        anyhow::ensure!(exchanges.insert(rx), "distinct signing keys share one X25519 public key");
        let shared = esk.diffie_hellman(&XPublic::from(rx));
        if !shared.was_contributory() {
            bail!("recipient key is low order");
        }
        let wk = Zeroizing::new(wrap_key(&epk, &rx, shared.as_bytes()));
        let k = ChaCha20Poly1305::new((&*wk).into())
            .encrypt(&[0u8; 12].into(), Payload { msg: ck.as_slice(), aad: r })
            .map_err(|_| anyhow!("wrap failed"))?;
        keys.push(Wrapped { to: *r, k });
    }
    Ok(Sealed { ciphertext, epk, keys })
}

/// Opens the body with `me`'s key if one of the wraps is for it. `Ok(None)`: not addressed to this key.
pub fn open(ciphertext: &[u8], ad: &[u8], epk: &[u8; 32], keys: &[Wrapped], me: &Seed) -> Result<Option<Vec<u8>>> {
    let Some(mut ck) = content_key(epk, keys, me)? else { return Ok(None) };
    let plain = decrypt(ciphertext, ad, &ck);
    ck.zeroize();
    Ok(Some(plain?))
}

/// The content key, if one of the wraps is for `me`.
pub fn content_key(epk: &[u8; 32], keys: &[Wrapped], me: &Seed) -> Result<Option<[u8; 32]>> {
    let my_pub = me.public();
    let Some(w) = keys.iter().find(|w| w.to == my_pub) else { return Ok(None) };
    unwrap(epk, &w.k, me).map(Some)
}

/// Unwraps one wrap made for `me` under ephemeral key `epk`.
fn unwrap(epk: &[u8; 32], k: &[u8], me: &Seed) -> Result<[u8; 32]> {
    let my_pub = me.public();
    let sk = me.x25519_secret();
    let shared = sk.diffie_hellman(&XPublic::from(*epk));
    if !shared.was_contributory() {
        bail!("ephemeral key is low order");
    }
    let rx = XPublic::from(&sk).to_bytes();
    let wk = Zeroizing::new(wrap_key(epk, &rx, shared.as_bytes()));
    let ck = ChaCha20Poly1305::new((&*wk).into())
        .decrypt(&[0u8; 12].into(), Payload { msg: k, aad: &my_pub })
        .map_err(|_| anyhow!("key unwrap failed"));
    let plain = Zeroizing::new(ck?);
    plain.as_slice().try_into().map_err(|_| anyhow!("bad content key"))
}

/// Decrypt a body with a content key obtained elsewhere (a key grant).
pub fn decrypt_with(ciphertext: &[u8], ad: &[u8], ck: &[u8; 32]) -> Result<Vec<u8>> {
    decrypt(ciphertext, ad, ck)
}

fn decrypt(ciphertext: &[u8], ad: &[u8], ck: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 + 16 {
        bail!("ciphertext too short");
    }
    let (nonce, body) = ciphertext.split_at(24);
    XChaCha20Poly1305::new(ck.into())
        .decrypt(nonce.into(), Payload { msg: body, aad: ad })
        .map_err(|_| anyhow!("body decrypt failed"))
}

const BLOB_AD: &[u8] = b"agent-mail/blob/v1";

/// An attachment: its own random key (carried inside the envelope body, so it is wrapped like the body), nonce (24)
/// || XChaCha20-Poly1305 ciphertext. The blob id is hex BLAKE3 of the result.
pub fn seal_blob(plain: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let key: [u8; 32] = crate::random_bytes();
    let nonce: [u8; 24] = crate::random_bytes();
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt((&nonce).into(), Payload { msg: plain, aad: BLOB_AD })
        .map_err(|_| anyhow!("encrypt failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok((out, key))
}

pub fn open_blob(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if blob.len() < 24 + 16 {
        bail!("blob too short");
    }
    let (nonce, ct) = blob.split_at(24);
    XChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), Payload { msg: ct, aad: BLOB_AD })
        .map_err(|_| anyhow!("blob decrypt failed"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn blob_roundtrip() {
        let (b, k) = super::seal_blob(b"file bytes").unwrap();
        assert_eq!(super::open_blob(&b, &k).unwrap(), b"file bytes");
        let mut bad = b.clone();
        bad[30] ^= 1;
        assert!(super::open_blob(&bad, &k).is_err());
    }

    use super::*;

    #[test]
    fn only_wrapped_recipients_open() {
        let a = Seed::generate();
        let b = Seed::generate();
        let c = Seed::generate();
        let mut opposite = a.public();
        opposite[31] ^= 0x80;
        assert!(seal(b"hello", b"hdr", &[a.public(), opposite]).is_err());
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
