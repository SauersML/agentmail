//! Body encryption. A fresh 32-byte content key encrypts the padded body (XChaCha20-Poly1305, random 24-byte nonce,
//! the envelope's public fields as associated data). The content key is wrapped once per recipient X25519 key: one
//! ephemeral X25519 key per envelope, a per-recipient wrap key = BLAKE3-derive_key("islandmail v1 key wrap",
//! epk || recipient_x || shared), ChaCha20-Poly1305 with a zero nonce (each wrap key is used once) and the recipient's
//! X25519 key as AD. Each wrap is labelled only by a tag derived the same way ("islandmail v1 wrap tag"), so the
//! recipient finds its slot and no one else learns whose it is; the slot count is padded to a power of two with
//! random slots.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{x25519_public, PublicKey, Seed};

const WRAP_CONTEXT: &str = "islandmail v1 key wrap";
const TAG_CONTEXT: &str = "islandmail v1 wrap tag";
pub const TAG_LEN: usize = 16;
/// A wrapped content key: 32 bytes + 16-byte tag.
pub const WRAP_LEN: usize = 48;
/// Fewest wrap slots an envelope carries (one recipient looks like two).
pub const MIN_SLOTS: usize = 2;

#[derive(Clone, Debug, PartialEq)]
pub struct Wrapped {
    /// Opaque label: only the holder of the recipient key can recompute it.
    pub tag: [u8; TAG_LEN],
    /// The content key under that recipient's wrap key (or random bytes in a padding slot).
    pub k: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Sealed {
    /// nonce (24) || ciphertext || tag (16)
    pub ciphertext: Vec<u8>,
    pub epk: [u8; 32],
    pub keys: Vec<Wrapped>,
}

/// (wrap key, tag) for one recipient X25519 key and the shared secret with the ephemeral key.
fn derive(epk: &[u8; 32], recipient_x: &[u8; 32], shared: &[u8; 32]) -> ([u8; 32], [u8; TAG_LEN]) {
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(epk);
    material[32..64].copy_from_slice(recipient_x);
    material[64..].copy_from_slice(shared);
    let k = blake3::derive_key(WRAP_CONTEXT, &material);
    let t = blake3::derive_key(TAG_CONTEXT, &material);
    material.zeroize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&t[..TAG_LEN]);
    (k, tag)
}

/// The X25519 keys of Ed25519 identity keys, for wrapping to them directly (long-lived keys: no forward secrecy).
pub fn identity_targets(keys: &[PublicKey]) -> Result<Vec<[u8; 32]>> {
    keys.iter().map(x25519_public).collect()
}

/// Slots for `n` recipients: the next power of two, at least MIN_SLOTS.
pub fn slots_for(n: usize) -> usize {
    n.max(MIN_SLOTS).next_power_of_two()
}

/// Encrypts `plain` (already padded by the caller) and wraps its key to each X25519 key in `targets`.
pub fn seal(plain: &[u8], ad: &[u8], targets: &[[u8; 32]]) -> Result<Sealed> {
    if targets.is_empty() {
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
    for rx in targets {
        if !seen.insert(*rx) {
            continue;
        }
        let shared = esk.diffie_hellman(&XPublic::from(*rx));
        if !shared.was_contributory() {
            bail!("recipient key is low order");
        }
        let (wk, tag) = derive(&epk, rx, shared.as_bytes());
        let wk = Zeroizing::new(wk);
        let k = ChaCha20Poly1305::new((&*wk).into())
            .encrypt(&[0u8; 12].into(), Payload { msg: ck.as_slice(), aad: rx })
            .map_err(|_| anyhow!("wrap failed"))?;
        keys.push(Wrapped { tag, k });
    }
    // Padding slots look like real ones (random tag and bytes); the order is by tag, so it says nothing either.
    while keys.len() < slots_for(seen.len()) {
        keys.push(Wrapped { tag: crate::random_bytes(), k: crate::random_bytes::<WRAP_LEN>().to_vec() });
    }
    keys.sort_by_key(|w| w.tag);
    Ok(Sealed { ciphertext, epk, keys })
}

/// Opens the body with `me`'s key if one of the wraps is for it. `Ok(None)`: not addressed to this key.
pub fn open(ciphertext: &[u8], ad: &[u8], epk: &[u8; 32], keys: &[Wrapped], me: &Seed) -> Result<Option<Vec<u8>>> {
    let Some(mut ck) = content_key(epk, keys, me)? else { return Ok(None) };
    let plain = decrypt(ciphertext, ad, &ck);
    ck.zeroize();
    Ok(Some(plain?))
}

/// The content key, if one of the wraps is for `me` (its X25519 key: an identity seed's, or a rotating node key's).
pub fn content_key(epk: &[u8; 32], keys: &[Wrapped], me: &Seed) -> Result<Option<[u8; 32]>> {
    let sk = me.x25519_secret();
    let shared = sk.diffie_hellman(&XPublic::from(*epk));
    if !shared.was_contributory() {
        bail!("ephemeral key is low order");
    }
    let rx = XPublic::from(&sk).to_bytes();
    let (wk, tag) = derive(epk, &rx, shared.as_bytes());
    let wk = Zeroizing::new(wk);
    let Some(w) = keys.iter().find(|w| w.tag == tag) else { return Ok(None) };
    let ck = ChaCha20Poly1305::new((&*wk).into())
        .decrypt(&[0u8; 12].into(), Payload { msg: &w.k, aad: &rx })
        .map_err(|_| anyhow!("key unwrap failed"));
    let plain = Zeroizing::new(ck?);
    plain.as_slice().try_into().map(Some).map_err(|_| anyhow!("bad content key"))
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

/* Padding */

/// Size buckets below the chunked range.
pub const BUCKETS: [usize; 4] = [1 << 10, 4 << 10, 16 << 10, 64 << 10];
/// Envelope bodies over 64 KiB grow in 64 KiB steps; attachments over 64 KiB in 1 MiB steps.
pub const BODY_CHUNK: usize = 64 << 10;
pub const BLOB_CHUNK: usize = 1 << 20;

/// The padded size of `n` bytes of data (plus its 4-byte length prefix).
pub const fn padded_len(n: usize, chunk: usize) -> usize {
    let n = n + 4;
    let mut i = 0;
    while i < BUCKETS.len() {
        if n <= BUCKETS[i] {
            return BUCKETS[i];
        }
        i += 1;
    }
    n.div_ceil(chunk) * chunk
}

/// Whether `len` is a size `pad` can produce.
pub fn is_padded_len(len: usize, chunk: usize) -> bool {
    BUCKETS.contains(&len) || (len > BUCKETS[3] && len.is_multiple_of(chunk))
}

/// u32 length || data || zeros, to a bucket.
pub fn pad(data: &[u8], chunk: usize) -> Result<Vec<u8>> {
    let len = u32::try_from(data.len()).map_err(|_| anyhow!("too large to pad"))?;
    let mut out = Vec::with_capacity(padded_len(data.len(), chunk));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(padded_len(data.len(), chunk), 0);
    Ok(out)
}

pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let n = padded.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize).ok_or_else(|| anyhow!("padding too short"))?;
    let data = padded.get(4..4 + n).ok_or_else(|| anyhow!("bad padding length"))?;
    if padded[4 + n..].iter().any(|&b| b != 0) {
        bail!("bad padding");
    }
    Ok(data)
}

const BLOB_AD: &[u8] = b"islandmail/blob/v1";

/// An attachment: its own random key (carried inside the envelope body, so it is wrapped like the body), nonce (24)
/// || XChaCha20-Poly1305 ciphertext of the padded bytes. The blob id is hex BLAKE3 of the result.
pub fn seal_blob(plain: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let key: [u8; 32] = crate::random_bytes();
    let nonce: [u8; 24] = crate::random_bytes();
    let padded = pad(plain, BLOB_CHUNK)?;
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt((&nonce).into(), Payload { msg: &padded, aad: BLOB_AD })
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
    let padded = XChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), Payload { msg: ct, aad: BLOB_AD })
        .map_err(|_| anyhow!("blob decrypt failed"))?;
    Ok(unpad(&padded)?.to_vec())
}

/// The stored size of an attachment of `n` bytes: padded, plus nonce and tag.
pub const fn blob_len(n: usize) -> usize {
    padded_len(n, BLOB_CHUNK) + 24 + 16
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
    fn only_wrapped_recipients_open_and_slots_say_nothing() {
        let (a, b, c) = (Seed::generate(), Seed::generate(), Seed::generate());
        let targets = identity_targets(&[a.public(), b.public()]).unwrap();
        let s = seal(b"hello", b"hdr", &targets).unwrap();
        assert_eq!(s.keys.len(), 2);
        assert_eq!(open(&s.ciphertext, b"hdr", &s.epk, &s.keys, &a).unwrap().unwrap(), b"hello");
        assert_eq!(open(&s.ciphertext, b"hdr", &s.epk, &s.keys, &b).unwrap().unwrap(), b"hello");
        assert!(open(&s.ciphertext, b"hdr", &s.epk, &s.keys, &c).unwrap().is_none());
        assert!(open(&s.ciphertext, b"other", &s.epk, &s.keys, &a).is_err(), "changed AD fails");
        // One recipient: two slots, the other random. Three: four. Tags differ per envelope for the same key.
        let one = seal(b"x", b"", &targets[..1]).unwrap();
        assert_eq!(one.keys.len(), 2);
        assert_eq!(seal(b"x", b"", &identity_targets(&[a.public(), b.public(), c.public()]).unwrap()).unwrap().keys.len(), 4);
        let again = seal(b"x", b"", &targets[..1]).unwrap();
        assert!(one.keys.iter().all(|w| again.keys.iter().all(|v| v.tag != w.tag)));
        assert!(one.keys.windows(2).all(|w| w[0].tag <= w[1].tag));
    }

    #[test]
    fn padding_buckets() {
        assert_eq!(pad(b"", BODY_CHUNK).unwrap().len(), 1024);
        assert_eq!(pad(&[1; 1020], BODY_CHUNK).unwrap().len(), 1024);
        assert_eq!(pad(&[1; 1021], BODY_CHUNK).unwrap().len(), 4096);
        assert_eq!(pad(&[1; 70_000], BODY_CHUNK).unwrap().len(), 2 * BODY_CHUNK);
        assert_eq!(pad(&[1; 70_000], BLOB_CHUNK).unwrap().len(), BLOB_CHUNK);
        for n in [0, 5, 1020, 1021, 70_000] {
            let p = pad(&vec![7; n], BODY_CHUNK).unwrap();
            assert!(is_padded_len(p.len(), BODY_CHUNK));
            assert_eq!(unpad(&p).unwrap(), vec![7; n].as_slice());
        }
        let mut p = pad(b"abc", BODY_CHUNK).unwrap();
        p[100] = 1;
        assert!(unpad(&p).is_err(), "nonzero padding refused");
        let (blob, k) = seal_blob(b"tiny").unwrap();
        assert_eq!(blob.len(), blob_len(4));
        assert_eq!(blob.len(), 1024 + 40);
        assert_eq!(open_blob(&blob, &k).unwrap(), b"tiny");
    }
}
