//! The replicated unit. Header fields are clear (member nodes route and order on them); the body is encrypted.
//! A node signs every envelope it writes; the envelope carries the sender's attestation (an aid1 token, or for history
//! imported from the old server, the bridge's statement).

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, Wrapped};
use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::members::MemberList;
use crate::token::{self, TokenPolicy};
use crate::{b64u, b64u_decode, parse_ts};

pub const VERSION: u32 = 1;
pub const MAX_FIELD: usize = 120;
pub const MAX_PARENTS: usize = 16;
pub const MAX_CIPHERTEXT: usize = 512 * 1024;
pub const MAX_KEYS: usize = 1000;
/// Attachments per message (the compat API's limit).
pub const MAX_BLOBS: usize = 10;
/// Largest old-server message number an import may claim. Old ids are small SQLite row ids; an unbounded one would let
/// a single import push every node's local numbering to the top of the integer range (no new mail could be stored).
pub const MAX_OLD_ID: u64 = 1 << 32;
/// Token lifetime check against the envelope's ts allows this much clock skew.
pub const TOKEN_SKEW_S: f64 = 300.0;
/// An envelope dated further than this past the receiver's clock is refused (it will be fetched again later).
pub const FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;
const SIG_CONTEXT: &[u8] = b"agent-mail/envelope/v1\n";
const AD_CONTEXT: &str = "agent-mail/body/v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Content key wrapped to every member agent key and every member node key.
    #[default]
    Members,
    /// Wrapped only to the named recipients' agent keys and the sender's.
    Private,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Members => "members",
            Mode::Private => "private",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Attest {
    /// The sender's aid1 token, minted by the home for audience "mail" ("token-attested"; to be refused later).
    Aid1 { token: String },
    /// Signed by the sender's own Ed25519 key (the member list's key for `from`) over `post_statement`:
    /// the header fields and `digest` = hex SHA-256(salt || text || 0x00 || comma-joined blob ids). The salt is in
    /// the encrypted body, so the digest cannot be used to guess short texts.
    Agent { key: String, digest: String, sig: String },
    /// A message copied from the old server (phase 2 bridge). `old_id` is its number there; the envelope is signed by
    /// a bridge key the member list names under `bridges`.
    Import { old_id: u64, sub: String, verified: bool },
}

impl Attest {
    pub fn kind(&self) -> &'static str {
        match self {
            Attest::Aid1 { .. } => "token",
            Attest::Agent { .. } => "agent",
            Attest::Import { .. } => "import",
        }
    }
}

/// What the sender's key signs. Plain text so clients without a JSON canonicalizer (islandmail.py) build it exactly.
pub fn post_statement(from: &str, to: &str, thread: &str, mode: Mode, ts: &str, digest: &str) -> String {
    format!("agent-mail-post|v1|{from}|{to}|{thread}|{}|{ts}|{digest}", mode.as_str())
}

/// hex SHA-256(salt || text || 0x00 || blob ids joined by ",")
pub fn post_digest(salt: &[u8], text: &str, blob_ids: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt);
    h.update(text.as_bytes());
    h.update([0u8]);
    h.update(blob_ids.join(",").as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WrappedKey {
    pub to: String,
    pub k: String,
}

/// The content key of one envelope wrapped for a node that joined later (see `Envelope::grant`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    pub epk: String,
    pub k: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub v: u32,
    /// hex BLAKE3 of the decoded ciphertext bytes.
    pub id: String,
    pub thread: String,
    /// Thread heads (envelope ids) the writing node had when it wrote this one.
    pub parents: Vec<String>,
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ`
    pub ts: String,
    pub from: String,
    pub to: String,
    pub mode: Mode,
    pub ciphertext: String,
    /// Ephemeral X25519 public key for the key wraps.
    pub epk: String,
    pub keys: Vec<WrappedKey>,
    /// Encrypted attachment blobs (hex BLAKE3 of each blob's ciphertext), in body.files order. In the clear so nodes
    /// that cannot read the body still replicate the blobs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<String>,
    pub attest: Attest,
    /// The writing node's key (or the bridge's, for imports).
    pub node: String,
    pub sig: String,
}

/// The encrypted part.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Body {
    pub text: String,
    /// Attachments: {id (blob id), name, type, size, key (b64url blob key)}; imported rows keep the old server's
    /// file metadata ({id, name, type, size, old: true}).
    #[serde(default)]
    pub files: Vec<serde_json::Value>,
    /// b64url salt of the sender's digest (Attest::Agent only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub salt: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    pub sender_sub: String,
    pub sender_kind: String,
    /// Some(old id) for history imported from the old server.
    pub imported: Option<u64>,
    /// False only for imported rows the old server marked unverified.
    pub verified: bool,
    /// "agent" (sender's key), "token" (aid1 token only) or "import".
    pub attest: &'static str,
}

pub struct Draft<'a> {
    pub thread: &'a str,
    pub parents: Vec<String>,
    pub ts: String,
    pub from: &'a str,
    pub to: &'a str,
    pub mode: Mode,
    pub body: &'a Body,
    pub blobs: Vec<String>,
    pub attest: Attest,
    pub recipients: &'a [PublicKey],
}

fn header_ad(v: u32, thread: &str, from: &str, to: &str, mode: Mode, ts: &str) -> Vec<u8> {
    let h = serde_json::json!([AD_CONTEXT, v, thread, from, to, mode.as_str(), ts]);
    serde_json::to_vec(&h).expect("json")
}

impl Envelope {
    pub fn seal(d: Draft<'_>, node: &Seed) -> Result<Envelope> {
        Self::seal_with(d, node, None)
    }

    /// `det`: derive the content key, nonce and ephemeral key from this secret instead of randomness, so sealing the
    /// same input twice gives the same envelope id (bridge imports: re-importing an old message is a no-op).
    pub fn seal_with(d: Draft<'_>, node: &Seed, det: Option<[u8; 32]>) -> Result<Envelope> {
        let plain = serde_json::to_vec(d.body)?;
        let ad = header_ad(VERSION, d.thread, d.from, d.to, d.mode, &d.ts);
        let sealed = crypto::seal_det(&plain, &ad, d.recipients, det)?;
        let mut env = Envelope {
            v: VERSION,
            id: blake3::hash(&sealed.ciphertext).to_hex().to_string(),
            thread: d.thread.to_string(),
            parents: d.parents,
            ts: d.ts,
            from: d.from.to_string(),
            to: d.to.to_string(),
            mode: d.mode,
            ciphertext: b64u(&sealed.ciphertext),
            epk: b64u(&sealed.epk),
            keys: sealed.keys.iter().map(|w| WrappedKey { to: fmt_key(&w.to), k: b64u(&w.k) }).collect(),
            blobs: d.blobs,
            attest: d.attest,
            node: fmt_key(&node.public()),
            sig: String::new(),
        };
        env.sig = b64u(&node.sign(&env.signing_bytes()));
        Ok(env)
    }

    /// The node signs the JSON of the envelope with `sig` empty. Field order is fixed by the struct and every value is
    /// a string, number or list, so re-serializing a parsed envelope gives the same bytes on every node.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = self.clone();
        e.sig.clear();
        let mut out = SIG_CONTEXT.to_vec();
        out.extend(serde_json::to_vec(&e).expect("json"));
        out
    }

    pub fn day(&self) -> &str {
        &self.ts[..10.min(self.ts.len())]
    }

    pub fn ts_ms(&self) -> i64 {
        parse_ts(&self.ts).unwrap_or(0)
    }

    pub fn wraps(&self) -> Result<Vec<Wrapped>> {
        self.keys
            .iter()
            .map(|w| {
                Ok(Wrapped { to: parse_key(&w.to)?, k: b64u_decode(&w.k).ok_or_else(|| anyhow!("bad wrapped key"))? })
            })
            .collect()
    }

    /// The body, if `me` is one of the keys it was wrapped to.
    pub fn open(&self, me: &Seed) -> Result<Option<Body>> {
        let ct = b64u_decode(&self.ciphertext).ok_or_else(|| anyhow!("bad ciphertext"))?;
        let epk: [u8; 32] =
            b64u_decode(&self.epk).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad epk"))?;
        let ad = header_ad(self.v, &self.thread, &self.from, &self.to, self.mode, &self.ts);
        match crypto::open(&ct, &ad, &epk, &self.wraps()?, me)? {
            None => Ok(None),
            Some(plain) => Ok(Some(serde_json::from_slice(&plain)?)),
        }
    }

    fn parts(&self) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
        let ct = b64u_decode(&self.ciphertext).ok_or_else(|| anyhow!("bad ciphertext"))?;
        let epk: [u8; 32] =
            b64u_decode(&self.epk).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad epk"))?;
        Ok((ct, epk, header_ad(self.v, &self.thread, &self.from, &self.to, self.mode, &self.ts)))
    }

    /// A grant: the content key re-wrapped by `me` (who can open the envelope) for `to`, a node that joined after it
    /// was written. `None` if `me` cannot open it. Grants travel outside the envelope; a wrong one just fails to open.
    pub fn grant(&self, me: &Seed, to: &PublicKey) -> Result<Option<Grant>> {
        let (_, epk, _) = self.parts()?;
        let Some(mut ck) = crypto::content_key(&epk, &self.wraps()?, me)? else { return Ok(None) };
        let r = crypto::wrap_for(&ck, to);
        ck.zeroize();
        let (gepk, k) = r?;
        Ok(Some(Grant { epk: b64u(&gepk), k: b64u(&k) }))
    }

    /// Opens the body with a grant made for `me`. The body AEAD (header as AD, ciphertext hashed into the id the node
    /// signed) authenticates the result whoever made the grant.
    pub fn open_grant(&self, g: &Grant, me: &Seed) -> Result<Body> {
        let (ct, _, ad) = self.parts()?;
        let gepk: [u8; 32] = b64u_decode(&g.epk).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad grant epk"))?;
        let k = b64u_decode(&g.k).ok_or_else(|| anyhow!("bad grant key"))?;
        let mut ck = crypto::unwrap(&gepk, &k, me)?;
        let plain = crypto::decrypt(&ct, &ad, &ck);
        ck.zeroize();
        Ok(serde_json::from_slice(&plain?)?)
    }

    /// Everything a receiver checks before storing: shape, id, the node's signature and membership, and the sender's
    /// attestation (token signed by the home, scope, name == from, live at ts).
    pub fn verify(&self, members: &MemberList, policy: &TokenPolicy, now_ms: i64) -> Result<Verified> {
        if self.v != VERSION {
            bail!("unsupported envelope version {}", self.v);
        }
        for (name, f) in [("thread", &self.thread), ("from", &self.from), ("to", &self.to)] {
            if f.is_empty() || f.chars().count() > MAX_FIELD || f.chars().any(|c| c.is_control()) {
                bail!("bad {name}");
            }
        }
        if self.parents.len() > MAX_PARENTS || !self.parents.iter().all(|p| is_id(p)) {
            bail!("bad parents");
        }
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            bail!("bad key list");
        }
        // Every wrap is a recipient key and a 32-byte content key + 16-byte tag; the ephemeral key is 32 bytes.
        if !self.wraps()?.iter().all(|w| w.k.len() == 48) {
            bail!("bad wrapped key");
        }
        if b64u_decode(&self.epk).is_none_or(|b| b.len() != 32) {
            bail!("bad epk");
        }
        // Blob ids drive fetches from peers on every sync: at most the API's attachment count, each a content hash.
        if self.blobs.len() > MAX_BLOBS || !self.blobs.iter().all(|b| is_id(b)) {
            bail!("bad blobs");
        }
        let ts = parse_ts(&self.ts).ok_or_else(|| anyhow!("bad ts"))?;
        if ts > now_ms + FUTURE_SKEW_MS {
            bail!("ts is in the future");
        }
        if self.ciphertext.len() > MAX_CIPHERTEXT * 4 / 3 + 4 {
            bail!("ciphertext too large");
        }
        let ct = b64u_decode(&self.ciphertext).ok_or_else(|| anyhow!("bad ciphertext"))?;
        if blake3::hash(&ct).to_hex().as_str() != self.id {
            bail!("id is not the hash of the ciphertext");
        }
        let node = parse_key(&self.node)?;
        let sig = b64u_decode(&self.sig).ok_or_else(|| anyhow!("bad sig"))?;
        if !keys::verify(&node, &self.signing_bytes(), &sig) {
            bail!("node signature does not verify");
        }
        match &self.attest {
            Attest::Aid1 { token } => {
                if !members.is_node(&node) {
                    bail!("written by a node that is not a member");
                }
                let p = token::verify_at(token, policy, ts as f64 / 1000.0, TOKEN_SKEW_S)
                    .map_err(|e| anyhow!("sender token refused: {e}"))?;
                if p.jti.is_some() {
                    bail!("sender token is a one-time sign-in token");
                }
                if p.name != self.from {
                    bail!("from ({}) is not the token's name ({})", self.from, p.name);
                }
                Ok(Verified { sender_sub: p.sub, sender_kind: p.kind, imported: None, verified: true, attest: "token" })
            }
            Attest::Agent { key, digest, sig } => {
                if !members.is_node(&node) {
                    bail!("written by a node that is not a member");
                }
                let m = members.member_by_name(&self.from).ok_or_else(|| anyhow!("{} is not on the member list", self.from))?;
                let k = parse_key(key)?;
                if parse_key(&m.key)? != k {
                    bail!("signed by a key that is not {}'s key on the member list", self.from);
                }
                if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!("bad digest");
                }
                let st = post_statement(&self.from, &self.to, &self.thread, self.mode, &self.ts, digest);
                let s = b64u_decode(sig).ok_or_else(|| anyhow!("bad sender signature"))?;
                if !keys::verify(&k, st.as_bytes(), &s) {
                    bail!("sender signature does not verify");
                }
                Ok(Verified { sender_sub: m.sub.clone(), sender_kind: "agent".into(), imported: None, verified: true, attest: "agent" })
            }
            Attest::Import { old_id, sub, verified } => {
                if !members.is_bridge(&node) {
                    bail!("import signed by a key that is not a member bridge");
                }
                if *old_id == 0 || *old_id > MAX_OLD_ID {
                    bail!("import old_id out of range");
                }
                // Shown in the header line readers trust: same rules as the other header fields (may be empty for
                // legacy rows).
                if sub.chars().count() > MAX_FIELD || sub.chars().any(|c| c.is_control()) {
                    bail!("bad import sub");
                }
                Ok(Verified {
                    sender_sub: sub.clone(),
                    sender_kind: String::new(),
                    imported: Some(*old_id),
                    verified: *verified,
                    attest: "import",
                })
            }
        }
    }

    /// For readers, after decrypting: an agent-signed envelope's digest must match the body it carries, and the
    /// body's attachments must be the header's blobs.
    pub fn check_body(&self, body: &Body) -> Result<()> {
        let ids: Vec<String> = body.files.iter().filter_map(|f| f["id"].as_str().map(|s| s.to_string())).collect();
        let blob_ids: Vec<String> =
            body.files.iter().filter(|f| f.get("key").is_some()).filter_map(|f| f["id"].as_str().map(|s| s.to_string())).collect();
        if blob_ids != self.blobs {
            bail!("body attachments do not match the header's blobs");
        }
        if let Attest::Agent { digest, .. } = &self.attest {
            let salt = b64u_decode(&body.salt).ok_or_else(|| anyhow!("bad salt"))?;
            if &post_digest(&salt, &body.text, &ids) != digest {
                bail!("body does not match the sender's signed digest");
            }
        }
        Ok(())
    }
}

pub fn is_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::members::tests::list;
    use crate::token::tests::{payload, policy};

    struct World {
        home: Seed,
        node: Seed,
        alice: Seed,
        bob: Seed,
        carol: Seed,
        members: MemberList,
    }

    fn world() -> World {
        let home = Seed::generate();
        let node = Seed::generate();
        let (alice, bob, carol) = (Seed::generate(), Seed::generate(), Seed::generate());
        let members = list(&[("a.alice", &alice), ("a.bob", &bob), ("b.carol", &carol)], &[&node]);
        World { home, node, alice, bob, carol, members }
    }

    fn env(w: &World, from: &str, to: &str, mode: Mode, token: String) -> Envelope {
        let body = Body { text: format!("hi from {from}"), ..Default::default() };
        let recipients = match mode {
            Mode::Members => w.members.all_keys(),
            Mode::Private => w.members.private_keys(to, from),
        };
        Envelope::seal(
            Draft {
                thread: "t",
                parents: vec![],
                ts: crate::now_ts(),
                from,
                to,
                mode,
                body: &body,
                blobs: vec![],
                attest: Attest::Aid1 { token },
                recipients: &recipients,
            },
            &w.node,
        )
        .unwrap()
    }

    /// An envelope signed by `signer` as `from` (the agent-key path), with the given body text.
    fn signed_env(w: &World, from: &str, signer: &Seed, text: &str, ts: String) -> Envelope {
        let salt = crate::random_bytes::<16>();
        let digest = post_digest(&salt, text, &[]);
        let st = post_statement(from, "all", "t", Mode::Members, &ts, &digest);
        let attest = Attest::Agent { key: fmt_key(&signer.public()), digest, sig: b64u(&signer.sign(st.as_bytes())) };
        let body = Body { text: text.into(), files: vec![], salt: b64u(&salt) };
        Envelope::seal(
            Draft {
                thread: "t",
                parents: vec![],
                ts,
                from,
                to: "all",
                mode: Mode::Members,
                body: &body,
                blobs: vec![],
                attest,
                recipients: &w.members.all_keys(),
            },
            &w.node,
        )
        .unwrap()
    }

    #[test]
    fn agent_signed_envelopes() {
        let w = world();
        let p = policy(&w.home);
        let now = crate::now_millis();
        let e = signed_env(&w, "a.alice", &w.alice, "signed by alice", crate::now_ts());
        let v = e.verify(&w.members, &p, now).unwrap();
        assert_eq!((v.attest, v.sender_sub.as_str()), ("agent", "agent:a.alice@test"));
        let body = e.open(&w.node).unwrap().unwrap();
        e.check_body(&body).unwrap();
        // Bob's key claiming to be alice.
        let e = signed_env(&w, "a.alice", &w.bob, "forged", crate::now_ts());
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("not a.alice's key"));
        // Not on the member list at all.
        let stranger = Seed::generate();
        let e = signed_env(&w, "x.stranger", &stranger, "who", crate::now_ts());
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("not on the member list"));
        // A header changed by the node after the sender signed (re-signed by the node so only the agent sig breaks).
        let mut e = signed_env(&w, "a.alice", &w.alice, "to all", crate::now_ts());
        e.to = "a.bob".into();
        e.sig = b64u(&w.node.sign(&e.signing_bytes()));
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("sender signature"));
        // A body swapped by the node under alice's signed digest: verify passes (header intact), check_body refuses.
        let good = signed_env(&w, "a.alice", &w.alice, "original", crate::now_ts());
        let mut body = good.open(&w.node).unwrap().unwrap();
        body.text = "tampered".into();
        assert!(good.check_body(&body).unwrap_err().to_string().contains("digest"));
    }

    #[test]
    fn deterministic_seal_gives_same_id() {
        let w = world();
        let body = Body { text: "old mail".into(), ..Default::default() };
        let mk = || {
            Envelope::seal_with(
                Draft {
                    thread: "t",
                    parents: vec![],
                    ts: "2026-01-01T00:00:00.000Z".into(),
                    from: "a.alice",
                    to: "all",
                    mode: Mode::Members,
                    body: &body,
                    blobs: vec![],
                    attest: Attest::Import { old_id: 7, sub: "agent:a.alice@test".into(), verified: true },
                    recipients: &w.members.all_keys(),
                },
                &w.node,
                Some([9u8; 32]),
            )
            .unwrap()
        };
        let (a, b) = (mk(), mk());
        assert_eq!(a.id, b.id);
        assert_eq!(a.open(&w.alice).unwrap().unwrap().text, "old mail");
        // A node that joined later reads it through a grant from one that can.
        let late = Seed::generate();
        assert!(a.open(&late).unwrap().is_none());
        let g = a.grant(&w.alice, &late.public()).unwrap().unwrap();
        assert_eq!(a.open_grant(&g, &late).unwrap().text, "old mail");
        assert!(a.open_grant(&g, &w.alice).is_err());
        assert!(a.grant(&late, &w.alice.public()).unwrap().is_none());
    }

    #[test]
    fn refuses_unbounded_fields() {
        let w = world();
        let p = policy(&w.home);
        let now = crate::now_millis();
        let resign = |mut e: Envelope| {
            e.sig = b64u(&w.node.sign(&e.signing_bytes()));
            e
        };
        let base = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.alice"));
        assert!(base.verify(&w.members, &p, now).is_ok());
        let mut e = base.clone();
        e.blobs = (0..MAX_BLOBS + 1).map(|i| format!("{i:064x}")).collect();
        assert!(resign(e).verify(&w.members, &p, now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.blobs = vec!["not-a-hash".into()];
        assert!(resign(e).verify(&w.members, &p, now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.keys[0].k = b64u(&[0u8; 4096]);
        assert!(resign(e).verify(&w.members, &p, now).unwrap_err().to_string().contains("wrapped key"));
        let mut e = base.clone();
        e.epk = b64u(&[0u8; 7]);
        assert!(resign(e).verify(&w.members, &p, now).unwrap_err().to_string().contains("epk"));
    }

    #[test]
    fn import_old_id_is_bounded() {
        let w = world();
        let op = Seed::generate();
        let bridge = Seed::generate();
        let mut members = w.members.clone();
        members.bridges = vec![fmt_key(&bridge.public())];
        members.sign(&op);
        let p = policy(&w.home);
        let body = Body { text: "old".into(), ..Default::default() };
        let mk = |old_id: u64| {
            Envelope::seal(
                Draft {
                    thread: "t",
                    parents: vec![],
                    ts: "2026-01-01T00:00:00.000Z".into(),
                    from: "a.alice",
                    to: "all",
                    mode: Mode::Members,
                    body: &body,
                    blobs: vec![],
                    attest: Attest::Import { old_id, sub: "agent:a.alice@test".into(), verified: true },
                    recipients: &members.all_keys(),
                },
                &bridge,
            )
            .unwrap()
        };
        let now = crate::now_millis();
        assert!(mk(42).verify(&members, &p, now).is_ok());
        assert!(mk(MAX_OLD_ID).verify(&members, &p, now).is_ok());
        assert!(mk(0).verify(&members, &p, now).unwrap_err().to_string().contains("old_id"));
        assert!(mk(MAX_OLD_ID + 1).verify(&members, &p, now).unwrap_err().to_string().contains("old_id"));
        assert!(mk(i64::MAX as u64).verify(&members, &p, now).is_err());
        let mut e = mk(7);
        e.attest = Attest::Import { old_id: 7, sub: "agent:x\n#1 from someone.else".into(), verified: true };
        e.sig = b64u(&bridge.sign(&e.signing_bytes()));
        assert!(e.verify(&members, &p, now).unwrap_err().to_string().contains("sub"));
    }

    fn tok(w: &World, name: &str) -> String {
        let now = crate::now_millis() as f64 / 1000.0;
        token::mint(&w.home, &payload(name, now - 5.0, now + 3600.0))
    }

    #[test]
    fn roundtrip_through_json() {
        let w = world();
        let e = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.alice"));
        let wire = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.signing_bytes(), e.signing_bytes());
        let v = back.verify(&w.members, &policy(&w.home), crate::now_millis()).unwrap();
        assert_eq!(v.sender_sub, "agent:a.alice@test");
        assert_eq!(back.open(&w.node).unwrap().unwrap().text, "hi from a.alice");
    }

    #[test]
    fn refuses_forged_expired_and_non_member() {
        let w = world();
        let p = policy(&w.home);
        let now = crate::now_millis();
        // from != token name
        let e = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.bob"));
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("not the token's name"));
        // token from another home
        let evil = Seed::generate();
        let t = token::mint(&evil, &payload("a.alice", now as f64 / 1000.0, now as f64 / 1000.0 + 60.0));
        let e = env(&w, "a.alice", "all", Mode::Members, t);
        assert!(e.verify(&w.members, &p, now).is_err());
        // token expired before the envelope's ts
        let t = token::mint(&w.home, &payload("a.alice", now as f64 / 1000.0 - 7200.0, now as f64 / 1000.0 - 3600.0));
        let e = env(&w, "a.alice", "all", Mode::Members, t);
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("expired"));
        // written by a node not on the member list
        let mut e = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.alice"));
        let stranger = Seed::generate();
        e.node = fmt_key(&stranger.public());
        e.sig = b64u(&stranger.sign(&e.signing_bytes()));
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("not a member"));
        // header changed after signing
        let mut e = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.alice"));
        e.thread = "other".into();
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("signature"));
        // ciphertext swapped: id no longer matches
        let mut e = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.alice"));
        let other = env(&w, "a.alice", "all", Mode::Members, tok(&w, "a.alice"));
        e.ciphertext = other.ciphertext;
        assert!(e.verify(&w.members, &p, now).unwrap_err().to_string().contains("hash"));
    }

    #[test]
    fn members_vs_private_reading() {
        let w = world();
        let m = env(&w, "a.alice", "a.bob", Mode::Members, tok(&w, "a.alice"));
        for k in [&w.alice, &w.bob, &w.carol, &w.node] {
            assert!(m.open(k).unwrap().is_some(), "members mode opens for every member and node");
        }
        let outsider = Seed::generate();
        assert!(m.open(&outsider).unwrap().is_none());

        let p = env(&w, "a.alice", "a.bob", Mode::Private, tok(&w, "a.alice"));
        assert!(p.open(&w.alice).unwrap().is_some(), "sender reads its own private mail");
        assert!(p.open(&w.bob).unwrap().is_some(), "recipient reads it");
        assert!(p.open(&w.carol).unwrap().is_none(), "another member does not");
        assert!(p.open(&w.node).unwrap().is_none(), "nor does the node");
        // A team prefix in private mode reaches the team only.
        let t = env(&w, "b.carol", "a.", Mode::Private, tok(&w, "b.carol"));
        assert!(t.open(&w.alice).unwrap().is_some());
        assert!(t.open(&w.bob).unwrap().is_some());
        assert!(t.open(&w.carol).unwrap().is_some());
        assert!(t.open(&w.node).unwrap().is_none());
    }
}
