//! Replicated mail. The node signs the envelope and the agent signs its addressing and body digest.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Wrapped};
use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::cert::Cert;
use crate::members::{self, Agent, MemberList};
use crate::{b64u, b64u_decode, parse_ts};

pub const VERSION: u32 = 1;
pub const MAX_FIELD: usize = 120;
pub const MAX_PARENTS: usize = 16;
pub const MAX_CIPHERTEXT: usize = 512 * 1024;
pub const MAX_KEYS: usize = 1000;
/// Attachments per message.
pub const MAX_BLOBS: usize = 10;
/// An envelope dated further than this past the receiver's clock is refused (peers fetch it again later).
pub const FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;
const SIG_CONTEXT: &[u8] = b"islandmail/envelope/v1\n";
const AD_CONTEXT: &str = "islandmail/body/v1";

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
/// The sender signs the network, routing fields, attachment IDs and salted body digest.
pub struct Attest {
    pub key: String,
    pub digest: String,
    pub sig: String,
    /// For a certified (not pinned) sender: a certificate for `key` from a trusted node, so a receiver can check
    /// the sender before that certificate replicates to it. Covered by the writing node's signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<Cert>,
}

pub struct PostStatement<'a> {
    pub from: &'a str,
    /// The sender's durable id: the pinned sub, or `agent:NAME` for a certified agent.
    pub sub: &'a str,
    pub to: &'a str,
    pub thread: &'a str,
    pub mode: Mode,
    pub ts: &'a str,
    pub digest: &'a str,
    pub blobs: &'a [String],
    pub recipients: &'a [PublicKey],
}

impl PostStatement<'_> {
    pub fn signing_bytes(&self, members: &MemberList) -> Vec<u8> {
        let sub = self.sub;
        let topic = members.topic();
        let mut recipients = self.recipients.to_vec();
        recipients.sort_unstable();
        let audience = crate::paseto::pae(&recipients.iter().map(|k| k.as_slice()).collect::<Vec<_>>());
        let mut fields: Vec<&[u8]> = vec![b"islandmail/post/v1", &topic, self.from.as_bytes(), sub.as_bytes(),
            self.to.as_bytes(), self.thread.as_bytes(), self.mode.as_str().as_bytes(), self.ts.as_bytes(),
            self.digest.as_bytes(), &audience];
        fields.extend(self.blobs.iter().map(|s| s.as_bytes()));
        crate::paseto::pae(&fields)
    }
}

/// Hash the encrypted body's public-facing fields using the same length framing as the signature.
pub fn post_digest(salt: &[u8], text: &str, files: &[serde_json::Value]) -> Result<String> {
    post_digest_meta(salt, text, files, "")
}

/// The digest with the body's room fields (`Body::meta`, the exact JSON text the sender signed). Without meta it is
/// the same digest as before rooms, so earlier messages verify unchanged.
pub fn post_digest_meta(salt: &[u8], text: &str, files: &[serde_json::Value], meta: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(crate::paseto::pae(&[b"islandmail/body-digest/v1", salt, text.as_bytes()]));
    for file in files {
        let field = |k: &str| file[k].as_str().ok_or_else(|| anyhow!("invalid attachment {k}"));
        let size = file["size"].as_u64().ok_or_else(|| anyhow!("invalid attachment size"))?;
        h.update(crate::paseto::pae(&[field("id")?.as_bytes(), field("name")?.as_bytes(),
            field("type")?.as_bytes(), &size.to_le_bytes()]));
    }
    if !meta.is_empty() {
        h.update(crate::paseto::pae(&[b"islandmail/body-meta/v1", meta.as_bytes()]));
    }
    Ok(format!("{:x}", h.finalize()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WrappedKey {
    pub to: String,
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
    /// The writing node's key.
    pub node: String,
    pub sig: String,
}

/// The encrypted part.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Body {
    pub text: String,
    /// Each attachment contains its ciphertext ID, name, media type, byte size and secret blob key.
    #[serde(default)]
    pub files: Vec<serde_json::Value>,
    /// b64url salt of the sender's digest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub salt: String,
    /// Room fields (`room::Meta`) as the JSON text the sender signed; empty for plain mail.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub meta: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    pub sender_sub: String,
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
        let plain = serde_json::to_vec(d.body)?;
        let ad = header_ad(VERSION, d.thread, d.from, d.to, d.mode, &d.ts);
        let sealed = crypto::seal(&plain, &ad, d.recipients)?;
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
        self.open_for([me])
    }

    /// Try local keys against the same decoded wraps. A matching key must authenticate the body.
    pub fn open_for<'a>(&self, local_keys: impl IntoIterator<Item = &'a Seed>) -> Result<Option<Body>> {
        let (ct, epk, ad) = self.parts()?;
        let wraps = self.wraps()?;
        for key in local_keys {
            if let Some(plain) = crypto::open(&ct, &ad, &epk, &wraps, key)? {
                return Ok(Some(serde_json::from_slice(&plain)?));
            }
        }
        Ok(None)
    }

    /// The content key, if one of `local_keys` is a recipient (for re-wrapping it in a key grant).
    pub fn content_key<'a>(&self, local_keys: impl IntoIterator<Item = &'a Seed>) -> Result<Option<[u8; 32]>> {
        let (_, epk, _) = self.parts()?;
        let wraps = self.wraps()?;
        for key in local_keys {
            if let Some(ck) = crypto::content_key(&epk, &wraps, key)? {
                return Ok(Some(ck));
            }
        }
        Ok(None)
    }

    /// The body under a content key from a grant. Err if the key does not open it.
    pub fn open_with(&self, ck: &[u8; 32]) -> Result<Body> {
        let (ct, _, ad) = self.parts()?;
        Ok(serde_json::from_slice(&crypto::decrypt_with(&ct, &ad, ck)?)?)
    }

    fn parts(&self) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
        let ct = b64u_decode(&self.ciphertext).ok_or_else(|| anyhow!("bad ciphertext"))?;
        let epk: [u8; 32] =
            b64u_decode(&self.epk).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad epk"))?;
        Ok((ct, epk, header_ad(self.v, &self.thread, &self.from, &self.to, self.mode, &self.ts)))
    }

    /// The certificate the envelope carries for its sender, if any.
    pub fn carried_cert(&self) -> Option<&Cert> {
        let Attest { cert, .. } = &self.attest;
        cert.as_ref()
    }

    /// Validate framing, writing peer and sender before accepting an envelope. `agents` is who this host accepts at
    /// the envelope's time (`MemberList::agents`, given the carried certificate too).
    pub fn verify(&self, members: &MemberList, agents: &[Agent], now_ms: i64) -> Result<Verified> {
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
        let wraps = self.wraps()?;
        if !wraps.iter().all(|w| w.k.len() == 48) {
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
        // A forwarding node can check the nonce, tag and size bounds without a recipient key.
        if !(24 + 16..=MAX_CIPHERTEXT).contains(&ct.len()) {
            bail!("invalid ciphertext length");
        }
        if blake3::hash(&ct).to_hex().as_str() != self.id {
            bail!("id is not the hash of the ciphertext");
        }
        let node = parse_key(&self.node)?;
        let sig = b64u_decode(&self.sig).ok_or_else(|| anyhow!("bad sig"))?;
        if !keys::verify(&node, &self.signing_bytes(), &sig) {
            bail!("node signature does not verify");
        }
        let Attest { key, digest, sig, .. } = &self.attest;
        if !members.is_node(&node) {
            bail!("written by a node that is not a member");
        }
        let k = parse_key(key)?;
        let m = match members::find(agents, &self.from, &k) {
            Some(m) => m,
            None if members::named(agents, &self.from).next().is_some() =>
                bail!("signed by a key that is not {}'s key on the member list or in its certificates", self.from),
            None => bail!("{} is not on the member list and has no certificate from a trusted node", self.from),
        };
        if !m.pinned && !m.certs.iter().any(|c| c.issued_by(ts)) {
            bail!("message predates the sender's certificates");
        }
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("bad digest");
        }
        let st = PostStatement {
            from: &self.from, sub: &m.sub, to: &self.to, thread: &self.thread, mode: self.mode,
            ts: &self.ts, digest, blobs: &self.blobs, recipients: &wraps.iter().map(|w| w.to).collect::<Vec<_>>(),
        }.signing_bytes(members);
        let s = b64u_decode(sig).ok_or_else(|| anyhow!("bad sender signature"))?;
        // One encoding per signature: nodes recognize a replayed message by it (see agent_sig in the store).
        if b64u(&s) != *sig {
            bail!("sender signature is not canonical base64url");
        }
        if !keys::verify(&k, &st, &s) {
            bail!("sender signature does not verify");
        }
        Ok(Verified { sender_sub: m.sub.clone() })
    }

    /// For readers, after decrypting: an agent-signed envelope's digest must match the body it carries, and the
    /// body's attachments must be the header's blobs.
    pub fn check_body(&self, body: &Body) -> Result<()> {
        if body.files.len() != self.blobs.len() || !body.files.iter().zip(&self.blobs).all(|(f, id)| {
            f.as_object().is_some_and(|o| o.len() == 5) && f["id"].as_str() == Some(id) && f["key"].as_str().and_then(b64u_decode).is_some_and(|k| k.len() == 32)
        }) {
            bail!("body attachments do not match the header's blobs");
        }
        let Attest { digest, .. } = &self.attest;
        let salt = b64u_decode(&body.salt).filter(|s| s.len() == 16).ok_or_else(|| anyhow!("invalid salt length"))?;
        if &post_digest_meta(&salt, &body.text, &body.files, &body.meta)? != digest {
            bail!("body does not match the sender's signed digest");
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

    fn pinned(l: &MemberList) -> Vec<Agent> {
        l.agents(&[], &|_| None, 0)
    }

    struct World {
        node: Seed,
        alice: Seed,
        bob: Seed,
        carol: Seed,
        members: MemberList,
    }

    fn world() -> World {
        let node = Seed::generate();
        let (alice, bob, carol) = (Seed::generate(), Seed::generate(), Seed::generate());
        let members = list(&[("a.alice", &alice), ("a.bob", &bob), ("b.carol", &carol)], &[&node]);
        World { node, alice, bob, carol, members }
    }

    fn env(w: &World, from: &str, to: &str, mode: Mode) -> Envelope {
        let signer = if from == "a.alice" { &w.alice } else { &w.carol };
        let ts = crate::now_ts();
        let salt = crate::random_bytes::<16>();
        let body = Body { text: format!("hi from {from}"), salt: b64u(&salt), files: vec![], meta: String::new() };
        let digest = post_digest(&salt, &body.text, &[]).unwrap();
        let recipients = match mode {
            Mode::Members => w.members.all_keys(),
            Mode::Private => members::private_keys(&pinned(&w.members), to, from),
        };
        let sig = b64u(&signer.sign(&PostStatement {
            from, sub: &format!("agent:{from}@test"), to, thread: "t", mode,
            ts: &ts, digest: &digest, blobs: &[], recipients: &recipients,
        }.signing_bytes(&w.members)));
        Envelope::seal(
            Draft {
                thread: "t",
                parents: vec![],
                ts,
                from,
                to,
                mode,
                body: &body,
                blobs: vec![],
                attest: Attest { key: fmt_key(&signer.public()), sig, digest, cert: None },
                recipients: &recipients,
            },
            &w.node,
        )
        .unwrap()
    }

    #[test]
    fn opening_with_local_keys_distinguishes_unaddressed_mail_from_corruption() {
        let w = world();
        let mut mail = env(&w, "a.alice", "a.bob", Mode::Private);
        assert!(mail.open_for([&w.node, &w.carol]).unwrap().is_none());
        assert_eq!(mail.open_for([&w.node, &w.bob]).unwrap().unwrap().text, "hi from a.alice");
        mail.ciphertext = crate::b64u(&[0; 40]);
        assert!(mail.open_for([&w.node, &w.bob]).is_err());
    }

    /// An envelope signed by `signer` as `from` (the agent-key path), with the given body text.
    fn signed_env(w: &World, from: &str, signer: &Seed, text: &str, ts: String) -> Envelope {
        let salt = crate::random_bytes::<16>();
        let digest = post_digest(&salt, text, &[]).unwrap();
        let st = PostStatement {
            from, sub: &format!("agent:{from}@test"), to: "all", thread: "t", mode: Mode::Members,
            ts: &ts, digest: &digest, blobs: &[], recipients: &w.members.all_keys(),
        }.signing_bytes(&w.members);
        let attest = Attest { key: fmt_key(&signer.public()), digest, sig: b64u(&signer.sign(&st)), cert: None };
        let body = Body { text: text.into(), files: vec![], salt: b64u(&salt), meta: String::new() };
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
        let now = crate::now_millis();
        let e = signed_env(&w, "a.alice", &w.alice, "signed by alice", crate::now_ts());
        let v = e.verify(&w.members, &pinned(&w.members), now).unwrap();
        assert_eq!(v.sender_sub, "agent:a.alice@test");
        let body = e.open(&w.node).unwrap().unwrap();
        e.check_body(&body).unwrap();
        let mut altered = e.clone();
        altered.keys.pop();
        altered.sig = b64u(&w.node.sign(&altered.signing_bytes()));
        assert!(altered.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("sender signature"));
        // Bob's key claiming to be alice.
        let e = signed_env(&w, "a.alice", &w.bob, "forged", crate::now_ts());
        assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("not a.alice's key"));
        // Not on the member list at all.
        let stranger = Seed::generate();
        let e = signed_env(&w, "x.stranger", &stranger, "who", crate::now_ts());
        assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("not on the member list"));
        // A header changed by the node after the sender signed (re-signed by the node so only the agent sig breaks).
        let mut e = signed_env(&w, "a.alice", &w.alice, "to all", crate::now_ts());
        e.to = "a.bob".into();
        e.sig = b64u(&w.node.sign(&e.signing_bytes()));
        assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("sender signature"));
        // A body swapped by the node under alice's signed digest: verify passes (header intact), check_body refuses.
        let good = signed_env(&w, "a.alice", &w.alice, "original", crate::now_ts());
        let mut body = good.open(&w.node).unwrap().unwrap();
        body.text = "tampered".into();
        assert!(good.check_body(&body).unwrap_err().to_string().contains("digest"));
    }

    #[test]
    fn signed_statement_fields_cannot_shift() {
        let w = world();
        let now = crate::now_millis();
        let ts = crate::now_ts();
        let salt = crate::random_bytes::<16>();
        let digest = post_digest(&salt, "hi", &[]).unwrap();
        // alice signs to "all", thread "x|y".
        let st = PostStatement {
            from: "a.alice", sub: "agent:a.alice@test", to: "all", thread: "x|y", mode: Mode::Members,
            ts: &ts, digest: &digest, blobs: &[], recipients: &w.members.all_keys(),
        }.signing_bytes(&w.members);
        let attest = Attest { key: fmt_key(&w.alice.public()), digest, sig: b64u(&w.alice.sign(&st)), cert: None };
        let body = Body { text: "hi".into(), files: vec![], salt: b64u(&salt), meta: String::new() };
        let mk = |to: &str, thread: &str| {
            Envelope::seal(
                Draft {
                    thread,
                    parents: vec![],
                    ts: ts.clone(),
                    from: "a.alice",
                    to,
                    mode: Mode::Members,
                    body: &body,
                    blobs: vec![],
                    attest: attest.clone(),
                    recipients: &w.members.all_keys(),
                },
                &w.node,
            )
            .unwrap()
        };
        assert!(mk("all", "x|y").verify(&w.members, &pinned(&w.members), now).is_ok(), "'|' in the thread is fine");
        assert!(mk("all|x", "y").verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("sender signature"));
        let mut other_network = w.members.clone();
        other_network.network.push_str("-other");
        assert!(mk("all", "x|y").verify(&other_network, &pinned(&other_network), now).unwrap_err().to_string().contains("sender signature"));
    }

    #[test]
    fn refuses_unbounded_fields() {
        let w = world();
        let now = crate::now_millis();
        let resign = |mut e: Envelope| {
            e.sig = b64u(&w.node.sign(&e.signing_bytes()));
            e
        };
        let base = env(&w, "a.alice", "all", Mode::Members);
        assert!(base.verify(&w.members, &pinned(&w.members), now).is_ok());
        for len in [39, MAX_CIPHERTEXT + 1] {
            let mut e = base.clone();
            e.ciphertext = b64u(&vec![0; len]);
            assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("ciphertext length"));
        }
        let mut e = base.clone();
        e.blobs = (0..MAX_BLOBS + 1).map(|i| format!("{i:064x}")).collect();
        assert!(resign(e).verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.blobs = vec!["not-a-hash".into()];
        assert!(resign(e).verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.keys[0].k = b64u(&[0u8; 4096]);
        assert!(resign(e).verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("wrapped key"));
        let mut e = base.clone();
        e.epk = b64u(&[0u8; 7]);
        assert!(resign(e).verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("epk"));
    }

    #[test]
    fn short_ids_and_prefix_ranges() {
        let env = "00443214c74254b635cf84653a56d7c675be77df".to_string() + "0123456789abcdefabcdef01";
        let id = crate::b32_id(&env);
        assert_eq!(id.len(), 52);
        assert_eq!(&id[..8], "abcdefgh");
        assert_eq!(crate::short_id(&env), &id[..8]);
        for n in [1, 3, 8, 13, 51, 52] {
            let (lo, hi) = crate::id_prefix_range(&id[..n]).unwrap();
            assert!(lo.as_str() <= env.as_str() && env.as_str() <= hi.as_str(), "prefix {n}");
            assert_eq!(lo.len(), 64);
        }
        let (lo, hi) = crate::id_prefix_range("abcdefgi").unwrap();
        assert!(env < lo || env > hi);
        assert!(crate::id_prefix_range("ab1").is_none() && crate::id_prefix_range("").is_none());
    }

    #[test]
    fn room_fields_are_covered_by_the_digest() {
        let salt = [7u8; 16];
        let plain = post_digest(&salt, "hi", &[]).unwrap();
        assert_eq!(plain, post_digest_meta(&salt, "hi", &[], "").unwrap(), "no meta: the digest before rooms");
        let meta = r#"{"room":"hypha/x","mentions":["bob"]}"#;
        let signed = post_digest_meta(&salt, "hi", &[], meta).unwrap();
        assert_ne!(signed, plain);
        assert_ne!(signed, post_digest_meta(&salt, "hi", &[], r#"{"room":"hypha/x"}"#).unwrap());
    }

    #[test]
    fn roundtrip_through_json() {
        let w = world();
        let e = env(&w, "a.alice", "all", Mode::Members);
        let wire = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.signing_bytes(), e.signing_bytes());
        let v = back.verify(&w.members, &pinned(&w.members), crate::now_millis()).unwrap();
        assert_eq!(v.sender_sub, "agent:a.alice@test");
        assert_eq!(back.open(&w.node).unwrap().unwrap().text, "hi from a.alice");
    }

    #[test]
    fn rejects_changed_or_untrusted_envelopes() {
        let w = world();
        let now = crate::now_millis();
        // written by a node not on the member list
        let mut e = env(&w, "a.alice", "all", Mode::Members);
        let stranger = Seed::generate();
        e.node = fmt_key(&stranger.public());
        e.sig = b64u(&stranger.sign(&e.signing_bytes()));
        assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("not a member"));
        // header changed after signing
        let mut e = env(&w, "a.alice", "all", Mode::Members);
        e.thread = "other".into();
        assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("signature"));
        // ciphertext swapped: id no longer matches
        let mut e = env(&w, "a.alice", "all", Mode::Members);
        let other = env(&w, "a.alice", "all", Mode::Members);
        e.ciphertext = other.ciphertext;
        assert!(e.verify(&w.members, &pinned(&w.members), now).unwrap_err().to_string().contains("hash"));
    }

    #[test]
    fn members_vs_private_reading() {
        let w = world();
        let m = env(&w, "a.alice", "a.bob", Mode::Members);
        for k in [&w.alice, &w.bob, &w.carol, &w.node] {
            assert!(m.open(k).unwrap().is_some(), "members mode opens for every member and node");
        }
        let outsider = Seed::generate();
        assert!(m.open(&outsider).unwrap().is_none());

        let p = env(&w, "a.alice", "a.bob", Mode::Private);
        assert!(p.open(&w.alice).unwrap().is_some(), "sender reads its own private mail");
        assert!(p.open(&w.bob).unwrap().is_some(), "recipient reads it");
        assert!(p.open(&w.carol).unwrap().is_none(), "another member does not");
        assert!(p.open(&w.node).unwrap().is_none(), "nor does the node");
        // A team prefix in private mode reaches the team only.
        let t = env(&w, "b.carol", "a.", Mode::Private);
        assert!(t.open(&w.alice).unwrap().is_some());
        assert!(t.open(&w.bob).unwrap().is_some());
        assert!(t.open(&w.carol).unwrap().is_some());
        assert!(t.open(&w.node).unwrap().is_none());
    }

    /// A certified agent's envelope, written by `writer`, carrying `cert` (or none).
    #[allow(clippy::too_many_arguments)]
    fn certified_env(l: &MemberList, agents: &[Agent], writer: &Seed, from: &str, signer: &Seed, to: &str, mode: Mode,
                     ts: String, cert: Option<Cert>) -> Envelope {
        let salt = crate::random_bytes::<16>();
        let body = Body { text: "hello".into(), files: vec![], salt: b64u(&salt), meta: String::new() };
        let digest = post_digest(&salt, &body.text, &[]).unwrap();
        let recipients = match mode {
            Mode::Members => l.all_keys(),
            Mode::Private => members::private_keys(agents, to, from),
        };
        let st = PostStatement {
            from, sub: &crate::cert::agent_sub(from), to, thread: "t", mode,
            ts: &ts, digest: &digest, blobs: &[], recipients: &recipients,
        }.signing_bytes(l);
        let attest = Attest { key: fmt_key(&signer.public()), digest, sig: b64u(&signer.sign(&st)), cert };
        Envelope::seal(Draft { thread: "t", parents: vec![], ts, from, to, mode, body: &body, blobs: vec![], attest,
                               recipients: &recipients }, writer).unwrap()
    }

    #[test]
    fn node_certified_senders() {
        let (mac, pod, ops) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (hypha, bob, carol) = (Seed::generate(), Seed::generate(), Seed::generate());
        let mut l = list(&[("b.carol", &carol)], &[&mac, &pod, &ops]);
        l.nodes[0].names = vec!["hypha".into(), "sauersml.".into()];
        l.nodes[1].names = vec!["hypha".into()];
        l.nodes[2].names = vec!["ops.".into()];
        l.validate().unwrap();
        let now = crate::now_millis();
        let ts = crate::ts_from_millis(now - 1000);
        let mac_cert = Cert::issue(&mac, "hypha", &hypha.public(), &ts);
        let pod_cert = Cert::issue(&pod, "hypha", &hypha.public(), &ts);
        let none = |_: &Cert| None;

        // A cert from a pinned node within its namespace is accepted, from the envelope alone.
        let agents = l.agents(std::slice::from_ref(&mac_cert), &none, now);
        let e = certified_env(&l, &agents, &mac, "hypha", &hypha, "all", Mode::Members, crate::now_ts(), Some(mac_cert.clone()));
        assert_eq!(e.verify(&l, &agents, now).unwrap().sender_sub, "agent:hypha");
        assert!(e.verify(&l, &l.agents(&[], &none, now), now).unwrap_err().to_string().contains("no certificate"));

        let boundary = now - 1000 - crate::cert::CERTIFY_SKEW_MS;
        for (t, allowed) in [(boundary - 1, false), (boundary, true)] {
            let mail = certified_env(&l, &agents, &mac, "hypha", &hypha, "all", Mode::Members,
                                     crate::ts_from_millis(t), Some(mac_cert.clone()));
            let dated = l.agents(std::slice::from_ref(&mac_cert), &none, t);
            assert_eq!(mail.verify(&l, &dated, now).is_ok(), allowed);
            assert_eq!(mail.verify(&l, &agents, now).is_ok(), allowed, "writer using its current roster");
        }

        // Out of namespace: ops's node cannot vouch for sauersml.x, nor can an untrusted node.
        let rogue = Cert::issue(&ops, "sauersml.x", &bob.public(), &ts);
        assert!(!l.accepts(&rogue));
        assert!(!l.accepts(&Cert::issue(&Seed::generate(), "hypha", &bob.public(), &ts)));
        let agents = l.agents(std::slice::from_ref(&rogue), &none, now);
        assert!(members::named(&agents, "sauersml.x").next().is_none());
        assert!(certified_env(&l, &agents, &ops, "sauersml.x", &bob, "all", Mode::Members, crate::now_ts(), Some(rogue))
            .verify(&l, &agents, now).is_err());

        // A pin takes precedence: a cert for a pinned name with another key does not count.
        let squat = Cert::issue(&mac, "b.carol", &bob.public(), &ts);
        let mut l2 = l.clone();
        l2.nodes[0].names.push("b.".into());
        let agents = l2.agents(&[squat], &none, now);
        assert_eq!(members::named(&agents, "b.carol").map(|a| a.key).collect::<Vec<_>>(), vec![carol.public()]);

        // Two homes: private mail to hypha opens at both of its nodes, and at no other.
        let both = [mac_cert.clone(), pod_cert.clone()];
        let agents = l.agents(&both, &none, now);
        assert_eq!(members::named(&agents, "hypha").count(), 1);
        let p = certified_env(&l, &agents, &pod, "hypha", &hypha, "b.carol", Mode::Private, crate::now_ts(), Some(pod_cert.clone()));
        p.verify(&l, &agents, now).unwrap();
        assert!(p.open(&mac).unwrap().is_some() && p.open(&pod).unwrap().is_some() && p.open(&hypha).unwrap().is_some());
        assert!(p.open(&ops).unwrap().is_none());

        // Revocation by the mac counts only against the mac's cert, and only from its time on.
        let rev_at = now - 500;
        let mac_key = fmt_key(&mac.public());
        let revoked = |c: &Cert| (c.node == mac_key).then_some(rev_at);
        let early = crate::ts_from_millis(now - 800);
        let at = |t: i64| l.agents(std::slice::from_ref(&mac_cert), &revoked, t);
        let old = certified_env(&l, &at(now - 800), &mac, "hypha", &hypha, "all", Mode::Members, early, Some(mac_cert.clone()));
        assert!(old.verify(&l, &at(old.ts_ms()), now).is_ok(), "mail dated before the revocation still verifies");
        let new = certified_env(&l, &at(now), &mac, "hypha", &hypha, "all", Mode::Members, crate::now_ts(), Some(mac_cert.clone()));
        assert!(new.verify(&l, &at(new.ts_ms()), now).is_err(), "mail dated after it does not");
        let agents = l.agents(&both, &revoked, now);
        assert_eq!(members::named(&agents, "hypha").next().unwrap().homes, vec![pod.public()],
                   "the pod's cert for the same key stays live");
    }
}
