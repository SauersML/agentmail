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
/// nonce + tag + the largest padded body (512 KiB).
pub const MAX_CIPHERTEXT: usize = 512 * 1024 + 40;
pub const MAX_KEYS: usize = 1000;
/// Attachments per message.
pub const MAX_BLOBS: usize = 10;
/// An envelope dated further than this past the receiver's clock is refused (peers fetch it again later).
pub const FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;
const SIG_CONTEXT: &[u8] = b"islandmail/envelope/v1\n";
const AD_CONTEXT: &str = "islandmail/sealed/v1";

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
    /// Opaque slot label (16 bytes, b64url): only the recipient can recompute it (`crypto`).
    pub t: String,
    pub k: String,
}

/// What every node sees: who wrote it (the node), when, how big, how many wrap slots and attachment ids. Sender,
/// recipients, thread, parents, mode and the sender's signature are inside the ciphertext (`Header`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub v: u32,
    /// hex BLAKE3 of the decoded ciphertext bytes.
    pub id: String,
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ`
    pub ts: String,
    /// nonce || XChaCha20-Poly1305 of the padded `Inner` JSON.
    pub ciphertext: String,
    /// Ephemeral X25519 public key for the key wraps.
    pub epk: String,
    /// Wrap slots, a power of two, padded with random ones and ordered by tag.
    pub keys: Vec<WrappedKey>,
    /// Encrypted attachment blobs (hex BLAKE3 of each blob's ciphertext), in body.files order. In the clear so nodes
    /// that cannot read the body still replicate the blobs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<String>,
    /// The writing node's key.
    pub node: String,
    pub sig: String,
}

/// The sealed routing fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub thread: String,
    /// Thread heads (envelope ids) the writing node had when it wrote this one.
    pub parents: Vec<String>,
    pub from: String,
    pub to: String,
    pub mode: Mode,
    /// The recipient identity keys (agents and nodes) the sender signed, sorted: who may read it.
    pub audience: Vec<String>,
    pub attest: Attest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner {
    h: Header,
    b: Body,
}

/// A decrypted envelope: its header, its body and the content key that opened it.
#[derive(Clone, Debug)]
pub struct Opened {
    pub header: Header,
    pub body: Body,
    pub ck: [u8; 32],
}

impl Header {
    pub fn audience_keys(&self) -> Result<Vec<PublicKey>> {
        self.audience.iter().map(|k| parse_key(k)).collect()
    }
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
    /// The audience: identity keys the sender signed.
    pub recipients: &'a [PublicKey],
}

/// The ciphertext's associated data: the public fields the node signs too, so a body cannot move between envelopes.
fn outer_ad(v: u32, ts: &str, node: &str, blobs: &[String]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([AD_CONTEXT, v, ts, node, blobs])).expect("json")
}

/// Most padded plaintext an envelope carries.
pub const MAX_PADDED: usize = MAX_CIPHERTEXT - 40;

impl Envelope {
    /// Seal to the audience's own long-lived keys (identity_targets): every key in `recipients` can open it.
    pub fn seal(d: Draft<'_>, node: &Seed) -> Result<Envelope> {
        let targets = crypto::identity_targets(d.recipients)?;
        Self::seal_to(d, node, &targets)
    }

    /// Seal with the content key wrapped to exactly `targets` (X25519 keys: a node's rotating key, or an identity's).
    pub fn seal_to(d: Draft<'_>, node: &Seed, targets: &[[u8; 32]]) -> Result<Envelope> {
        let mut audience: Vec<String> = d.recipients.iter().map(fmt_key).collect();
        audience.sort();
        audience.dedup();
        let header = Header {
            thread: d.thread.to_string(), parents: d.parents, from: d.from.to_string(), to: d.to.to_string(),
            mode: d.mode, audience, attest: d.attest,
        };
        let plain = crypto::pad(&serde_json::to_vec(&Inner { h: header, b: d.body.clone() })?, crypto::BODY_CHUNK)?;
        if plain.len() > MAX_PADDED {
            bail!("message too large for an envelope");
        }
        let node_key = fmt_key(&node.public());
        let sealed = crypto::seal(&plain, &outer_ad(VERSION, &d.ts, &node_key, &d.blobs), targets)?;
        let mut env = Envelope {
            v: VERSION,
            id: blake3::hash(&sealed.ciphertext).to_hex().to_string(),
            ts: d.ts,
            ciphertext: b64u(&sealed.ciphertext),
            epk: b64u(&sealed.epk),
            keys: sealed.keys.iter().map(|w| WrappedKey { t: b64u(&w.tag), k: b64u(&w.k) }).collect(),
            blobs: d.blobs,
            node: node_key,
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
                let tag = b64u_decode(&w.t).and_then(|t| t.try_into().ok()).ok_or_else(|| anyhow!("bad wrap tag"))?;
                Ok(Wrapped { tag, k: b64u_decode(&w.k).ok_or_else(|| anyhow!("bad wrapped key"))? })
            })
            .collect()
    }

    /// Opened with whichever of `local_keys` one of the slots is for. A matching key must authenticate the body.
    pub fn open_for<'a>(&self, local_keys: impl IntoIterator<Item = &'a Seed>) -> Result<Option<Opened>> {
        match self.content_key(local_keys)? {
            Some(ck) => self.open_with(&ck).map(Some),
            None => Ok(None),
        }
    }

    pub fn open(&self, me: &Seed) -> Result<Option<Opened>> {
        self.open_for([me])
    }

    /// The content key, if one of `local_keys` has a slot (for re-wrapping it in a key grant).
    pub fn content_key<'a>(&self, local_keys: impl IntoIterator<Item = &'a Seed>) -> Result<Option<[u8; 32]>> {
        let epk = self.epk_bytes()?;
        let wraps = self.wraps()?;
        for key in local_keys {
            if let Some(ck) = crypto::content_key(&epk, &wraps, key)? {
                return Ok(Some(ck));
            }
        }
        Ok(None)
    }

    /// Header and body under a content key (from a slot or a key grant). Err if the key does not open it.
    pub fn open_with(&self, ck: &[u8; 32]) -> Result<Opened> {
        let ct = b64u_decode(&self.ciphertext).ok_or_else(|| anyhow!("bad ciphertext"))?;
        let padded = crypto::decrypt_with(&ct, &outer_ad(self.v, &self.ts, &self.node, &self.blobs), ck)?;
        let inner: Inner = serde_json::from_slice(crypto::unpad(&padded)?)?;
        Ok(Opened { header: inner.h, body: inner.b, ck: *ck })
    }

    fn epk_bytes(&self) -> Result<[u8; 32]> {
        b64u_decode(&self.epk).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("bad epk"))
    }

    /// What any trusted node checks before keeping and forwarding an envelope it may not be able to read: framing,
    /// sizes, time and the writing node's signature and membership.
    pub fn check(&self, members: &MemberList, now_ms: i64) -> Result<()> {
        if self.v != VERSION {
            bail!("unsupported envelope version {}", self.v);
        }
        let n = self.keys.len();
        if n < crypto::MIN_SLOTS || n > MAX_KEYS.next_power_of_two() || !n.is_power_of_two() {
            bail!("bad key list");
        }
        let wraps = self.wraps()?;
        if !wraps.iter().all(|w| w.k.len() == crypto::WRAP_LEN) {
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
        // Every body is padded to a bucket, so a forwarding node can check its length without a key.
        if ct.len() < 40 || ct.len() > MAX_CIPHERTEXT || !crypto::is_padded_len(ct.len() - 40, crypto::BODY_CHUNK) {
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
        if !members.is_node(&node) {
            bail!("written by a node that is not a member");
        }
        Ok(())
    }

    /// For the nodes that can read it, after `check` and opening: the sealed header (sender, its key and signature
    /// over the routing fields, audience and digest) and the body against that digest. `agents` is who this host
    /// accepts at the envelope's time (`MemberList::agents`, given the carried certificate too).
    pub fn verify_opened(&self, o: &Opened, members: &MemberList, agents: &[Agent]) -> Result<Verified> {
        let h = &o.header;
        for (name, f) in [("thread", &h.thread), ("from", &h.from), ("to", &h.to)] {
            if f.is_empty() || f.chars().count() > MAX_FIELD || f.chars().any(|c| c.is_control()) {
                bail!("bad {name}");
            }
        }
        if h.parents.len() > MAX_PARENTS || !h.parents.iter().all(|p| is_id(p)) {
            bail!("bad parents");
        }
        if h.audience.is_empty() || h.audience.len() > MAX_KEYS || !h.audience.windows(2).all(|w| w[0] < w[1]) {
            bail!("bad audience");
        }
        let audience = h.audience_keys()?;
        if audience.iter().map(fmt_key).ne(h.audience.iter().cloned()) {
            bail!("audience keys are not canonical");
        }
        let ts = self.ts_ms();
        let Attest { key, digest, sig, .. } = &h.attest;
        let k = parse_key(key)?;
        let m = match members::find(agents, &h.from, &k) {
            Some(m) => m,
            None if members::named(agents, &h.from).next().is_some() =>
                bail!("signed by a key that is not {}'s key on the member list or in its certificates", h.from),
            None => bail!("{} is not on the member list and has no certificate from a trusted node", h.from),
        };
        if !m.pinned && !m.certs.iter().any(|c| c.issued_by(ts)) {
            bail!("message predates the sender's certificates");
        }
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("bad digest");
        }
        let st = PostStatement {
            from: &h.from, sub: &m.sub, to: &h.to, thread: &h.thread, mode: h.mode,
            ts: &self.ts, digest, blobs: &self.blobs, recipients: &audience,
        }.signing_bytes(members);
        let s = b64u_decode(sig).ok_or_else(|| anyhow!("bad sender signature"))?;
        // One encoding per signature: nodes recognize a replayed message by it (see agent_sig in the store).
        if b64u(&s) != *sig {
            bail!("sender signature is not canonical base64url");
        }
        if !keys::verify(&k, &st, &s) {
            bail!("sender signature does not verify");
        }
        self.check_body(h, &o.body)?;
        Ok(Verified { sender_sub: m.sub.clone() })
    }

    /// `check`, open with one of `local_keys` (an error if none can) and `verify_opened`.
    pub fn verify<'a>(&self, members: &MemberList, agents: &[Agent], now_ms: i64,
                      local_keys: impl IntoIterator<Item = &'a Seed>) -> Result<(Verified, Opened)> {
        self.check(members, now_ms)?;
        let o = self.open_for(local_keys)?.ok_or_else(|| anyhow!("none of these keys opens the envelope"))?;
        Ok((self.verify_opened(&o, members, agents)?, o))
    }

    /// The sender's digest must match the body it carries, and the body's attachments must be the envelope's blobs.
    pub fn check_body(&self, h: &Header, body: &Body) -> Result<()> {
        if body.files.len() != self.blobs.len() || !body.files.iter().zip(&self.blobs).all(|(f, id)| {
            f.as_object().is_some_and(|o| o.len() == 5) && f["id"].as_str() == Some(id) && f["key"].as_str().and_then(b64u_decode).is_some_and(|k| k.len() == 32)
        }) {
            bail!("body attachments do not match the header's blobs");
        }
        let Attest { digest, .. } = &h.attest;
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
        assert_eq!(mail.open_for([&w.node, &w.bob]).unwrap().unwrap().body.text, "hi from a.alice");
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

    /// `e` opened by the world's node, its header edited, sealed again by the node (the sender's signature is kept).
    fn reseal(w: &World, e: &Envelope, edit: impl FnOnce(&mut Header)) -> Envelope {
        let o = e.open(&w.node).unwrap().unwrap();
        let mut h = o.header;
        edit(&mut h);
        let recipients = h.audience_keys().unwrap();
        Envelope::seal(Draft { thread: &h.thread, parents: h.parents.clone(), ts: e.ts.clone(), from: &h.from, to: &h.to,
                               mode: h.mode, body: &o.body, blobs: e.blobs.clone(), attest: h.attest.clone(),
                               recipients: &recipients }, &w.node).unwrap()
    }

    #[test]
    fn agent_signed_envelopes() {
        let w = world();
        let now = crate::now_millis();
        let ok = |e: &Envelope| e.verify(&w.members, &pinned(&w.members), now, [&w.node]);
        let e = signed_env(&w, "a.alice", &w.alice, "signed by alice", crate::now_ts());
        let (v, o) = ok(&e).unwrap();
        assert_eq!(v.sender_sub, "agent:a.alice@test");
        assert_eq!(o.body.text, "signed by alice");
        // The audience is signed: a node dropping a recipient breaks the sender's signature.
        let node = crate::keys::fmt_key(&w.node.public());
        let fewer = reseal(&w, &e, |h| { let i = h.audience.iter().position(|k| *k != node).unwrap(); h.audience.remove(i); });
        assert!(ok(&fewer).unwrap_err().to_string().contains("sender signature"));
        // Bob's key claiming to be alice.
        let e = signed_env(&w, "a.alice", &w.bob, "forged", crate::now_ts());
        assert!(ok(&e).unwrap_err().to_string().contains("not a.alice's key"));
        // Not on the member list at all.
        let stranger = Seed::generate();
        let e = signed_env(&w, "x.stranger", &stranger, "who", crate::now_ts());
        assert!(ok(&e).unwrap_err().to_string().contains("not on the member list"));
        // A sealed field changed by the node after the sender signed.
        let e = signed_env(&w, "a.alice", &w.alice, "to all", crate::now_ts());
        for edit in [(|h: &mut Header| h.to = "a.bob".into()) as fn(&mut Header), |h| h.thread = "other".into(),
                     |h| h.mode = Mode::Private] {
            assert!(ok(&reseal(&w, &e, edit)).unwrap_err().to_string().contains("sender signature"));
        }
        // A body swapped by the node under alice's signed digest.
        let good = signed_env(&w, "a.alice", &w.alice, "original", crate::now_ts());
        let o = good.open(&w.node).unwrap().unwrap();
        let mut body = o.body.clone();
        body.text = "tampered".into();
        assert!(good.check_body(&o.header, &body).unwrap_err().to_string().contains("digest"));
    }

    #[test]
    fn the_wire_form_hides_routing_fields() {
        let w = world();
        let e = signed_env(&w, "a.alice", &w.alice, "a secret body", crate::now_ts());
        let wire = serde_json::to_string(&e).unwrap();
        for hidden in ["a.alice", "members", "attest", "secret", "thread", &fmt_key(&w.alice.public()),
                       &fmt_key(&w.bob.public())] {
            assert!(!wire.contains(hidden), "{hidden} is visible on the wire: {wire}");
        }
        let fields: Vec<String> = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&wire).unwrap()
            .keys().cloned().collect();
        assert_eq!(fields, ["ciphertext", "epk", "id", "keys", "node", "sig", "ts", "v"]);
        // Size says only the bucket: a 1-byte and a 300-byte body give the same length.
        let a = signed_env(&w, "a.alice", &w.alice, "x", crate::now_ts());
        let b = signed_env(&w, "a.alice", &w.alice, &"y".repeat(300), crate::now_ts());
        assert_eq!(a.ciphertext.len(), b.ciphertext.len());
        assert_eq!(b64u_decode(&a.ciphertext).unwrap().len(), 1024 + 40);
        let big = signed_env(&w, "a.alice", &w.alice, &"z".repeat(5000), crate::now_ts());
        assert_eq!(b64u_decode(&big.ciphertext).unwrap().len(), 16384 + 40);
        // A forwarding node (here: a member node no slot is for) checks the envelope without opening it.
        let other = Seed::generate();
        let mut l = w.members.clone();
        l.nodes.push(crate::NodeEntry { name: "other".into(), key: fmt_key(&other.public()), addrs: vec![], names: vec![] });
        let p = env(&w, "a.alice", "a.bob", Mode::Private);
        p.check(&l, crate::now_millis()).unwrap();
        assert!(p.open(&other).unwrap().is_none());
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
        assert!(mk("all", "x|y").verify(&w.members, &pinned(&w.members), now, [&w.node]).is_ok(), "'|' in the thread is fine");
        assert!(mk("all|x", "y").verify(&w.members, &pinned(&w.members), now, [&w.node]).unwrap_err().to_string().contains("sender signature"));
        let mut other_network = w.members.clone();
        other_network.network.push_str("-other");
        assert!(mk("all", "x|y").verify(&other_network, &pinned(&other_network), now, [&w.node]).unwrap_err().to_string().contains("sender signature"));
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
        assert!(base.verify(&w.members, &pinned(&w.members), now, [&w.node]).is_ok());
        for len in [39, 1000 + 40, 1025 + 40, MAX_CIPHERTEXT + 1] {
            let mut e = base.clone();
            e.ciphertext = b64u(&vec![0; len]);
            assert!(e.check(&w.members, now).unwrap_err().to_string().contains("ciphertext length"), "{len}");
        }
        for n in [1, 3, 5] {
            let mut e = base.clone();
            e.keys.truncate(n.min(e.keys.len()));
            while e.keys.len() < n { e.keys.push(e.keys[0].clone()); }
            assert!(resign(e).check(&w.members, now).unwrap_err().to_string().contains("key list"), "{n} slots");
        }
        let mut e = base.clone();
        e.blobs = (0..MAX_BLOBS + 1).map(|i| format!("{i:064x}")).collect();
        assert!(resign(e).check(&w.members, now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.blobs = vec!["not-a-hash".into()];
        assert!(resign(e).check(&w.members, now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.keys[0].k = b64u(&[0u8; 4096]);
        assert!(resign(e).check(&w.members, now).unwrap_err().to_string().contains("wrapped key"));
        let mut e = base.clone();
        e.epk = b64u(&[0u8; 7]);
        assert!(resign(e).check(&w.members, now).unwrap_err().to_string().contains("epk"));
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
        let meta = r#"{"room":"dana/x","mentions":["bob"]}"#;
        let signed = post_digest_meta(&salt, "hi", &[], meta).unwrap();
        assert_ne!(signed, plain);
        assert_ne!(signed, post_digest_meta(&salt, "hi", &[], r#"{"room":"dana/x"}"#).unwrap());
    }

    #[test]
    fn roundtrip_through_json() {
        let w = world();
        let e = env(&w, "a.alice", "all", Mode::Members);
        let wire = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.signing_bytes(), e.signing_bytes());
        let (v, o) = back.verify(&w.members, &pinned(&w.members), crate::now_millis(), [&w.node]).unwrap();
        assert_eq!(v.sender_sub, "agent:a.alice@test");
        assert_eq!(o.body.text, "hi from a.alice");
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
        assert!(e.check(&w.members, now).unwrap_err().to_string().contains("not a member"));
        // public field changed after the node signed
        let mut e = env(&w, "a.alice", "all", Mode::Members);
        e.ts = crate::ts_from_millis(now - 5);
        assert!(e.check(&w.members, now).unwrap_err().to_string().contains("signature"));
        // ciphertext swapped: id no longer matches
        let mut e = env(&w, "a.alice", "all", Mode::Members);
        let other = env(&w, "a.alice", "all", Mode::Members);
        e.ciphertext = other.ciphertext;
        assert!(e.check(&w.members, now).unwrap_err().to_string().contains("hash"));
        // the same ciphertext under another node's or time's signature does not open (bound as associated data)
        let mut e = env(&w, "a.alice", "all", Mode::Members);
        e.ts = crate::ts_from_millis(now - 5);
        e.sig = b64u(&w.node.sign(&e.signing_bytes()));
        e.check(&w.members, now).unwrap();
        assert!(e.open(&w.node).is_err());
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
        let (dana, bob, carol) = (Seed::generate(), Seed::generate(), Seed::generate());
        let mut l = list(&[("b.carol", &carol)], &[&mac, &pod, &ops]);
        l.nodes[0].names = vec!["dana".into(), "eng.".into()];
        l.nodes[1].names = vec!["dana".into()];
        l.nodes[2].names = vec!["ops.".into()];
        l.validate().unwrap();
        let now = crate::now_millis();
        let ts = crate::ts_from_millis(now - 1000);
        let mac_cert = Cert::issue(&mac, "dana", &dana.public(), &ts);
        let pod_cert = Cert::issue(&pod, "dana", &dana.public(), &ts);
        let none = |_: &Cert| None;

        // A cert from a pinned node within its namespace is accepted, from the envelope alone.
        let agents = l.agents(std::slice::from_ref(&mac_cert), &none, now);
        let e = certified_env(&l, &agents, &mac, "dana", &dana, "all", Mode::Members, crate::now_ts(), Some(mac_cert.clone()));
        assert_eq!(e.verify(&l, &agents, now, [&mac]).unwrap().0.sender_sub, "agent:dana");
        assert!(e.verify(&l, &l.agents(&[], &none, now), now, [&mac]).unwrap_err().to_string().contains("no certificate"));

        let boundary = now - 1000 - crate::cert::CERTIFY_SKEW_MS;
        for (t, allowed) in [(boundary - 1, false), (boundary, true)] {
            let mail = certified_env(&l, &agents, &mac, "dana", &dana, "all", Mode::Members,
                                     crate::ts_from_millis(t), Some(mac_cert.clone()));
            let dated = l.agents(std::slice::from_ref(&mac_cert), &none, t);
            assert_eq!(mail.verify(&l, &dated, now, [&mac]).is_ok(), allowed);
            assert_eq!(mail.verify(&l, &agents, now, [&mac]).is_ok(), allowed, "writer using its current roster");
        }

        // Out of namespace: ops's node cannot vouch for eng.x, nor can an untrusted node.
        let rogue = Cert::issue(&ops, "eng.x", &bob.public(), &ts);
        assert!(!l.accepts(&rogue));
        assert!(!l.accepts(&Cert::issue(&Seed::generate(), "dana", &bob.public(), &ts)));
        let agents = l.agents(std::slice::from_ref(&rogue), &none, now);
        assert!(members::named(&agents, "eng.x").next().is_none());
        assert!(certified_env(&l, &agents, &ops, "eng.x", &bob, "all", Mode::Members, crate::now_ts(), Some(rogue))
            .verify(&l, &agents, now, [&ops]).is_err());

        // A pin takes precedence: a cert for a pinned name with another key does not count.
        let squat = Cert::issue(&mac, "b.carol", &bob.public(), &ts);
        let mut l2 = l.clone();
        l2.nodes[0].names.push("b.".into());
        let agents = l2.agents(&[squat], &none, now);
        assert_eq!(members::named(&agents, "b.carol").map(|a| a.key).collect::<Vec<_>>(), vec![carol.public()]);

        // Two homes: private mail to dana opens at both of its nodes, and at no other.
        let both = [mac_cert.clone(), pod_cert.clone()];
        let agents = l.agents(&both, &none, now);
        assert_eq!(members::named(&agents, "dana").count(), 1);
        let p = certified_env(&l, &agents, &pod, "dana", &dana, "b.carol", Mode::Private, crate::now_ts(), Some(pod_cert.clone()));
        p.verify(&l, &agents, now, [&pod]).unwrap();
        assert!(p.open(&mac).unwrap().is_some() && p.open(&pod).unwrap().is_some() && p.open(&dana).unwrap().is_some());
        assert!(p.open(&ops).unwrap().is_none());

        // Revocation by the mac counts only against the mac's cert, and only from its time on.
        let rev_at = now - 500;
        let mac_key = fmt_key(&mac.public());
        let revoked = |c: &Cert| (c.node == mac_key).then_some(rev_at);
        let early = crate::ts_from_millis(now - 800);
        let at = |t: i64| l.agents(std::slice::from_ref(&mac_cert), &revoked, t);
        let old = certified_env(&l, &at(now - 800), &mac, "dana", &dana, "all", Mode::Members, early, Some(mac_cert.clone()));
        assert!(old.verify(&l, &at(old.ts_ms()), now, [&mac]).is_ok(), "mail dated before the revocation still verifies");
        let new = certified_env(&l, &at(now), &mac, "dana", &dana, "all", Mode::Members, crate::now_ts(), Some(mac_cert.clone()));
        assert!(new.verify(&l, &at(new.ts_ms()), now, [&mac]).is_err(), "mail dated after it does not");
        let agents = l.agents(&both, &revoked, now);
        assert_eq!(members::named(&agents, "dana").next().unwrap().homes, vec![pod.public()],
                   "the pod's cert for the same key stays live");
    }
}
