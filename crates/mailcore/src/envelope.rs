//! The replicated unit. Header fields are clear (member nodes route and order on them); the body is encrypted to node
//! keys. A node signs every envelope it writes; the envelope carries the sender's attestation: the agent's own
//! signature with the certificate the writing node issued it, or the writing node's word for one of its own agents.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::addr;
use crate::cert::{agent_sub, live_certs, valid_name, Cert, KnownCerts};
use crate::crypto::{self, Wrapped};
use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::members::MemberList;
use crate::{b64u, b64u_decode, parse_ts};

pub const VERSION: u32 = 2;
pub const MAX_FIELD: usize = 120;
pub const MAX_PARENTS: usize = 16;
pub const MAX_CIPHERTEXT: usize = 512 * 1024;
pub const MAX_KEYS: usize = 1000;
/// Attachments per message (the API's limit).
pub const MAX_BLOBS: usize = 10;
/// An envelope dated further than this past the receiver's clock is refused (it will be fetched again later).
pub const FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;
const SIG_CONTEXT: &[u8] = b"agent-mail/envelope/v1\n";
const AD_CONTEXT: &str = "agent-mail/body/v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Content key wrapped to every node key on the member list (`MemberList::node_keys`).
    #[default]
    Members,
    /// Wrapped to the writing node and the nodes that certified the addressees (`private_recipients`).
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
    /// Signed by the sender's own Ed25519 key over `post_statement`: the header fields and `digest` = hex
    /// SHA-256(salt || text || 0x00 || comma-joined blob ids). The salt is in the encrypted body, so the digest cannot
    /// be used to guess short texts. `cert` binds `from` to `key` and is issued by the writing node.
    Agent { key: String, digest: String, sig: String, cert: Cert },
    /// The writing node vouches for one of its own agents (`from` is in its namespace and holds a certificate from it).
    Node,
}

impl Attest {
    pub fn kind(&self) -> &'static str {
        match self {
            Attest::Agent { .. } => "agent",
            Attest::Node => "node",
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
    /// The writing node's key.
    pub node: String,
    pub sig: String,
}

/// The encrypted part.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Body {
    pub text: String,
    /// Attachments: {id (blob id), name, type, size, key (b64url blob key)}, in the header's blobs order.
    #[serde(default)]
    pub files: Vec<serde_json::Value>,
    /// b64url salt of the sender's digest (Attest::Agent only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub salt: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    /// `agent:{name}@{writing node's name}`, with the name as certified.
    pub sender_sub: String,
    /// Always "agent".
    pub sender_kind: String,
    /// "agent" (signed by the sender's key) or "node" (vouched for by the writing node).
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
    /// Encrypts the body to `d.recipients` (fresh content key) and signs the envelope as `node`.
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
    /// attestation. `known` is the receiver's store (revocations, and the certificates a node attest needs).
    ///
    /// Agent attest: the certificate verifies against `list`, names `from`, binds `key`, was issued by the writing node
    /// (an agent writes through the node that certified it), the key is not revoked, and the post statement signature
    /// verifies. Node attest: `from` is in the writing node's namespace and has a live certificate from it in `known`
    /// (certificates sync before envelopes; a refused envelope is fetched again later).
    pub fn verify(&self, list: &MemberList, known: &dyn KnownCerts, now_ms: i64) -> Result<Verified> {
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
        let writer = list.node_by_key(&node).ok_or_else(|| anyhow!("written by a node that is not a member"))?;
        if !valid_name(&self.from) {
            bail!("from is not a valid agent name");
        }
        match &self.attest {
            Attest::Agent { key, digest, sig, cert } => {
                cert.verify(list).map_err(|e| anyhow!("sender certificate refused: {e}"))?;
                if !addr::same(&cert.name, &self.from) {
                    bail!("from ({}) is not the certificate's name ({})", self.from, cert.name);
                }
                let k = parse_key(key)?;
                if cert.agent_key()? != k {
                    bail!("signed by a key that is not the one {}'s certificate names", self.from);
                }
                if cert.node_key()? != node {
                    bail!("the sender's certificate is from another node (an agent writes through the node that certified it)");
                }
                if known.revoked(cert) {
                    bail!("{}'s key is revoked", self.from);
                }
                if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!("bad digest");
                }
                // The statement joins from, to and thread with '|'. With none in from or to (names never have one, and
                // the API never allows one in to) it splits one way only; otherwise a node could move text between to
                // and thread under the same signature (e.g. to "all", thread "x|y" re-labelled to "all|x", thread "y").
                if self.from.contains('|') || self.to.contains('|') {
                    bail!("from and to of a signed message cannot contain '|'");
                }
                let st = post_statement(&self.from, &self.to, &self.thread, self.mode, &self.ts, digest);
                let s = b64u_decode(sig).ok_or_else(|| anyhow!("bad sender signature"))?;
                // One encoding per signature: nodes recognize a replayed message by it (see agent_sig in the store).
                if b64u(&s) != *sig {
                    bail!("sender signature is not canonical base64url");
                }
                if !keys::verify(&k, st.as_bytes(), &s) {
                    bail!("sender signature does not verify");
                }
                Ok(Verified { sender_sub: agent_sub(&cert.name, &writer.name), sender_kind: "agent".into(), attest: "agent" })
            }
            Attest::Node => {
                if list.node_for_name(&self.from).map(|e| e.key.as_str()) != Some(writer.key.as_str()) {
                    bail!("{} is not in the names of the writing node {}", self.from, writer.name);
                }
                let certs = live_certs(known, list, &self.from, &node);
                let cert = certs.first().ok_or_else(|| {
                    anyhow!("{} has no known certificate from the writing node {} (certificates sync first; it is fetched again later)", self.from, writer.name)
                })?;
                Ok(Verified { sender_sub: agent_sub(&cert.name, &writer.name), sender_kind: "agent".into(), attest: "node" })
            }
        }
    }

    /// For readers, after decrypting: the body's attachments are exactly the header's blobs (each with an id and a
    /// key), and an agent-signed envelope's digest matches the body it carries.
    pub fn check_body(&self, body: &Body) -> Result<()> {
        let ids: Vec<String> = body.files.iter().filter_map(|f| f["id"].as_str().map(|s| s.to_string())).collect();
        if ids.len() != body.files.len() || ids != self.blobs || !body.files.iter().all(|f| f["key"].is_string()) {
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

/// Recipients of a private envelope written by the node `writer`: its own key, plus the node key of every live
/// certificate (valid against `list`, not `revoked` by its issuing node) whose name `to` addresses, deduped and sorted.
/// No agent keys.
/// `None` when no known agent matches `to` (the post is refused).
pub fn private_recipients(list: &MemberList, to: &str, writer: &PublicKey, certs: &[Cert], revoked: &dyn Fn(&Cert) -> bool) -> Option<Vec<PublicKey>> {
    let mut out: Vec<PublicKey> = certs
        .iter()
        .filter(|c| addr::addressed_to(to, &[c.name.as_str()]))
        .filter(|c| c.verify(list).is_ok())
        .filter(|c| c.agent_key().is_ok() && !revoked(c))
        .filter_map(|c| c.node_key().ok())
        .collect();
    if out.is_empty() {
        return None;
    }
    out.push(*writer);
    out.sort();
    out.dedup();
    Some(out)
}

pub fn is_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{CertSet, Revocation};
    use crate::members::tests::list;

    /// Three hosts: mac (names "a."), box (default namespace "box.") and far (names "c."), with agents a.alice and
    /// a.bob certified by mac, box.carol by box, c.dave by far.
    struct World {
        mac: Seed,
        boxn: Seed,
        far: Seed,
        alice: Seed,
        bob: Seed,
        members: MemberList,
        known: CertSet,
        alice_cert: Cert,
        bob_cert: Cert,
    }

    fn world() -> World {
        let (mac, boxn, far) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (alice, bob, carol, dave) = (Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate());
        let members = list(&[("mac", &mac, &["a."]), ("box", &boxn, &[]), ("far", &far, &["c."])]);
        let ts = crate::now_ts();
        let alice_cert = Cert::issue(&mac, "a.alice", &alice.public(), &ts);
        let bob_cert = Cert::issue(&mac, "a.bob", &bob.public(), &ts);
        let mut known = CertSet::default();
        for c in [alice_cert.clone(), bob_cert.clone(), Cert::issue(&boxn, "box.carol", &carol.public(), &ts), Cert::issue(&far, "c.dave", &dave.public(), &ts)] {
            known.add(c);
        }
        World { mac, boxn, far, alice, bob, members, known, alice_cert, bob_cert }
    }

    fn recipients(w: &World, mode: Mode, to: &str, writer: &Seed) -> Vec<PublicKey> {
        match mode {
            Mode::Members => w.members.node_keys(),
            Mode::Private => private_recipients(&w.members, to, &writer.public(), &w.known.certs, &|c| w.known.is_revoked(c)).expect("someone matches"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn seal(w: &World, from: &str, to: &str, mode: Mode, body: &Body, attest: Attest, ts: String, writer: &Seed) -> Envelope {
        Envelope::seal(
            Draft { thread: "t", parents: vec![], ts, from, to, mode, body, blobs: vec![], attest, recipients: &recipients(w, mode, to, writer) },
            writer,
        )
        .unwrap()
    }

    /// Written by `writer` with the writing node's word for `from`.
    fn node_env(w: &World, from: &str, to: &str, mode: Mode, writer: &Seed) -> Envelope {
        let body = Body { text: format!("hi from {from}"), ..Default::default() };
        seal(w, from, to, mode, &body, Attest::Node, crate::now_ts(), writer)
    }

    /// Signed by `signer` as `from` with `cert`, written by `writer`.
    fn signed_env(w: &World, from: &str, signer: &Seed, cert: &Cert, writer: &Seed, text: &str) -> Envelope {
        let ts = crate::now_ts();
        let salt = crate::random_bytes::<16>();
        let digest = post_digest(&salt, text, &[]);
        let st = post_statement(from, "all", "t", Mode::Members, &ts, &digest);
        let attest = Attest::Agent { key: fmt_key(&signer.public()), digest, sig: b64u(&signer.sign(st.as_bytes())), cert: cert.clone() };
        let body = Body { text: text.into(), files: vec![], salt: b64u(&salt) };
        seal(w, from, "all", Mode::Members, &body, attest, ts, writer)
    }

    #[test]
    fn agent_attest_verifies_for_a_second_reader() {
        let w = world();
        let now = crate::now_millis();
        let e = signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "signed by alice");
        // box knows no certificates at all: the envelope carries alice's.
        let v = e.verify(&w.members, &CertSet::default(), now).unwrap();
        assert_eq!((v.attest, v.sender_sub.as_str(), v.sender_kind.as_str()), ("agent", "agent:a.alice@mac", "agent"));
        let body = e.open(&w.boxn).unwrap().unwrap();
        e.check_body(&body).unwrap();
        // Bob's key claiming to be alice, with alice's certificate; and with his own.
        let e = signed_env(&w, "a.alice", &w.bob, &w.alice_cert, &w.mac, "forged");
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("not the one a.alice's certificate names"));
        let e = signed_env(&w, "a.alice", &w.bob, &w.bob_cert, &w.mac, "forged");
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("not the certificate's name"));
        // A certificate for a name in nobody's namespace (signed by mac).
        let stranger = Seed::generate();
        let c = Cert::issue(&w.mac, "x.stranger", &stranger.public(), &crate::now_ts());
        let e = signed_env(&w, "x.stranger", &stranger, &c, &w.mac, "who");
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("certificate refused"));
        // A header changed by the node after the sender signed (re-signed by the node so only the agent sig breaks).
        let mut e = signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "to all");
        e.to = "a.bob".into();
        e.sig = b64u(&w.mac.sign(&e.signing_bytes()));
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("sender signature"));
        // A body swapped by the node under alice's signed digest: verify passes (header intact), check_body refuses.
        let good = signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "original");
        let mut body = good.open(&w.mac).unwrap().unwrap();
        body.text = "tampered".into();
        assert!(good.check_body(&body).unwrap_err().to_string().contains("digest"));
    }

    #[test]
    fn agent_writes_through_the_node_that_certified_it() {
        let w = world();
        let e = signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.boxn, "via box");
        assert!(e.verify(&w.members, &w.known, crate::now_millis()).unwrap_err().to_string().contains("from another node"));
    }

    #[test]
    fn node_attest() {
        let w = world();
        let now = crate::now_millis();
        let v = node_env(&w, "a.alice", "all", Mode::Members, &w.mac).verify(&w.members, &w.known, now).unwrap();
        assert_eq!((v.attest, v.sender_sub.as_str()), ("node", "agent:a.alice@mac"));
        // Names compare like mail addresses; the certified spelling is the one shown.
        assert_eq!(node_env(&w, "A.Alice", "all", Mode::Members, &w.mac).verify(&w.members, &w.known, now).unwrap().sender_sub, "agent:a.alice@mac");
        // box vouching for a name in mac's namespace (and in nobody's).
        for from in ["a.alice", "z.nobody"] {
            let e = node_env(&w, from, "all", Mode::Members, &w.boxn);
            assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("not in the names of the writing node box"), "{from}");
        }
        // In mac's namespace but not certified (or certificates not synced yet).
        let e = node_env(&w, "a.zed", "all", Mode::Members, &w.mac);
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("no known certificate"));
        let e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        assert!(e.verify(&w.members, &CertSet::default(), now).unwrap_err().to_string().contains("no known certificate"));
        // A certificate for the name from another node does not count (box certifying a mac name never verifies).
        let mut known = CertSet::default();
        known.add(Cert::issue(&w.boxn, "a.alice", &w.alice.public(), &crate::now_ts()));
        assert!(e.verify(&w.members, &known, now).is_err());
        // Not a valid name at all.
        for from in ["all", "a.", "a b"] {
            let e = node_env(&w, from, "all", Mode::Members, &w.mac);
            assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("valid agent name"), "{from}");
        }
    }

    #[test]
    fn revoked_key_is_refused_and_the_name_can_be_certified_again() {
        let mut w = world();
        let now = crate::now_millis();
        let e = signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "before");
        e.verify(&w.members, &w.known, now).unwrap();
        let r = Revocation::sign(&w.mac, "a.alice", &w.alice.public(), &crate::now_ts());
        r.verify(&w.members).unwrap();
        w.known.revoke(&r).unwrap();
        let e = signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "after");
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("revoked"));
        let e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("no known certificate"));
        // A new key for the same name.
        let fresh = Seed::generate();
        let c = Cert::issue(&w.mac, "a.alice", &fresh.public(), &crate::now_ts());
        w.known.add(c.clone());
        signed_env(&w, "a.alice", &fresh, &c, &w.mac, "new key").verify(&w.members, &w.known, now).unwrap();
        node_env(&w, "a.alice", "all", Mode::Members, &w.mac).verify(&w.members, &w.known, now).unwrap();
    }

    #[test]
    fn another_nodes_revocation_does_not_count() {
        // box signs a revocation of alice's key under a name in its own namespace. It verifies, but it is box's word
        // about box's certificates: mac's certificate for alice stays live, so her mail and her private mail still go.
        let mut w = world();
        let now = crate::now_millis();
        let r = Revocation::sign(&w.boxn, "box.alice", &w.alice.public(), &crate::now_ts());
        r.verify(&w.members).unwrap();
        w.known.revoke(&r).unwrap();
        signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "still here").verify(&w.members, &w.known, now).unwrap();
        node_env(&w, "a.alice", "all", Mode::Members, &w.mac).verify(&w.members, &w.known, now).unwrap();
        let rcp = private_recipients(&w.members, "a.alice", &w.boxn.public(), &w.known.certs, &|c| w.known.is_revoked(c));
        assert!(rcp.unwrap().contains(&w.mac.public()));
    }

    #[test]
    fn signed_statement_fields_cannot_shift() {
        let w = world();
        let now = crate::now_millis();
        let ts = crate::now_ts();
        let salt = crate::random_bytes::<16>();
        let digest = post_digest(&salt, "hi", &[]);
        // alice signs to "all", thread "x|y".
        let st = post_statement("a.alice", "all", "x|y", Mode::Members, &ts, &digest);
        let attest = Attest::Agent { key: fmt_key(&w.alice.public()), digest, sig: b64u(&w.alice.sign(st.as_bytes())), cert: w.alice_cert.clone() };
        let body = Body { text: "hi".into(), files: vec![], salt: b64u(&salt) };
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
                    recipients: &w.members.node_keys(),
                },
                &w.mac,
            )
            .unwrap()
        };
        assert!(mk("all", "x|y").verify(&w.members, &w.known, now).is_ok(), "'|' in the thread is fine");
        // The same statement re-split by the node: to "all|x", thread "y".
        assert_eq!(post_statement("a.alice", "all|x", "y", Mode::Members, &ts, "d"), post_statement("a.alice", "all", "x|y", Mode::Members, &ts, "d"));
        assert!(mk("all|x", "y").verify(&w.members, &w.known, now).unwrap_err().to_string().contains("'|'"));
    }

    #[test]
    fn late_node_reads_through_a_grant() {
        let w = world();
        let e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        let late = Seed::generate();
        assert!(e.open(&late).unwrap().is_none());
        let g = e.grant(&w.boxn, &late.public()).unwrap().unwrap();
        assert_eq!(e.open_grant(&g, &late).unwrap().text, "hi from a.alice");
        assert!(e.open_grant(&g, &w.boxn).is_err());
        assert!(e.grant(&late, &w.boxn.public()).unwrap().is_none());
    }

    #[test]
    fn refuses_unbounded_fields() {
        let w = world();
        let now = crate::now_millis();
        let resign = |mut e: Envelope| {
            e.sig = b64u(&w.mac.sign(&e.signing_bytes()));
            e
        };
        let base = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        assert!(base.verify(&w.members, &w.known, now).is_ok());
        let mut e = base.clone();
        e.blobs = (0..MAX_BLOBS + 1).map(|i| format!("{i:064x}")).collect();
        assert!(resign(e).verify(&w.members, &w.known, now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.blobs = vec!["not-a-hash".into()];
        assert!(resign(e).verify(&w.members, &w.known, now).unwrap_err().to_string().contains("blobs"));
        let mut e = base.clone();
        e.keys[0].k = b64u(&[0u8; 4096]);
        assert!(resign(e).verify(&w.members, &w.known, now).unwrap_err().to_string().contains("wrapped key"));
        let mut e = base.clone();
        e.epk = b64u(&[0u8; 7]);
        assert!(resign(e).verify(&w.members, &w.known, now).unwrap_err().to_string().contains("epk"));
        let mut e = base.clone();
        e.v = 1;
        assert!(resign(e).verify(&w.members, &w.known, now).unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn roundtrip_through_json() {
        let w = world();
        for e in [node_env(&w, "a.alice", "all", Mode::Members, &w.mac), signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "x")] {
            let wire = serde_json::to_string(&e).unwrap();
            assert!(wire.starts_with(r#"{"v":2,"#), "{wire}");
            let back: Envelope = serde_json::from_str(&wire).unwrap();
            assert_eq!(back, e);
            assert_eq!(back.signing_bytes(), e.signing_bytes());
            let v = back.verify(&w.members, &w.known, crate::now_millis()).unwrap();
            assert_eq!(v.sender_sub, "agent:a.alice@mac");
            assert!(back.open(&w.far).unwrap().is_some());
        }
        let wire = serde_json::to_value(node_env(&w, "a.alice", "all", Mode::Members, &w.mac)).unwrap();
        assert_eq!(wire["attest"], serde_json::json!({"kind": "node"}));
        let wire = serde_json::to_value(signed_env(&w, "a.alice", &w.alice, &w.alice_cert, &w.mac, "x")).unwrap();
        assert_eq!(wire["attest"]["kind"], "agent");
        assert_eq!(wire["attest"]["cert"], serde_json::to_value(&w.alice_cert).unwrap());
    }

    #[test]
    fn refuses_forged_and_non_member() {
        let w = world();
        let now = crate::now_millis();
        // Written by a node not on the member list.
        let mut e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        let stranger = Seed::generate();
        e.node = fmt_key(&stranger.public());
        e.sig = b64u(&stranger.sign(&e.signing_bytes()));
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("not a member"));
        // Header changed after signing.
        let mut e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        e.thread = "other".into();
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("signature"));
        // Ciphertext swapped: id no longer matches.
        let mut e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        e.ciphertext = node_env(&w, "a.alice", "all", Mode::Members, &w.mac).ciphertext;
        assert!(e.verify(&w.members, &w.known, now).unwrap_err().to_string().contains("hash"));
    }

    #[test]
    fn members_vs_private_reading() {
        let w = world();
        let m = node_env(&w, "a.alice", "a.bob", Mode::Members, &w.mac);
        for k in [&w.mac, &w.boxn, &w.far] {
            assert!(m.open(k).unwrap().is_some(), "members mode opens for every node");
        }
        assert!(m.open(&w.alice).unwrap().is_none(), "no agent keys");
        assert!(m.open(&Seed::generate()).unwrap().is_none());

        let rcp = |to: &str, writer: &Seed| private_recipients(&w.members, to, &writer.public(), &w.known.certs, &|c| w.known.is_revoked(c));
        let mut both = vec![w.mac.public(), w.boxn.public()];
        both.sort();
        assert_eq!(rcp("box.carol", &w.mac), Some(both.clone()), "the addressee's node and the writer");
        assert_eq!(rcp("a.bob", &w.mac), Some(vec![w.mac.public()]), "same host: the writer only");
        assert_eq!(rcp("BOX.CAROL, box.carol", &w.mac), Some(both.clone()), "deduped");
        assert_eq!(rcp("box.", &w.mac), Some(both), "a team prefix reaches its nodes");
        assert_eq!(rcp("a.nobody", &w.mac), None, "no known agent matches");
        assert_eq!(rcp("all", &w.mac).unwrap().len(), 3);

        let p = node_env(&w, "a.alice", "box.carol", Mode::Private, &w.mac);
        assert!(p.open(&w.mac).unwrap().is_some(), "the writing node reads it");
        assert!(p.open(&w.boxn).unwrap().is_some(), "the addressee's node reads it");
        assert!(p.open(&w.far).unwrap().is_none(), "another node does not");
        assert!(p.open(&w.alice).unwrap().is_none(), "no agent keys");
        p.verify(&w.members, &w.known, crate::now_millis()).unwrap();

        // A revoked addressee is never a recipient; a certificate from a node no longer on the list does not count.
        let mut known = w.known.clone();
        let carol = known.certs.iter().find(|c| c.name == "box.carol").unwrap().clone();
        known.revoke(&Revocation::sign(&w.boxn, "box.carol", &carol.agent_key().unwrap(), &crate::now_ts())).unwrap();
        assert_eq!(private_recipients(&w.members, "box.carol", &w.mac.public(), &known.certs, &|c| known.is_revoked(c)), None);
        let smaller = list(&[("mac", &w.mac, &["a."]), ("far", &w.far, &["c."])]);
        assert_eq!(private_recipients(&smaller, "box.carol", &w.mac.public(), &w.known.certs, &|_| false), None);
    }

    #[test]
    fn body_attachments_must_be_the_blobs() {
        let w = world();
        let e = node_env(&w, "a.alice", "all", Mode::Members, &w.mac);
        let body = e.open(&w.mac).unwrap().unwrap();
        e.check_body(&body).unwrap();
        let id = format!("{:064x}", 1);
        let mut b = body.clone();
        b.files = vec![serde_json::json!({"id": id, "name": "f", "type": "text/plain", "size": 1})];
        assert!(e.check_body(&b).is_err(), "an attachment the header does not list");
        let mut e2 = e.clone();
        e2.blobs = vec![id.clone()];
        assert!(e2.check_body(&b).unwrap_err().to_string().contains("blobs"), "an attachment without a key");
        b.files[0]["key"] = serde_json::json!("k");
        e2.check_body(&b).unwrap();
    }
}
