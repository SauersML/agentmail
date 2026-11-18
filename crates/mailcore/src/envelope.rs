//! The replicated unit. Header fields are clear (member nodes route and order on them); the body is encrypted.
//! A node signs every envelope it writes; the envelope carries the sender's attestation (an aid1 token, or for history
//! imported from the old server, the bridge's statement).

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

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
    /// The sender's aid1 token, minted by the home for audience "mail".
    Aid1 { token: String },
    /// A message copied from the old server (phase 2 bridge). `old_id` is its number there; the envelope is signed by
    /// a bridge key the member list names under `bridges`.
    Import { old_id: u64, sub: String, verified: bool },
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
    pub attest: Attest,
    /// The writing node's key (or the bridge's, for imports).
    pub node: String,
    pub sig: String,
}

/// The encrypted part.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Body {
    pub text: String,
    /// Phase 2: file references (content hashes). Always empty in phase 1.
    #[serde(default)]
    pub files: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    pub sender_sub: String,
    pub sender_kind: String,
    /// Some(old id) for history imported from the old server.
    pub imported: Option<u64>,
    /// False only for imported rows the old server marked unverified.
    pub verified: bool,
}

pub struct Draft<'a> {
    pub thread: &'a str,
    pub parents: Vec<String>,
    pub ts: String,
    pub from: &'a str,
    pub to: &'a str,
    pub mode: Mode,
    pub body: &'a Body,
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
                Ok(Verified { sender_sub: p.sub, sender_kind: p.kind, imported: None, verified: true })
            }
            Attest::Import { old_id, sub, verified } => {
                if !members.is_bridge(&node) {
                    bail!("import signed by a key that is not a member bridge");
                }
                Ok(Verified { sender_sub: sub.clone(), sender_kind: String::new(), imported: Some(*old_id), verified: *verified })
            }
        }
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
        let body = Body { text: format!("hi from {from}"), files: vec![] };
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
                attest: Attest::Aid1 { token },
                recipients: &recipients,
            },
            &w.node,
        )
        .unwrap()
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
