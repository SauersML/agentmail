//! Agent certificates. A member node binds an agent name in its namespace (see `members`) to the agent's own Ed25519
//! key; every node accepts the binding while the issuing node is on the member list and the name is in its namespace.
//! A revocation, signed by a node for a name in its namespace, kills that node's certificates for an agent key
//! everywhere: no sign-in, no new agent-attested mail from it, never a recipient of private mail. It counts only against
//! certificates from the node that signed it, so one host cannot revoke another host's agents. The issuing node may
//! then certify a new key for the name.
//!
//! Certificates are known by (issuing node, agent key): any member node has seen other agents' public keys, so a
//! certificate one node signs for a key never displaces another node's certificate for the same key.
//!
//! Both are signed by the node over a context string and the JSON of the struct with `sig` empty (field order fixed by
//! the struct, every value a string or number), so re-serializing a parsed one gives the same bytes on every node.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::addr;
use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::members::MemberList;
use crate::{b64u, b64u_decode, parse_ts};

pub const VERSION: u32 = 1;
/// Longest agent name.
pub const MAX_NAME: usize = 48;
/// How far an issuance proof's ts may be from the node's clock.
pub const CERTIFY_SKEW_MS: i64 = 300_000;
const CERT_CONTEXT: &[u8] = b"agent-mail/agent-cert/v1\n";
const REVOKE_CONTEXT: &[u8] = b"agent-mail/agent-revoke/v1\n";

/// Agent name rules: 1-48 characters of A-Z a-z 0-9 . _ -, not starting or ending with '.', not `all` (any case).
/// So a name never contains '|', ',', '/', '*' or whitespace.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.eq_ignore_ascii_case("all")
}

/// The sender id shown for an agent: `agent:{name}@{node name}`.
pub fn agent_sub(name: &str, node_name: &str) -> String {
    format!("agent:{name}@{node_name}")
}

/// What an agent signs with its key to ask `node` for a certificate (the issuance proof). `key` and `node` are
/// `ed25519:…` strings, `ts` a canonical envelope timestamp. No field can contain '|', so it splits one way only.
pub fn certify_statement(name: &str, key: &str, node: &str, ts: &str) -> String {
    format!("agent-mail-certify|v1|{name}|{key}|{node}|{ts}")
}

/// Checks an issuance request made to the node `node` (body `{name, key, ts, sig}`): the name is valid, the key is a
/// canonical `ed25519:` key, ts is canonical and within 300 s of `now_ms`, and `sig` (canonical base64url) is the
/// key's signature over `certify_statement`. Returns the agent key. The namespace and what is already certified are
/// the node's to check. Every error is a bad request.
pub fn check_issuance(name: &str, key: &str, ts: &str, sig: &str, node: &PublicKey, now_ms: i64) -> Result<PublicKey> {
    if !valid_name(name) {
        bail!("{:?} is not a valid agent name (1-48 of A-Z a-z 0-9 . _ -, not starting or ending with '.', not all)", trunc(name));
    }
    let k = parse_key(key).map_err(|e| anyhow!("key: {e}"))?;
    if fmt_key(&k) != key {
        bail!("key must be ed25519:<base64url of 32 bytes, no padding>");
    }
    let t = parse_ts(ts).ok_or_else(|| anyhow!("ts must be YYYY-MM-DDTHH:MM:SS.mmmZ"))?;
    if (t - now_ms).abs() > CERTIFY_SKEW_MS {
        bail!("ts is more than 5 minutes from the node's clock");
    }
    let s = canonical_sig(sig).ok_or_else(|| anyhow!("sig must be a canonical base64url Ed25519 signature"))?;
    if !keys::verify(&k, certify_statement(name, key, &fmt_key(node), ts).as_bytes(), &s) {
        bail!("sig does not verify: sign agent-mail-certify|v1|NAME|KEY|NODE|TS with the key");
    }
    Ok(k)
}

fn canonical_sig(sig: &str) -> Option<Vec<u8>> {
    b64u_decode(sig).filter(|s| s.len() == 64 && b64u(s) == sig)
}

fn trunc(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}

/// The checks a certificate and a revocation share: version, name, keys, timestamp, the node is on the list and the
/// name is in its namespace, and the node's signature (canonical, verify_strict).
#[allow(clippy::too_many_arguments)]
fn check_signed(what: &str, v: u32, name: &str, key: &str, node: &str, ts: &str, sig: &str, bytes: &[u8], list: &MemberList) -> Result<()> {
    if v != VERSION {
        bail!("unsupported {what} version {v}");
    }
    if !valid_name(name) {
        bail!("{what} name {:?} is not a valid agent name", trunc(name));
    }
    parse_key(key).map_err(|e| anyhow!("{what} key: {e}"))?;
    let n = parse_key(node).map_err(|e| anyhow!("{what} node: {e}"))?;
    if parse_ts(ts).is_none() {
        bail!("{what} time is not YYYY-MM-DDTHH:MM:SS.mmmZ");
    }
    let entry = list.node_by_key(&n).ok_or_else(|| anyhow!("{what} is from a node that is not on the member list"))?;
    if list.node_for_name(name).map(|e| e.key.as_str()) != Some(entry.key.as_str()) {
        bail!("{what}: {} is not in the names of node {} ({})", trunc(name), entry.name, entry.namespace().join(", "));
    }
    let s = canonical_sig(sig).ok_or_else(|| anyhow!("{what} signature is not a canonical base64url signature"))?;
    if !keys::verify(&n, bytes, &s) {
        bail!("{what} signature does not verify");
    }
    Ok(())
}

fn signing_bytes<T: Serialize>(context: &[u8], value: &T) -> Vec<u8> {
    let mut out = context.to_vec();
    out.extend(serde_json::to_vec(value).expect("json"));
    out
}

/// A node's binding of an agent name to the agent's key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cert {
    pub v: u32,
    pub name: String,
    /// The agent's Ed25519 key.
    pub key: String,
    /// The issuing node's key.
    pub node: String,
    /// When the node issued it (canonical envelope timestamp).
    pub issued: String,
    #[serde(default)]
    pub sig: String,
}

impl Cert {
    /// Signs a certificate for `name` and `key` as the node `node`. The caller has checked the issuance request
    /// (`check_issuance`), the namespace and what this node already certified.
    pub fn issue(node: &Seed, name: &str, key: &PublicKey, issued: &str) -> Cert {
        let mut c = Cert { v: VERSION, name: name.into(), key: fmt_key(key), node: fmt_key(&node.public()), issued: issued.into(), sig: String::new() };
        c.sig = b64u(&node.sign(&c.signing_bytes()));
        c
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.sig.clear();
        signing_bytes(CERT_CONTEXT, &c)
    }

    /// Valid against `list`: version 1, valid name, `node` is on the list and the name is in its namespace (dropping a
    /// node from the list, or moving the name to another node, makes its certificates invalid), and the signature
    /// verifies. Revocation is not checked here: that needs the receiver's store (see `KnownCerts`).
    pub fn verify(&self, list: &MemberList) -> Result<()> {
        check_signed("certificate", self.v, &self.name, &self.key, &self.node, &self.issued, &self.sig, &self.signing_bytes(), list)
    }

    pub fn agent_key(&self) -> Result<PublicKey> {
        parse_key(&self.key)
    }

    pub fn node_key(&self) -> Result<PublicKey> {
        parse_key(&self.node)
    }
}

/// A node's statement that an agent key is dead.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    pub v: u32,
    pub name: String,
    /// The revoked agent key.
    pub key: String,
    /// The revoking node's key.
    pub node: String,
    pub ts: String,
    #[serde(default)]
    pub sig: String,
}

impl Revocation {
    pub fn sign(node: &Seed, name: &str, key: &PublicKey, ts: &str) -> Revocation {
        let mut r = Revocation { v: VERSION, name: name.into(), key: fmt_key(key), node: fmt_key(&node.public()), ts: ts.into(), sig: String::new() };
        r.sig = b64u(&node.sign(&r.signing_bytes()));
        r
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut r = self.clone();
        r.sig.clear();
        signing_bytes(REVOKE_CONTEXT, &r)
    }

    /// Valid against `list`: version 1, valid name, `node` is on the list and the name is in its namespace, and the
    /// signature verifies.
    pub fn verify(&self, list: &MemberList) -> Result<()> {
        check_signed("revocation", self.v, &self.name, &self.key, &self.node, &self.ts, &self.sig, &self.signing_bytes(), list)
    }

    pub fn agent_key(&self) -> Result<PublicKey> {
        parse_key(&self.key)
    }

    pub fn node_key(&self) -> Result<PublicKey> {
        parse_key(&self.node)
    }

    /// Whether this revocation counts against `cert`: the same agent key and the same issuing node. A node's
    /// revocation never touches another node's certificates.
    pub fn revokes(&self, cert: &Cert) -> bool {
        match (self.agent_key(), self.node_key(), cert.agent_key(), cert.node_key()) {
            (Ok(rk), Ok(rn), Ok(ck), Ok(cn)) => rk == ck && rn == cn,
            _ => false,
        }
    }
}

/// What a node knows about certificates (its store answers). Used by `Envelope::verify` and `agent_token::verify`.
pub trait KnownCerts {
    /// Whether a valid revocation of `cert` is known: one signed by the certificate's issuing node for its agent key
    /// (`Revocation::revokes`). Revocations from other nodes never count against it.
    fn revoked(&self, cert: &Cert) -> bool;
    /// The known certificates whose name is `name` (compared with `addr::same`), from any node, revoked or not.
    /// Callers check each one again (`live_certs`), so returning extra ones is harmless.
    fn certs_for(&self, name: &str) -> Vec<Cert>;
}

/// The certificates for `name` that count now: issued by `node`, valid against `list`, not revoked by `node`.
pub fn live_certs(known: &dyn KnownCerts, list: &MemberList, name: &str, node: &PublicKey) -> Vec<Cert> {
    known
        .certs_for(name)
        .into_iter()
        .filter(|c| addr::same(&c.name, name))
        .filter(|c| c.node_key().ok().as_ref() == Some(node))
        .filter(|c| c.verify(list).is_ok())
        .filter(|c| c.agent_key().is_ok() && !known.revoked(c))
        .collect()
}

/// An in-memory `KnownCerts` (tests, small tools), keyed like a node's store: one certificate per (issuing node,
/// agent key), the first one kept, and revocations by (revoking node, agent key). Checks happen at use.
#[derive(Clone, Debug, Default)]
pub struct CertSet {
    pub certs: Vec<Cert>,
    /// (revoking node, agent key)
    pub revoked: BTreeSet<(PublicKey, PublicKey)>,
}

impl CertSet {
    /// Adds `c` unless a certificate from the same node for the same key is already held. Another node's certificate
    /// for that key is a different entry, so it never blocks this one.
    pub fn add(&mut self, c: Cert) {
        let id = (c.node_key().ok(), c.agent_key().ok());
        if !self.certs.iter().any(|h| (h.node_key().ok(), h.agent_key().ok()) == id) {
            self.certs.push(c);
        }
    }

    pub fn revoke(&mut self, r: &Revocation) -> Result<()> {
        self.revoked.insert((r.node_key()?, r.agent_key()?));
        Ok(())
    }

    pub fn is_revoked(&self, cert: &Cert) -> bool {
        match (cert.node_key(), cert.agent_key()) {
            (Ok(n), Ok(k)) => self.revoked.contains(&(n, k)),
            _ => false,
        }
    }
}

impl KnownCerts for CertSet {
    fn revoked(&self, cert: &Cert) -> bool {
        self.is_revoked(cert)
    }

    fn certs_for(&self, name: &str) -> Vec<Cert> {
        self.certs.iter().filter(|c| addr::same(&c.name, name)).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::members::tests::list;

    const TS: &str = "2026-11-25T19:00:00.000Z";

    #[test]
    fn cert_signs_verifies_and_round_trips() {
        let (mac, agent) = (Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml.", "hypha"])]);
        let c = Cert::issue(&mac, "sauersml.lead", &agent.public(), TS);
        c.verify(&l).unwrap();
        assert_eq!(c.agent_key().unwrap(), agent.public());
        let wire = serde_json::to_string(&c).unwrap();
        assert!(wire.starts_with(r#"{"v":1,"name":"sauersml.lead","key":"ed25519:"#), "{wire}");
        let back: Cert = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, c);
        back.verify(&l).unwrap();
        // Any edited field breaks the signature.
        for edit in [
            |c: &mut Cert| c.name = "sauersml.other".into(),
            |c: &mut Cert| c.key = fmt_key(&Seed::generate().public()),
            |c: &mut Cert| c.issued = "2026-11-25T19:00:01.000Z".into(),
        ] {
            let mut e = c.clone();
            edit(&mut e);
            assert!(e.verify(&l).unwrap_err().to_string().contains("does not verify"));
        }
        // A non-canonical signature encoding, a wrong version, a bad name or timestamp.
        let mut e = c.clone();
        e.sig.push('=');
        assert!(e.verify(&l).unwrap_err().to_string().contains("canonical"));
        let mut e = c.clone();
        e.v = 2;
        assert!(e.verify(&l).is_err());
        assert!(Cert::issue(&mac, "sauersml.", &agent.public(), TS).verify(&l).unwrap_err().to_string().contains("valid agent name"));
        assert!(Cert::issue(&mac, "hypha", &agent.public(), "yesterday").verify(&l).unwrap_err().to_string().contains("time"));
    }

    #[test]
    fn cert_from_a_non_member_node_is_refused() {
        let (mac, stranger, agent) = (Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml."])]);
        let c = Cert::issue(&stranger, "sauersml.lead", &agent.public(), TS);
        assert!(c.verify(&l).unwrap_err().to_string().contains("not on the member list"));
        // The same holds once a node is dropped from the list: its certificates stop counting.
        let c = Cert::issue(&mac, "sauersml.lead", &agent.public(), TS);
        let other = Seed::generate();
        assert!(c.verify(&list(&[("box", &other, &["sauersml."])])).is_err());
    }

    #[test]
    fn cert_outside_the_issuing_nodes_namespace_is_refused() {
        let (mac, boxn, agent) = (Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml.", "hypha"]), ("box", &boxn, &[])]);
        // mac certifying a name in box's namespace, and a name in nobody's.
        for name in ["box.worker", "will.orchestrator", "hypha.x"] {
            let c = Cert::issue(&mac, name, &agent.public(), TS);
            assert!(c.verify(&l).unwrap_err().to_string().contains("not in the names of node mac"), "{name}");
        }
        Cert::issue(&boxn, "box.worker", &agent.public(), TS).verify(&l).unwrap();
        Cert::issue(&mac, "HYPHA", &agent.public(), TS).verify(&l).unwrap();
    }

    #[test]
    fn revocation_signs_and_verifies() {
        let (mac, boxn, agent) = (Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml."]), ("box", &boxn, &[])]);
        let r = Revocation::sign(&mac, "sauersml.lead", &agent.public(), TS);
        r.verify(&l).unwrap();
        let wire = serde_json::to_string(&r).unwrap();
        assert!(wire.starts_with(r#"{"v":1,"name":"sauersml.lead","key":"ed25519:"#), "{wire}");
        assert_eq!(serde_json::from_str::<Revocation>(&wire).unwrap(), r);
        // Another node cannot revoke a name outside its namespace; a stranger cannot revoke at all.
        assert!(Revocation::sign(&boxn, "sauersml.lead", &agent.public(), TS).verify(&l).unwrap_err().to_string().contains("not in the names"));
        assert!(Revocation::sign(&Seed::generate(), "sauersml.lead", &agent.public(), TS).verify(&l).is_err());
        // A certificate's signature is not a revocation's (different context).
        let c = Cert::issue(&mac, "sauersml.lead", &agent.public(), TS);
        let forged = Revocation { v: 1, name: c.name, key: c.key, node: c.node, ts: c.issued, sig: c.sig };
        assert!(forged.verify(&l).unwrap_err().to_string().contains("does not verify"));
    }

    #[test]
    fn issuance_proof() {
        let (mac, agent) = (Seed::generate(), Seed::generate());
        let now = crate::parse_ts(TS).unwrap();
        let key = fmt_key(&agent.public());
        let st = certify_statement("sauersml.lead", &key, &fmt_key(&mac.public()), TS);
        assert_eq!(st, format!("agent-mail-certify|v1|sauersml.lead|{key}|{}|{TS}", fmt_key(&mac.public())));
        let sig = b64u(&agent.sign(st.as_bytes()));
        assert_eq!(check_issuance("sauersml.lead", &key, TS, &sig, &mac.public(), now).unwrap(), agent.public());
        // Signed for another node, by another key, too far from the clock, a bad name, a non-canonical key.
        assert!(check_issuance("sauersml.lead", &key, TS, &sig, &Seed::generate().public(), now).is_err());
        let other = b64u(&Seed::generate().sign(st.as_bytes()));
        assert!(check_issuance("sauersml.lead", &key, TS, &other, &mac.public(), now).unwrap_err().to_string().contains("does not verify"));
        assert!(check_issuance("sauersml.lead", &key, TS, &sig, &mac.public(), now + 301_000).unwrap_err().to_string().contains("5 minutes"));
        assert!(check_issuance("all", &key, TS, &sig, &mac.public(), now).unwrap_err().to_string().contains("valid agent name"));
        assert!(check_issuance("sauersml.lead", &format!("{key}="), TS, &sig, &mac.public(), now).is_err());
        assert!(check_issuance("sauersml.lead", &key, TS, &format!("{sig}="), &mac.public(), now).unwrap_err().to_string().contains("canonical"));
    }

    #[test]
    fn live_certs_skip_revoked_foreign_and_stale() {
        let (mac, boxn, k1, k2) = (Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml."]), ("box", &boxn, &[])]);
        let mut known = CertSet::default();
        known.add(Cert::issue(&mac, "sauersml.lead", &k1.public(), TS));
        known.add(Cert::issue(&boxn, "sauersml.lead", &k2.public(), TS)); // outside box's names: never counts
        known.add(Cert::issue(&mac, "sauersml.lead", &k1.public(), TS)); // a duplicate
        known.add(Cert::issue(&mac, "sauersml.lead", &k1.public(), "2026-11-25T19:00:05.000Z")); // same (node, key)
        assert_eq!(known.certs.len(), 2);
        let live = live_certs(&known, &l, "SauersML/Lead", &mac.public());
        assert_eq!(live.len(), 1);
        assert!(live_certs(&known, &l, "sauersml.lead", &boxn.public()).is_empty());
        // Revoked, then the name certified again with a new key.
        known.revoke(&Revocation::sign(&mac, "sauersml.lead", &k1.public(), TS)).unwrap();
        assert!(live_certs(&known, &l, "sauersml.lead", &mac.public()).is_empty());
        known.add(Cert::issue(&mac, "sauersml.lead", &k2.public(), TS));
        let live = live_certs(&known, &l, "sauersml.lead", &mac.public());
        assert_eq!(live.iter().map(|c| c.agent_key().unwrap()).collect::<Vec<_>>(), vec![k2.public()]);
    }

    #[test]
    fn another_nodes_cert_for_the_same_key_does_not_preempt() {
        // box has seen mac's agent's public key and certifies it first, under a name of its own. Held by (node, key),
        // mac's certificate for the key still goes in, and only mac's counts for sauersml.lead.
        let (mac, boxn, lead) = (Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml."]), ("box", &boxn, &[])]);
        let mut known = CertSet::default();
        known.add(Cert::issue(&boxn, "box.lead", &lead.public(), TS));
        known.add(Cert::issue(&mac, "sauersml.lead", &lead.public(), TS));
        assert_eq!(known.certs.len(), 2);
        let live = live_certs(&known, &l, "sauersml.lead", &mac.public());
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].node_key().unwrap(), mac.public());
        // box's certificate counts only for its own name, and only as box's.
        assert!(live_certs(&known, &l, "sauersml.lead", &boxn.public()).is_empty());
        assert_eq!(live_certs(&known, &l, "box.lead", &boxn.public()).len(), 1);
    }

    #[test]
    fn a_revocation_counts_only_against_its_own_nodes_certs() {
        let (mac, boxn, lead) = (Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&[("mac", &mac, &["sauersml."]), ("box", &boxn, &[])]);
        let mut known = CertSet::default();
        let mine = Cert::issue(&mac, "sauersml.lead", &lead.public(), TS);
        let theirs = Cert::issue(&boxn, "box.lead", &lead.public(), TS);
        known.add(mine.clone());
        known.add(theirs.clone());
        // box revokes the key under a name in its own namespace: a valid revocation, but only of box's certificate.
        let r = Revocation::sign(&boxn, "box.lead", &lead.public(), TS);
        r.verify(&l).unwrap();
        assert!(r.revokes(&theirs) && !r.revokes(&mine));
        known.revoke(&r).unwrap();
        assert!(known.revoked(&theirs) && !known.revoked(&mine));
        assert_eq!(live_certs(&known, &l, "sauersml.lead", &mac.public()), vec![mine.clone()]);
        assert!(live_certs(&known, &l, "box.lead", &boxn.public()).is_empty());
        // mac's own revocation kills mac's certificate.
        known.revoke(&Revocation::sign(&mac, "sauersml.lead", &lead.public(), TS)).unwrap();
        assert!(known.revoked(&mine));
        assert!(live_certs(&known, &l, "sauersml.lead", &mac.public()).is_empty());
    }
}
