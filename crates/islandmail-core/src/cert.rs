//! Node-certified agents. A host's trust file can give a node a namespace (`names`); that node then vouches for its
//! own host's agents within it by signing a certificate binding a name to an agent key, and every host that trusts
//! the node accepts those agents with no per-agent pin. A node signs a certificate only for a key that proved itself
//! (an issuance proof signed by the agent key), and can later revoke a key it certified.

use anyhow::{anyhow, bail, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::{b64u, b64u_decode, parse_ts};

pub const VERSION: u32 = 1;
/// How far an issuance proof's timestamp may be from the node's clock.
pub const CERTIFY_SKEW_MS: i64 = 300_000;

const CERT_CONTEXT: &[u8] = b"islandmail/agent-cert/v1\n";
const REVOKE_CONTEXT: &[u8] = b"islandmail/agent-revoke/v1\n";

/// An agent name: 1-48 of [A-Za-z0-9._-], starting with a letter, digit or '_', not ending with '.', not "all".
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.first().is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && b.len() <= 48
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
        && !name.ends_with('.')
        && !name.eq_ignore_ascii_case("all")
}

/// A name a certificate may carry: an agent name, or a home name `local@domain` (see `home`).
pub fn valid_agent_name(name: &str) -> bool {
    valid_name(name) || crate::home::split_name(name).is_some()
}

/// A namespace entry in a trust file: an exact agent name, or a prefix ending in '.' (e.g. "ops.").
pub fn valid_namespace_entry(entry: &str) -> bool {
    match entry.strip_suffix('.') {
        Some(prefix) => valid_name(prefix),
        None => valid_name(entry),
    }
}

/// Whether a namespace entry covers `name` (case-insensitive; a prefix covers the longer names under it).
pub fn entry_covers(entry: &str, name: &str) -> bool {
    let (e, n) = (crate::addr::norm(entry), crate::addr::norm(name));
    if e.ends_with('.') { n.starts_with(&e) && n.len() > e.len() } else { e == n }
}

/// The durable id of a certified agent, the same on every host (the client's default sub).
pub fn agent_sub(name: &str) -> String {
    format!("agent:{name}")
}

/// What an agent signs to ask its local node for a certificate.
pub fn certify_statement(name: &str, key: &str, node: &str, ts: &str) -> String {
    format!("islandmail-certify|v1|{name}|{key}|{node}|{ts}")
}

fn canonical_sig(sig: &str) -> Result<[u8; 64]> {
    let b = b64u_decode(sig).ok_or_else(|| anyhow!("signature is not base64url"))?;
    ensure!(b64u(&b) == sig, "signature is not canonical base64url");
    b.try_into().map_err(|_| anyhow!("signature is not 64 bytes"))
}

fn canonical_key(key: &str) -> Result<PublicKey> {
    let k = parse_key(key)?;
    ensure!(fmt_key(&k) == key, "key must be ed25519:<base64url without padding>");
    Ok(k)
}

/// Checks an issuance request `{name, key, ts, sig}` for the node `node`: valid name, canonical key, a timestamp within
/// 5 minutes of `now_ms`, and the key's signature over the certify statement. Returns the agent key.
pub fn check_issuance(name: &str, key: &str, ts: &str, sig: &str, node: &PublicKey, now_ms: i64) -> Result<PublicKey> {
    ensure!(valid_agent_name(name), "invalid agent name");
    let k = canonical_key(key)?;
    keys::x25519_public(&k)?;
    let t = parse_ts(ts).ok_or_else(|| anyhow!("ts must be YYYY-MM-DDTHH:MM:SS.mmmZ"))?;
    ensure!((t - now_ms).abs() <= CERTIFY_SKEW_MS, "ts is more than 5 minutes from the node's clock");
    let s = canonical_sig(sig)?;
    let st = certify_statement(name, key, &fmt_key(node), ts);
    ensure!(keys::verify(&k, st.as_bytes(), &s), "the proof is not signed by that key");
    Ok(k)
}

/// A node's statement that `key` is the agent `name` on its host.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cert {
    pub v: u32,
    pub name: String,
    pub key: String,
    /// The issuing node's key.
    pub node: String,
    pub issued: String,
    pub sig: String,
    /// For a home name: the home's token and the agent's proof of possession, which every peer re-checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<crate::home::HomeProof>,
}

/// A node's statement that it no longer vouches for `key`, from `ts` on. It counts only against that node's certs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub v: u32,
    pub name: String,
    pub key: String,
    pub node: String,
    pub ts: String,
    pub sig: String,
}

fn signed_json<T: Serialize>(context: &[u8], v: &T) -> Vec<u8> {
    let mut out = context.to_vec();
    out.extend(serde_json::to_vec(v).expect("json"));
    out
}

fn check_signed(v: u32, name: &str, key: &str, node: &str, ts: &str, sig: &str, msg: &[u8]) -> Result<()> {
    ensure!(v == VERSION, "unsupported certificate version {v}");
    ensure!(valid_agent_name(name), "invalid agent name in certificate");
    canonical_key(key)?;
    let n = canonical_key(node)?;
    ensure!(parse_ts(ts).is_some(), "bad certificate timestamp");
    let s = canonical_sig(sig)?;
    if !keys::verify(&n, msg, &s) {
        bail!("certificate signature does not verify");
    }
    Ok(())
}

impl Cert {
    pub fn issue(node: &Seed, name: &str, key: &PublicKey, issued: &str) -> Cert {
        let mut c = Cert { v: VERSION, name: name.into(), key: fmt_key(key), node: fmt_key(&node.public()),
                           issued: issued.into(), sig: String::new(), home: None };
        c.sig = b64u(&node.sign(&c.signing_bytes()));
        c
    }

    /// A certificate for a home name, carrying the home's token and the agent's proof of possession.
    pub fn issue_home(node: &Seed, name: &str, key: &PublicKey, issued: &str, proof: crate::home::HomeProof) -> Cert {
        let mut c = Cert { home: Some(proof), ..Cert::issue(node, name, key, issued) };
        c.sig = b64u(&node.sign(&c.signing_bytes()));
        c
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        signed_json(CERT_CONTEXT, &Cert { sig: String::new(), ..self.clone() })
    }

    /// Shape and the issuing node's signature. Whether this host trusts the node for the name is the trust file's
    /// call (`MemberList::accepts`), and revocation is the store's.
    pub fn check(&self) -> Result<()> {
        keys::x25519_public(&self.agent_key()?)?;
        check_signed(self.v, &self.name, &self.key, &self.node, &self.issued, &self.sig, &self.signing_bytes())
    }

    /// The agent timestamps mail on its own clock. Allow the same skew as its enrollment proof.
    pub fn issued_by(&self, at_ms: i64) -> bool {
        parse_ts(&self.issued).is_some_and(|t| t <= at_ms.saturating_add(CERTIFY_SKEW_MS))
    }

    pub fn agent_key(&self) -> Result<PublicKey> {
        parse_key(&self.key)
    }

    pub fn node_key(&self) -> Result<PublicKey> {
        parse_key(&self.node)
    }
}

impl Revocation {
    pub fn sign(node: &Seed, name: &str, key: &PublicKey, ts: &str) -> Revocation {
        let mut r = Revocation { v: VERSION, name: name.into(), key: fmt_key(key), node: fmt_key(&node.public()),
                                 ts: ts.into(), sig: String::new() };
        r.sig = b64u(&node.sign(&r.signing_bytes()));
        r
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        signed_json(REVOKE_CONTEXT, &Revocation { sig: String::new(), ..self.clone() })
    }

    pub fn check(&self) -> Result<()> {
        check_signed(self.v, &self.name, &self.key, &self.node, &self.ts, &self.sig, &self.signing_bytes())
    }

    pub fn ts_ms(&self) -> i64 {
        parse_ts(&self.ts).unwrap_or(i64::MIN)
    }

    /// Only the issuing node's cert for the same key.
    pub fn revokes(&self, cert: &Cert) -> bool {
        self.key == cert.key && self.node == cert.node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_namespaces() {
        assert!(valid_name("eng.lead") && valid_name("alice") && valid_name("_x-1"));
        assert!(!valid_name("all") && !valid_name("ALL") && !valid_name("a.") && !valid_name(".a") && !valid_name("a/b"));
        assert!(!valid_name("") && !valid_name(&"a".repeat(49)));
        assert!(valid_namespace_entry("ops.") && valid_namespace_entry("alice"));
        assert!(!valid_namespace_entry("*") && !valid_namespace_entry("all") && !valid_namespace_entry("all.")
                && !valid_namespace_entry(".") && !valid_namespace_entry("a b."));
        assert!(entry_covers("ops.", "Ops.Bob") && entry_covers("alice", "ALICE"));
        assert!(!entry_covers("ops.", "ops") && !entry_covers("ops.", "opswest.x") && !entry_covers("alice", "alice.x"));
    }

    #[test]
    fn issuance_proof() {
        let node = Seed::generate();
        let agent = Seed::generate();
        let now = crate::now_millis();
        let ts = crate::ts_from_millis(now);
        let key = fmt_key(&agent.public());
        let sig = b64u(&agent.sign(certify_statement("a.bob", &key, &fmt_key(&node.public()), &ts).as_bytes()));
        assert_eq!(check_issuance("a.bob", &key, &ts, &sig, &node.public(), now).unwrap(), agent.public());
        // Another node, another name, a stale time, someone else's key, a non-canonical signature.
        assert!(check_issuance("a.bob", &key, &ts, &sig, &Seed::generate().public(), now).is_err());
        assert!(check_issuance("a.sue", &key, &ts, &sig, &node.public(), now).is_err());
        assert!(check_issuance("a.bob", &key, &ts, &sig, &node.public(), now + 400_000).is_err());
        assert!(check_issuance("a.bob", &fmt_key(&node.public()), &ts, &sig, &node.public(), now).is_err());
        assert!(check_issuance("a.bob", &key, &ts, &format!("{sig}="), &node.public(), now).is_err());
        assert!(check_issuance("all", &key, &ts, &sig, &node.public(), now).is_err());
    }

    #[test]
    fn certs_and_revocations_are_signed_by_their_node() {
        let node = Seed::generate();
        let agent = Seed::generate();
        let c = Cert::issue(&node, "a.bob", &agent.public(), &crate::now_ts());
        c.check().unwrap();
        assert_eq!(c.agent_key().unwrap(), agent.public());
        let mut forged = c.clone();
        forged.name = "a.sue".into();
        assert!(forged.check().is_err());
        let mut moved = c.clone();
        moved.node = fmt_key(&Seed::generate().public());
        assert!(moved.check().is_err());
        let r = Revocation::sign(&node, "a.bob", &agent.public(), &crate::now_ts());
        r.check().unwrap();
        assert!(r.revokes(&c));
        let other = Cert::issue(&Seed::generate(), "a.bob", &agent.public(), &crate::now_ts());
        assert!(!r.revokes(&other), "a revocation counts only against its own node's certificate");
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Cert>(&json).unwrap(), c);
    }
}
