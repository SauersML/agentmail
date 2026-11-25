//! Operator-signed membership for agent identities and direct peers.

use std::collections::HashSet;

use anyhow::{anyhow, bail, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::addr;
use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::{b64u, b64u_decode};

const SIG_CONTEXT: &[u8] = b"agent-mail/members/v1\n";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Member {
    /// Mail name (the token's `name`), e.g. sauersml.lead
    pub name: String,
    /// Durable principal id (the token's `sub`)
    pub sub: String,
    /// The agent's public signing key.
    pub key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NodeEntry {
    pub name: String,
    /// The node's Ed25519 key; also its iroh endpoint id.
    pub key: String,
    /// Direct socket addresses that other peers can dial.
    #[serde(default)]
    pub addrs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MemberList {
    pub v: u32,
    /// Network name; the gossip topic is derived from it and the operator key.
    pub network: String,
    pub seq: u64,
    pub issued: String,
    pub operator: String,
    pub members: Vec<Member>,
    pub nodes: Vec<NodeEntry>,
    #[serde(default)]
    pub sig: String,
}

impl MemberList {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut l = self.clone();
        l.sig.clear();
        let mut out = SIG_CONTEXT.to_vec();
        out.extend(serde_json::to_vec(&l).expect("json"));
        out
    }

    pub fn sign(&mut self, operator: &Seed) {
        self.operator = fmt_key(&operator.public());
        self.sig = b64u(&operator.sign(&self.signing_bytes()));
    }

    /// Checks the signature against the pinned operator key and that every key parses.
    pub fn verify(&self, pinned_operator: &PublicKey) -> Result<()> {
        if self.v != 1 {
            bail!("unsupported member list version");
        }
        if parse_key(&self.operator)? != *pinned_operator {
            bail!("member list is signed by another operator");
        }
        let sig = b64u_decode(&self.sig).ok_or_else(|| anyhow!("bad member list signature"))?;
        if !keys::verify(pinned_operator, &self.signing_bytes(), &sig) {
            bail!("member list signature does not verify");
        }
        ensure!(!self.nodes.is_empty() && self.members.len() + self.nodes.len() <= crate::envelope::MAX_KEYS,
                "list needs at least one node and at most {} recipient keys", crate::envelope::MAX_KEYS);
        ensure!(!self.network.trim().is_empty() && self.network.len() <= 120 && !self.network.chars().any(char::is_control),
                "invalid network name");
        let mut keys = HashSet::new();
        let mut add_key = |raw: &str| -> Result<()> {
            let key = parse_key(raw)?;
            ensure!(fmt_key(&key) == raw, "public key must use canonical base64url");
            ensure!(keys.insert(keys::x25519_public(&key)?), "keys must be distinct across members, nodes and operator");
            Ok(())
        };
        add_key(&self.operator)?;
        let mut names = HashSet::new();
        let mut subjects = HashSet::new();
        for m in &self.members {
            let name = m.name.as_bytes();
            ensure!(name.first().is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') && name.len() <= 48
                    && name.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
                    && !m.name.ends_with('.') && !m.name.eq_ignore_ascii_case("all"), "invalid agent name");
            ensure!(!m.sub.is_empty() && m.sub.len() <= 120 && m.sub.bytes().all(|b| b.is_ascii_graphic()),
                    "invalid agent subject");
            ensure!(names.insert(addr::norm(&m.name)) && subjects.insert(&m.sub), "duplicate agent name or subject");
            add_key(&m.key)?;
        }
        for n in &self.nodes {
            add_key(&n.key)?;
            for addr in &n.addrs {
                addr.parse::<std::net::SocketAddr>().map_err(|_| anyhow!("invalid peer socket address {addr:?}"))?;
            }
        }
        Ok(())
    }

    pub fn is_node(&self, key: &PublicKey) -> bool {
        let key = fmt_key(key);
        self.nodes.iter().any(|n| n.key == key)
    }

    pub fn node_keys(&self) -> Vec<PublicKey> {
        self.nodes.iter().filter_map(|n| parse_key(&n.key).ok()).collect()
    }

    /// Mode "members": every member agent key and every node key.
    pub fn all_keys(&self) -> Vec<PublicKey> {
        let mut out: Vec<PublicKey> = self.members.iter().filter_map(|m| parse_key(&m.key).ok()).collect();
        out.extend(self.node_keys());
        out.sort();
        out.dedup();
        out
    }

    /// Mode "private": the keys of the members `to` addresses, plus the sender's.
    pub fn private_keys(&self, to: &str, from: &str) -> Vec<PublicKey> {
        let mut out: Vec<PublicKey> = self
            .members
            .iter()
            .filter(|m| addr::addressed_to(to, &[m.name.as_str()]) || addr::same(&m.name, from))
            .filter_map(|m| parse_key(&m.key).ok())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn member_by_name(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| addr::same(&m.name, name))
    }

    pub fn topic(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("agent-mail v1 gossip topic");
        h.update(self.operator.as_bytes());
        h.update(b"\n");
        h.update(self.network.as_bytes());
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn list(members: &[(&str, &Seed)], nodes: &[&Seed]) -> MemberList {
        let op = Seed::generate();
        let mut l = MemberList {
            v: 1,
            network: "test".into(),
            seq: 1,
            issued: crate::now_ts(),
            operator: String::new(),
            members: members
                .iter()
                .map(|(n, s)| Member { name: n.to_string(), sub: format!("agent:{n}@test"), key: fmt_key(&s.public()) })
                .collect(),
            nodes: nodes
                .iter()
                .enumerate()
                .map(|(i, s)| NodeEntry { name: format!("node{i}"), key: fmt_key(&s.public()), addrs: vec![] })
                .collect(),
            sig: String::new(),
        };
        l.sign(&op);
        l.verify(&op.public()).unwrap();
        l
    }

    #[test]
    fn membership_rejects_shared_roles_and_ambiguous_names() {
        let op = Seed::generate();
        let mut l = list(&[("a.bob", &Seed::generate()), ("a.sue", &Seed::generate())], &[&Seed::generate()]);
        l.members[1].name = "A.Bob".into();
        l.sign(&op);
        assert!(l.verify(&op.public()).is_err());
        l.members[1].name = "a.sue".into();
        l.nodes[0].key = l.members[0].key.clone();
        l.sign(&op);
        assert!(l.verify(&op.public()).is_err());
    }

    #[test]
    fn signed_list_verifies_and_refuses_edits() {
        let op = Seed::generate();
        let node = Seed::generate();
        let mut l = list(&[("a.x", &Seed::generate())], &[&node]);
        l.sign(&op);
        assert!(l.verify(&op.public()).is_ok());
        assert!(l.verify(&Seed::generate().public()).is_err());
        let mut edited = l.clone();
        edited.nodes.push(NodeEntry { name: "evil".into(), key: fmt_key(&Seed::generate().public()), addrs: vec![] });
        assert!(edited.verify(&op.public()).is_err());
        assert!(l.is_node(&node.public()));
    }
}
