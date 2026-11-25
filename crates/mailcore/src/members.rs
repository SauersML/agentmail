//! Locally pinned agent identities and direct peers.

use std::collections::HashSet;

use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::addr;
use crate::keys::{self, fmt_key, parse_key, PublicKey};
use crate::{b64u, b64u_decode};

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
#[serde(deny_unknown_fields)]
pub struct MemberList {
    pub v: u32,
    /// Random public network identifier shared by the participating hosts.
    pub network: String,
    pub seq: u64,
    pub members: Vec<Member>,
    pub nodes: Vec<NodeEntry>,
}

impl MemberList {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.v == 2 && self.seq > 0, "expected local trust file version 2 and positive revision");
        let id = b64u_decode(&self.network).ok_or_else(|| anyhow!("invalid network ID"))?;
        ensure!(id.len() == 32 && b64u(&id) == self.network, "use the network ID printed by mailnode network-id");
        ensure!(!self.nodes.is_empty() && self.members.len() + self.nodes.len() <= crate::envelope::MAX_KEYS,
                "list needs at least one node and at most {} recipient keys", crate::envelope::MAX_KEYS);
        let mut keys = HashSet::new();
        let mut add_key = |raw: &str| -> Result<()> {
            let key = parse_key(raw)?;
            ensure!(fmt_key(&key) == raw, "public key must use canonical base64url");
            ensure!(keys.insert(keys::x25519_public(&key)?), "keys must be distinct across agents and nodes");
            Ok(())
        };
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
        blake3::derive_key("agent-mail/local-trust/v2", self.network.as_bytes())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::Seed;

    pub fn list(members: &[(&str, &Seed)], nodes: &[&Seed]) -> MemberList {
        let l = MemberList {
            v: 2,
            network: b64u(&crate::random_bytes::<32>()),
            seq: 1,
            members: members
                .iter()
                .map(|(n, s)| Member { name: n.to_string(), sub: format!("agent:{n}@test"), key: fmt_key(&s.public()) })
                .collect(),
            nodes: nodes
                .iter()
                .enumerate()
                .map(|(i, s)| NodeEntry { name: format!("node{i}"), key: fmt_key(&s.public()), addrs: vec![] })
                .collect(),
        };
        l.validate().unwrap();
        l
    }

    #[test]
    fn membership_rejects_shared_roles_and_ambiguous_names() {
        let mut l = list(&[("a.bob", &Seed::generate()), ("a.sue", &Seed::generate())], &[&Seed::generate()]);
        l.members[1].name = "A.Bob".into();
        assert!(l.validate().is_err());
        l.members[1].name = "a.sue".into();
        l.nodes[0].key = l.members[0].key.clone();
        assert!(l.validate().is_err());
    }
}
