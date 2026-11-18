//! The member list: who may write (node keys), whom mail is encrypted to (agent keys), and which bridge keys may sign
//! imported history. Signed by the operator key; nodes pin the operator key and accept the list with the highest `seq`.
//! Phase 1 loads it from a local file; it has the same shape it will have when replicated like mail.

use anyhow::{anyhow, bail, Result};
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
    /// The agent's enrolled Ed25519 key (principals.json `key`)
    pub key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NodeEntry {
    pub name: String,
    /// The node's Ed25519 key; also its iroh endpoint id.
    pub key: String,
    /// Direct addresses (ip:port) other nodes may dial; optional when relays or address lookup find it.
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
    pub bridges: Vec<String>,
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
        for m in &self.members {
            parse_key(&m.key)?;
        }
        for n in &self.nodes {
            parse_key(&n.key)?;
        }
        for b in &self.bridges {
            parse_key(b)?;
        }
        Ok(())
    }

    pub fn is_node(&self, key: &PublicKey) -> bool {
        self.nodes.iter().any(|n| parse_key(&n.key).ok().as_ref() == Some(key))
    }

    pub fn is_bridge(&self, key: &PublicKey) -> bool {
        self.bridges.iter().any(|b| parse_key(b).ok().as_ref() == Some(key))
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
            bridges: vec![],
            sig: String::new(),
        };
        l.sign(&op);
        l.verify(&op.public()).unwrap();
        l
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
