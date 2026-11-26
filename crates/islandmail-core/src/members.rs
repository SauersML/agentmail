//! The local trust file: pinned agent identities, direct peers and the namespaces those peers may certify agents in.

use std::collections::{BTreeMap, HashSet};

use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::addr;
use crate::cert::{self, Cert};
use crate::keys::{self, fmt_key, parse_key, PublicKey};
use crate::{b64u, b64u_decode};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Member {
    /// Mail name (the token's `name`), e.g. eng.lead
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
    /// Agent names this node may certify: exact names or prefixes ending in '.'. Empty: none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

impl NodeEntry {
    pub fn covers(&self, name: &str) -> bool {
        self.names.iter().any(|e| cert::entry_covers(e, name))
    }
}

/// Max namespace entries per node.
pub const MAX_NAMES: usize = 64;

/// An agent this host accepts: pinned in the trust file, or certified by a trusted node within its namespace.
#[derive(Clone, Debug, PartialEq)]
pub struct Agent {
    pub name: String,
    pub sub: String,
    pub key: PublicKey,
    /// Trusted nodes that certify this name and key. Each one can sign the agent in and read its private mail.
    pub homes: Vec<PublicKey>,
    /// One live certificate per home.
    pub certs: Vec<Cert>,
    pub pinned: bool,
}

/// The agents named `name`.
pub fn named<'a>(agents: &'a [Agent], name: &'a str) -> impl Iterator<Item = &'a Agent> + 'a {
    agents.iter().filter(move |a| addr::same(&a.name, name))
}

/// The agent named `name` with this key.
pub fn find<'a>(agents: &'a [Agent], name: &str, key: &PublicKey) -> Option<&'a Agent> {
    agents.iter().find(|a| addr::same(&a.name, name) && a.key == *key)
}

/// Mode "private": the agent key and every home node key of each agent `to` addresses, and of the sender.
pub fn private_keys(agents: &[Agent], to: &str, from: &str) -> Vec<PublicKey> {
    let mut out = Vec::new();
    for a in agents.iter().filter(|a| addr::addressed_to(to, &[a.name.as_str()]) || addr::same(&a.name, from)) {
        out.push(a.key);
        out.extend(a.homes.iter().copied());
    }
    out.sort();
    out.dedup();
    out
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
    /// Identity homes trusted to vouch for names under their suffix (see `home`). Any listed node may certify them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub homes: Vec<crate::home::HomeEntry>,
}

impl MemberList {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.v == 1 && self.seq > 0, "expected local trust file version 1 and positive revision");
        let id = b64u_decode(&self.network).ok_or_else(|| anyhow!("invalid network ID"))?;
        ensure!(id.len() == 32 && b64u(&id) == self.network, "use the network ID printed by islandmail-node network-id");
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
            ensure!(cert::valid_name(&m.name), "invalid agent name");
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
            ensure!(n.names.len() <= MAX_NAMES, "node {:?} lists more than {MAX_NAMES} names", n.name);
            for e in &n.names {
                ensure!(cert::valid_namespace_entry(e),
                        "node {:?}: names entry {e:?} must be an agent name or a prefix ending in '.'", n.name);
            }
        }
        ensure!(self.homes.len() <= MAX_NAMES, "at most {MAX_NAMES} homes");
        for (i, h) in self.homes.iter().enumerate() {
            h.validate()?;
            // One suffix, one home; the same home may list a second key while it rotates.
            for o in &self.homes[..i] {
                ensure!(o.suffix != h.suffix || (o.iss == h.iss && o.key != h.key),
                        "homes {:?} and {:?} share suffix {}", o.name, h.name, h.suffix);
            }
        }
        Ok(())
    }

    pub fn node_by_key(&self, key: &PublicKey) -> Option<&NodeEntry> {
        let key = fmt_key(key);
        self.nodes.iter().find(|n| n.key == key)
    }

    /// Pins reserve their subject and encryption key, including both sign encodings with the same X25519 image.
    pub fn permits_agent_key(&self, name: &str, key: &PublicKey) -> bool {
        let exact = fmt_key(key);
        let mut opposite = *key;
        opposite[31] ^= 0x80;
        let opposite = fmt_key(&opposite);
        if self.nodes.iter().any(|n| n.key == exact || n.key == opposite) { return false; }
        if let Some(pin) = self.member_by_name(name) { return pin.key == exact; }
        self.members.iter().all(|m| m.key != exact && m.key != opposite
            && !m.sub.strip_prefix("agent:").is_some_and(|reserved| reserved.eq_ignore_ascii_case(name)))
    }

    /// Whether this host trusts `c`: well formed, signed by a node on this list whose namespace covers its name.
    /// A home name instead needs any node on this list and a home proof one of this list's homes accepts.
    pub fn accepts(&self, c: &Cert) -> bool {
        let home = crate::home::is_home_name(&c.name);
        self.nodes.iter().any(|n| n.key == c.node && (home || n.covers(&c.name)))
            && c.agent_key().is_ok_and(|k| self.permits_agent_key(&c.name, &k)) && c.check().is_ok()
            && crate::home::check_cert(&self.homes, &self.network, c).is_ok()
    }

    /// Every agent this host accepts at `at_ms`. `revoked_at(cert)` is when the cert's own node revoked its key, if
    /// it did; a revoked cert counts for times before that. A pinned name takes only its pinned key: certificates
    /// for that name and key add homes, certificates for another key are ignored.
    pub fn agents(&self, certs: &[Cert], revoked_at: &dyn Fn(&Cert) -> Option<i64>, at_ms: i64) -> Vec<Agent> {
        let mut seen = HashSet::new();
        let mut groups: BTreeMap<_, Vec<(PublicKey, Cert)>> = BTreeMap::new();
        for c in certs {
            if !c.issued_by(at_ms) || revoked_at(c).is_some_and(|t| at_ms >= t) || !self.accepts(c) { continue; }
            let (Ok(node), Ok(key)) = (c.node_key(), c.agent_key()) else { continue };
            if seen.insert((node, key)) {
                groups.entry((addr::norm(&c.name), key)).or_default().push((node, c.clone()));
            }
        }
        let agent = |name, sub, key, pinned, mut group: Vec<(PublicKey, Cert)>| {
            group.sort_unstable_by_key(|(node, _)| *node);
            let (homes, certs) = group.into_iter().unzip();
            Agent { name, sub, key, homes, certs, pinned }
        };
        let mut out = Vec::new();
        for m in &self.members {
            let Ok(key) = parse_key(&m.key) else { continue };
            let group = groups.remove(&(addr::norm(&m.name), key)).unwrap_or_default();
            out.push(agent(m.name.clone(), m.sub.clone(), key, true, group));
        }
        for ((_, key), group) in groups {
            let name = group.iter().map(|(_, c)| &c.name).min().expect("nonempty certificate group").clone();
            let sub = cert::agent_sub(&name);
            out.push(agent(name, sub, key, false, group));
        }
        out
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

    pub fn member_by_name(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| addr::same(&m.name, name))
    }

    pub fn topic(&self) -> [u8; 32] {
        blake3::derive_key("islandmail/local-trust/v1", self.network.as_bytes())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::Seed;

    pub fn list(members: &[(&str, &Seed)], nodes: &[&Seed]) -> MemberList {
        let l = MemberList {
            v: 1,
            network: b64u(&crate::random_bytes::<32>()),
            seq: 1,
            members: members
                .iter()
                .map(|(n, s)| Member { name: n.to_string(), sub: format!("agent:{n}@test"), key: fmt_key(&s.public()) })
                .collect(),
            nodes: nodes
                .iter()
                .enumerate()
                .map(|(i, s)| NodeEntry { name: format!("node{i}"), key: fmt_key(&s.public()), addrs: vec![], names: vec![] })
                .collect(),
            homes: vec![],
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

    #[test]
    fn certificates_respect_pinned_key_roles_and_encryption_requirements() {
        let (home, agent) = (Seed::generate(), Seed::generate());
        let mut l = list(&[("a.bob", &agent)], &[&home]);
        l.members[0].sub = "agent:a.reserved".into();
        l.nodes[0].names = vec!["a.".into()];
        let accepts = |name, key| l.accepts(&Cert::issue(&home, name, &key, &crate::now_ts()));
        assert!(accepts("a.bob", agent.public()));
        assert!(!accepts("a.reserved", Seed::generate().public()));
        assert!(!accepts("a.Reserved", Seed::generate().public()));
        assert!(accepts("a.other", Seed::generate().public()));
        assert!(!accepts("a.other", agent.public()));
        assert!(!accepts("a.other", home.public()));
        assert!(!accepts("a.other", [0; 32]));
        let mut alias = agent.public();
        alias[31] ^= 0x80;
        assert!(!accepts("a.other", alias));
    }

    #[test]
    fn namespaces_are_checked_and_may_overlap_for_two_homes() {
        let mut l = list(&[], &[&Seed::generate(), &Seed::generate()]);
        l.nodes[0].names = vec!["alice".into(), "eng.".into()];
        l.nodes[1].names = vec!["alice".into()];
        l.validate().unwrap();
        for bad in ["*", "all", "all.", "a b", "", "eng..", "/x"] {
            l.nodes[1].names = vec![bad.into()];
            assert!(l.validate().is_err(), "{bad:?}");
        }
        // A file without `names` still parses, and its nodes certify nobody.
        let raw = r#"{"v":1,"network":"NET","seq":1,"members":[],"nodes":[{"name":"x","key":"KEY"}]}"#
            .replace("NET", &l.network).replace("KEY", &l.nodes[0].key);
        let old: MemberList = serde_json::from_str(&raw).unwrap();
        old.validate().unwrap();
        assert!(old.nodes[0].names.is_empty() && !old.nodes[0].covers("x.y"));
    }
}
