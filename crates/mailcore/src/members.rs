//! The member list: the nodes of a network, their keys and addresses, and the agent names each node may certify.
//! Signed by the operator key; nodes pin the operator key and accept the list with the highest `seq`. Agents are not
//! on the list: a node certifies its own agents (see `cert`), within the names the list gives it.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::addr;
use crate::cert::valid_name;
use crate::keys::{self, fmt_key, parse_key, PublicKey, Seed};
use crate::{b64u, b64u_decode};

pub const VERSION: u32 = 2;
const SIG_CONTEXT: &[u8] = b"agent-mail/members/v1\n";
/// Longest node name (it is shown in every sender line, `agent:NAME@NODE`).
pub const MAX_NODE_NAME: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NodeEntry {
    pub name: String,
    /// The node's Ed25519 key; also its iroh endpoint id.
    pub key: String,
    /// Agent names this node may certify: an entry ending in '.' is a prefix (it covers every name that starts with
    /// it), any other entry is one exact name. Empty means the default, `["<node name>."]` (see `namespace`).
    #[serde(default)]
    pub names: Vec<String>,
    /// Direct addresses (ip:port) other nodes may dial; optional when relays or address lookup find it.
    #[serde(default)]
    pub addrs: Vec<String>,
}

impl NodeEntry {
    /// The names this node may certify, as written (or the default, the node name followed by '.').
    pub fn namespace(&self) -> Vec<String> {
        if self.names.is_empty() {
            vec![format!("{}.", self.name)]
        } else {
            self.names.clone()
        }
    }

    /// Whether `name` is in this node's namespace (compared like mail addresses: case-insensitive, '/' = '.').
    /// A prefix covers the names that start with it, not the bare prefix itself.
    pub fn covers(&self, name: &str) -> bool {
        let n = addr::norm(name);
        self.namespace().iter().map(|e| addr::norm(e)).any(|e| if e.ends_with('.') { n.len() > e.len() && n.starts_with(&e) } else { n == e })
    }
}

/// Whether `entry` is a valid namespace entry: a valid agent name, or a valid agent name followed by '.'.
pub fn valid_namespace_entry(entry: &str) -> bool {
    match entry.strip_suffix('.') {
        Some(prefix) => valid_name(prefix),
        None => valid_name(entry),
    }
}

/// Whether two normalized namespace entries can both cover one name.
fn overlap(a: &str, b: &str) -> bool {
    match (a.ends_with('.'), b.ends_with('.')) {
        (false, false) => a == b,
        (false, true) => a.starts_with(b),
        (true, false) => b.starts_with(a),
        (true, true) => a.starts_with(b) || b.starts_with(a),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MemberList {
    pub v: u32,
    /// Network name; the gossip topic is derived from it and the operator key.
    pub network: String,
    pub seq: u64,
    /// When the operator signed it; `sign-members` fills it in when empty.
    #[serde(default)]
    pub issued: String,
    /// The operator key that signed it (set by `sign`).
    #[serde(default)]
    pub operator: String,
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

    /// Checks the version, the signature against the pinned operator key, every node key and name, and the namespaces:
    /// every entry a valid name or prefix, and no name coverable by two different nodes.
    pub fn verify(&self, pinned_operator: &PublicKey) -> Result<()> {
        if self.v == 1 {
            bail!("member list v1 is the old format: write a v2 list (\"v\": 2, nodes only, each with the agent names it may certify) and sign it again");
        }
        if self.v != VERSION {
            bail!("unsupported member list version {}", self.v);
        }
        if parse_key(&self.operator)? != *pinned_operator {
            bail!("member list is signed by another operator");
        }
        let sig = b64u_decode(&self.sig).ok_or_else(|| anyhow!("bad member list signature"))?;
        if !keys::verify(pinned_operator, &self.signing_bytes(), &sig) {
            bail!("member list signature does not verify");
        }
        self.check_nodes()
    }

    /// The checks of `verify` that do not need the signature: node keys, node names, namespaces.
    pub fn check_nodes(&self) -> Result<()> {
        let mut keys_seen = std::collections::BTreeSet::new();
        for n in &self.nodes {
            let k = parse_key(&n.key).map_err(|e| anyhow!("node {}: {e}", n.name))?;
            if !keys_seen.insert(k) {
                bail!("node key {} is listed twice", n.key);
            }
            if n.name.is_empty() || n.name.chars().count() > MAX_NODE_NAME || n.name.chars().any(|c| c.is_control() || c == '@') {
                bail!("node name {:?} must be 1-{MAX_NODE_NAME} characters, without control characters or '@'", n.name);
            }
            for e in n.namespace() {
                if !valid_namespace_entry(&e) {
                    bail!(
                        "node {}: {e:?} is not a valid name or prefix (names are 1-48 of A-Z a-z 0-9 . _ -, not starting or ending with '.', not all; a prefix is a name followed by '.')",
                        n.name
                    );
                }
            }
        }
        for (i, a) in self.nodes.iter().enumerate() {
            for b in &self.nodes[i + 1..] {
                for x in a.namespace() {
                    for y in b.namespace() {
                        if overlap(&addr::norm(&x), &addr::norm(&y)) {
                            bail!("namespaces overlap: {x:?} of node {} and {y:?} of node {} can cover the same name", a.name, b.name);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn is_node(&self, key: &PublicKey) -> bool {
        self.node_by_key(key).is_some()
    }

    pub fn node_by_key(&self, key: &PublicKey) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| parse_key(&n.key).ok().as_ref() == Some(key))
    }

    /// The node whose namespace covers `name`. On a verified list there is at most one.
    pub fn node_for_name(&self, name: &str) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.covers(name))
    }

    /// Every node key, sorted: the recipients of mode "members".
    pub fn node_keys(&self) -> Vec<PublicKey> {
        let mut out: Vec<PublicKey> = self.nodes.iter().filter_map(|n| parse_key(&n.key).ok()).collect();
        out.sort();
        out.dedup();
        out
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

    pub fn entry(name: &str, seed: &Seed, names: &[&str]) -> NodeEntry {
        NodeEntry { name: name.into(), key: fmt_key(&seed.public()), names: names.iter().map(|s| s.to_string()).collect(), addrs: vec![] }
    }

    pub fn unsigned(nodes: Vec<NodeEntry>) -> MemberList {
        MemberList { v: 2, network: "test".into(), seq: 1, issued: crate::now_ts(), operator: String::new(), nodes, sig: String::new() }
    }

    /// A signed, verified list of `(node name, node seed, names)`.
    pub fn list(nodes: &[(&str, &Seed, &[&str])]) -> MemberList {
        let op = Seed::generate();
        let mut l = unsigned(nodes.iter().map(|(n, s, names)| entry(n, s, names)).collect());
        l.sign(&op);
        l.verify(&op.public()).unwrap();
        l
    }

    fn signed(l: &MemberList) -> Result<()> {
        let op = Seed::generate();
        let mut l = l.clone();
        l.sign(&op);
        l.verify(&op.public())
    }

    #[test]
    fn signed_list_verifies_and_refuses_edits() {
        let op = Seed::generate();
        let node = Seed::generate();
        let mut l = list(&[("mac", &node, &[])]);
        l.sign(&op);
        assert!(l.verify(&op.public()).is_ok());
        assert!(l.verify(&Seed::generate().public()).is_err());
        let mut edited = l.clone();
        edited.nodes.push(entry("evil", &Seed::generate(), &[]));
        assert!(edited.verify(&op.public()).is_err());
        let mut edited = l.clone();
        edited.nodes[0].names = vec!["all.".into()];
        assert!(edited.verify(&op.public()).is_err());
        assert!(l.is_node(&node.public()));
        assert_eq!(l.node_keys(), vec![node.public()]);
    }

    #[test]
    fn v1_lists_are_refused() {
        let op = Seed::generate();
        let node = Seed::generate();
        let v1 = format!(
            r#"{{"v":1,"network":"test","seq":1,"issued":"","operator":"","members":[{{"name":"a.x","sub":"agent:a.x@t","key":"{k}"}}],"nodes":[{{"name":"n","key":"{k}","addrs":[]}}],"sig":""}}"#,
            k = fmt_key(&node.public())
        );
        let mut l: MemberList = serde_json::from_str(&v1).unwrap();
        l.sign(&op);
        assert!(l.verify(&op.public()).unwrap_err().to_string().contains("v1 is the old format"));
    }

    #[test]
    fn unsigned_file_may_omit_issued_operator_sig_and_names() {
        let node = Seed::generate();
        let raw = format!(r#"{{"v":2,"network":"n","seq":3,"nodes":[{{"name":"mac","key":"{}"}}]}}"#, fmt_key(&node.public()));
        let mut l: MemberList = serde_json::from_str(&raw).unwrap();
        assert_eq!((l.issued.as_str(), l.operator.as_str(), l.sig.as_str()), ("", "", ""));
        assert_eq!(l.nodes[0].namespace(), vec!["mac.".to_string()]);
        let op = Seed::generate();
        l.sign(&op);
        l.verify(&op.public()).unwrap();
        // The signed form round-trips through JSON to the same signing bytes.
        let back: MemberList = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back.signing_bytes(), l.signing_bytes());
        back.verify(&op.public()).unwrap();
    }

    #[test]
    fn namespaces_default_cover_and_resolve() {
        let (a, b) = (Seed::generate(), Seed::generate());
        let l = list(&[("mac", &a, &["sauersml.", "hypha"]), ("box", &b, &[])]);
        let at = |n: &str| l.node_for_name(n).map(|e| e.name.as_str());
        assert_eq!(at("sauersml.lead"), Some("mac"));
        assert_eq!(at("SauersML.Lead"), Some("mac"), "case-insensitive");
        assert_eq!(at("sauersml/lead"), Some("mac"), "'/' counts as '.'");
        assert_eq!(at("hypha"), Some("mac"));
        assert_eq!(at("box.worker"), Some("box"), "default namespace: the node name and '.'");
        assert_eq!(at("sauersml."), None, "a prefix does not cover itself");
        assert_eq!(at("sauersml"), None);
        assert_eq!(at("hypha.x"), None, "an exact entry is not a prefix");
        assert_eq!(at("will.orchestrator"), None);
    }

    #[test]
    fn overlapping_namespaces_are_refused() {
        let (a, b) = (Seed::generate(), Seed::generate());
        let cases: &[(&[&str], &[&str])] = &[
            (&["hypha"], &["Hypha"]),             // equal exacts (case-insensitive)
            (&["sauersml."], &["sauersml.lead"]), // an exact inside another node's prefix
            (&["sauersml.lead"], &["sauersml."]),
            (&["sauersml."], &["sauersml.team."]), // one prefix starts with the other
            (&["a."], &["a."]),
        ];
        for (x, y) in cases {
            let l = unsigned(vec![entry("one", &a, x), entry("two", &b, y)]);
            assert!(signed(&l).unwrap_err().to_string().contains("overlap"), "{x:?} vs {y:?}");
        }
        // A node's default namespace counts: "two." vs an exact "two.x" on another node.
        let l = unsigned(vec![entry("one", &a, &["two.x"]), entry("two", &b, &[])]);
        assert!(signed(&l).unwrap_err().to_string().contains("overlap"));
        // Disjoint: an exact name equal to another node's prefix without its dot, and sibling prefixes.
        let l = unsigned(vec![entry("one", &a, &["sauersml", "a.b."]), entry("two", &b, &["sauersml.", "a.c."])]);
        signed(&l).unwrap();
        // One node may list overlapping entries of its own.
        let l = unsigned(vec![entry("one", &a, &["x.", "x.y"])]);
        signed(&l).unwrap();
    }

    #[test]
    fn bad_entries_and_nodes_are_refused() {
        let (a, b) = (Seed::generate(), Seed::generate());
        for bad in ["all", "ALL", "*", "all.", ".x", "x..", "a b", "a|b", "a/b", "", ".", &"x".repeat(49), "é"] {
            let l = unsigned(vec![entry("one", &a, &[bad])]);
            assert!(signed(&l).unwrap_err().to_string().contains("not a valid name"), "{bad:?}");
        }
        for good in ["x", "x.", "sauersml.lead", "a-b_c.", &"x".repeat(48), &format!("{}.", "x".repeat(48))] {
            signed(&unsigned(vec![entry("one", &a, &[good])])).unwrap();
        }
        // A node name that makes an invalid default prefix.
        assert!(signed(&unsigned(vec![entry("my mac", &a, &[])])).is_err());
        // The same node key twice, a bad key, a bad node name.
        assert!(signed(&unsigned(vec![entry("one", &a, &["x"]), entry("two", &a, &["y"])])).unwrap_err().to_string().contains("twice"));
        let mut e = entry("one", &b, &[]);
        e.key = "ed25519:nope".into();
        assert!(signed(&unsigned(vec![e])).is_err());
        assert!(signed(&unsigned(vec![entry("a@b", &b, &["x."])])).is_err());
    }
}
