//! Helpers shared by the unit tests: signed member lists, nodes on temporary stores, certified agents.

use std::path::PathBuf;

use mailcore::keys::{fmt_key, PublicKey, Seed};
use mailcore::{Envelope, MemberList, NodeEntry};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::node::{Caller, Node, Opts, Outbound};
use crate::store::Store;

/// A fresh path under the temp folder.
pub fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mailnode-{tag}-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())))
}

/// An operator-signed v2 list of `(node name, node seed, names)`; empty names mean the default "<node name>.".
pub fn list(op: &Seed, nodes: &[(&str, &Seed, &[&str])], seq: u64) -> MemberList {
    let mut l = MemberList {
        v: 2,
        network: "t".into(),
        seq,
        issued: mailcore::now_ts(),
        operator: String::new(),
        nodes: nodes
            .iter()
            .map(|(n, s, names)| NodeEntry {
                name: n.to_string(),
                key: fmt_key(&s.public()),
                names: names.iter().map(|x| x.to_string()).collect(),
                addrs: vec![],
            })
            .collect(),
        sig: String::new(),
    };
    l.sign(op);
    l.verify(&op.public()).expect("test list verifies");
    l
}

/// A node with `seed` on `list`, holding `identities`, on a temporary store.
pub fn node(list: &MemberList, op: &Seed, seed: &Seed, identities: Vec<(String, Seed)>) -> (Node, mpsc::UnboundedReceiver<Outbound>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let opts = Opts { identities, members_path: None, public_url: "http://127.0.0.1:8787".into() };
    let store = Store::open(&temp_path("node")).unwrap();
    (Node::new(store, list.clone(), op.public(), seed.clone(), opts, tx), rx)
}

/// A POST /api/agents body: `agent`'s issuance proof for `name` at `node`.
pub fn proof(agent: &Seed, name: &str, node: &PublicKey) -> Value {
    let ts = mailcore::now_ts();
    let key = fmt_key(&agent.public());
    let st = mailcore::cert::certify_statement(name, &key, &fmt_key(node), &ts);
    json!({ "name": name, "key": key, "ts": ts, "sig": mailcore::b64u(&agent.sign(st.as_bytes())) })
}

/// A fresh single-use agent token for `name` on `node`.
pub fn token(agent: &Seed, name: &str, node: &Node) -> String {
    mailcore::agent_token::mint(agent, name, &node.seed.public(), mailcore::now_millis(), 600)
}

/// Certifies `agent` as `name` on `node` (201 or 200) and signs it in.
pub fn sign_in(node: &Node, agent: &Seed, name: &str) -> Caller {
    let (st, _) = node.certify(&proof(agent, name, &node.seed.public())).unwrap_or_else(|e| panic!("{}", e.message));
    assert!(st == 200 || st == 201);
    node.verify(&token(agent, name, node)).unwrap_or_else(|e| panic!("{}", e.message))
}

/// The next envelope the node announced (skipping certificates and revocations).
pub fn next_env(rx: &mut mpsc::UnboundedReceiver<Outbound>) -> Envelope {
    loop {
        match rx.try_recv().expect("an announcement") {
            Outbound::Envelope(e) => return *e,
            _ => continue,
        }
    }
}

/// `{ts, salt, sig}` of `agent`'s signed post as `from` (members mode).
pub fn signed(agent: &Seed, from: &str, to: &str, thread: &str, text: &str, files: &[String]) -> Value {
    let ts = mailcore::now_ts();
    let salt = mailcore::random_bytes::<16>();
    let digest = mailcore::envelope::post_digest(&salt, text, files);
    let st = mailcore::envelope::post_statement(from, to, thread, mailcore::Mode::Members, &ts, &digest);
    json!({ "ts": ts, "salt": mailcore::b64u(&salt), "sig": mailcore::b64u(&agent.sign(st.as_bytes())) })
}
