//! Fixed keys, a trust file and nodes for the fuzz targets. Everything is deterministic except the temporary paths,
//! so a crashing input replays the same way.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use islandmail_core::envelope::{post_digest_meta, Attest, Body, Draft, Envelope, Mode, PostStatement};
use islandmail_core::keys::{fmt_key, Seed};
use islandmail_core::members::{self, Member, MemberList, NodeEntry};
use islandmail_core::b64u;

use islandmail_node::node::{Node, Opts};
use islandmail_node::store::Store;

pub const NETWORK: [u8; 32] = [7; 32];

/// Node A, node B, then agents: alice (pinned, a.alice), bob (pinned, a.bob), carol (certified by node A as c.carol).
pub fn seed(i: u8) -> Seed {
    Seed::from_bytes([i + 1; 32])
}
pub fn node_a() -> Seed { seed(0) }
pub fn node_b() -> Seed { seed(1) }
pub fn alice() -> Seed { seed(10) }
pub fn bob() -> Seed { seed(11) }
pub fn carol() -> Seed { seed(12) }

pub fn network() -> String {
    b64u(&NETWORK)
}

/// The trust file every node in the world starts from.
pub fn list(seq: u64) -> MemberList {
    MemberList {
        v: 1,
        network: network(),
        seq,
        members: vec![
            Member { name: "a.alice".into(), sub: "agent:alice@test".into(), key: fmt_key(&alice().public()) },
            Member { name: "a.bob".into(), sub: "agent:bob@test".into(), key: fmt_key(&bob().public()) },
        ],
        nodes: vec![
            NodeEntry { name: "na".into(), key: fmt_key(&node_a().public()), addrs: vec!["192.0.2.1:4433".into()],
                        names: vec!["c.".into()] },
            NodeEntry { name: "nb".into(), key: fmt_key(&node_b().public()), addrs: vec![], names: vec!["d.".into()] },
        ],
        relays: vec![],
    }
}

static N: AtomicU64 = AtomicU64::new(0);

/// A fresh path under the temp dir (TMPDIR=/dev/shm keeps fuzzing off the disk).
pub fn temp_path(what: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("islandmail-fuzz-{}-{n}-{what}", std::process::id()))
}

/// A node with `seed` on a fresh store, trusting `list(1)`.
pub fn node(seed: Seed) -> Node {
    let list = &list(1);
    let db = temp_path("store.sqlite");
    let trust = temp_path("trust.json");
    std::fs::write(&trust, serde_json::to_vec(list).unwrap()).unwrap();
    let store = Store::open(&db).unwrap();
    store.bind_roster(&seed.public(), list).unwrap();
    let opts = Opts { public_url: "http://127.0.0.1:1".into(), relay: vec!["n0".into()], members_file: Some(trust),
                      ..Default::default() };
    Node::new(store, list.clone(), seed, opts, tokio::sync::mpsc::channel(1 << 16).0)
}

/// A members-mode message from alice, written by node B, at `ts_ms`.
pub fn plain(text: &str, thread: &str, ts_ms: i64, salt: u8) -> Envelope {
    let l = list(1);
    let agents = l.agents(&[], &|_| None, ts_ms);
    let (from, to, salt, recipients) = ("a.alice", "all", [salt; 16], l.all_keys());
    let ts = islandmail_core::ts_from_millis(ts_ms);
    let digest = post_digest_meta(&salt, text, &[], "").unwrap();
    let sub = &members::find(&agents, from, &alice().public()).unwrap().sub;
    let st = PostStatement { from, sub, to, thread, mode: Mode::Members, ts: &ts, digest: &digest, blobs: &[],
                             recipients: &recipients }.signing_bytes(&l);
    let attest = Attest { key: fmt_key(&alice().public()), digest, sig: b64u(&alice().sign(&st)), cert: None };
    let body = Body { text: text.into(), files: vec![], salt: b64u(&salt), meta: String::new() };
    Envelope::seal(Draft { thread, parents: vec![], ts, from, to, mode: Mode::Members, body: &body, blobs: vec![], attest,
                           recipients: &recipients }, &node_b()).unwrap()
}
