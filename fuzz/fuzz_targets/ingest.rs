//! Validly signed envelopes with fuzzer-chosen headers and bodies (text, room meta, attachments, parents, mode,
//! time): what a member agent and its node can put on the wire, through ingest, the store and the readers' views.
#![no_main]
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use islandmail_fuzz_harness::{node::Node, world};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In {
    signer: u8,
    from: String,
    to: String,
    thread: String,
    text: String,
    meta: String,
    files: String,
    blobs: Vec<[u8; 32]>,
    parents: Vec<u8>,
    private: bool,
    outsider: bool,
    ts_back_s: u32,
    salt: [u8; 16],
    reader: u8,
}

/// A node outside every trust file, and eve, an agent only the room's creator vouches for (through that node).
fn outsider() -> islandmail_core::keys::Seed { world::seed(5) }
fn eve() -> islandmail_core::keys::Seed { world::seed(13) }
const ROOM: &str = "a.alice/r";

/// Node A, holding alice's open room a.alice/r (written by node B) and alice's vouch for eve at the outsider node.
fn node() -> &'static Node {
    static N: OnceLock<Node> = OnceLock::new();
    N.get_or_init(|| {
        let n = world::node(world::node_a());
        let l = world::list(1);
        let now = islandmail_core::now_millis();
        let agents = l.agents(&[], &|_| None, now);
        let vouch = serde_json::json!({ "room": ROOM, "event": { "op": "vouch", "members": [{ "name": "x.eve",
            "sub": "agent:x.eve", "key": islandmail_core::keys::fmt_key(&eve().public()),
            "nodes": [islandmail_core::keys::fmt_key(&outsider().public())] }] } });
        let create = serde_json::json!({ "room": ROOM, "event": { "op": "create", "members": ["a.bob"] } });
        for (k, meta) in [create, vouch].iter().enumerate() {
            let m = world::Mail { from: "a.alice".into(), to: islandmail_core::room::room_to(ROOM), thread: ROOM.into(),
                                  text: "room".into(), meta: meta.to_string(), ts_ms: now - 60_000 + k as i64, salt: [k as u8; 16],
                                  ..Default::default() };
            let e = world::envelope(&l, &agents, &world::node_b(), &world::alice(), &m, None).unwrap();
            assert!(n.ingest(e).unwrap().is_some_and(|r| r.text.is_some()), "room setup message {k} not read");
        }
        assert_eq!(n.room_vouched(ROOM, &l).unwrap().len(), 1, "the vouch for eve does not count");
        n
    })
}

fuzz_target!(|i: In| {
    let n = node();
    let l = world::list(1);
    let now = islandmail_core::now_millis();
    let ts_ms = now - i64::from(i.ts_back_s % 86_400) * 1000;
    let agents = l.agents(&[], &|_| None, ts_ms);
    let (signer, default_from) = match i.signer % 4 {
        0 => (world::alice(), "a.alice"), 1 => (world::bob(), "a.bob"), 2 => (world::carol(), "c.carol"), _ => (eve(), "x.eve"),
    };
    let from = if i.from.is_empty() { default_from.to_string() } else { i.from.clone() };
    let files: Vec<serde_json::Value> = serde_json::from_str(&i.files).unwrap_or_default();
    let m = world::Mail {
        from, to: i.to.clone(), thread: i.thread.clone(), text: i.text.clone(), meta: i.meta.clone(), files,
        blobs: i.blobs.iter().take(12).map(|b| blake3::Hash::from_bytes(*b).to_hex().to_string()).collect(),
        parents: i.parents.iter().take(20).map(|p| blake3::hash(&[*p]).to_hex().to_string()).collect(),
        private: i.private, ts_ms, salt: i.salt,
    };
    let writer = if i.outsider { outsider() } else { world::node_b() };
    let Ok(env) = world::envelope(&l, &agents, &writer, &signer, &m, None) else { return };
    let first = n.ingest(env.clone());
    if let Ok(Some(row)) = &first {
        assert_eq!(row.env_id, env.id);
        // A node outside the trust file gets mail read here only for eve, only in the room that vouched for it.
        if i.outsider {
            assert!(row.text.is_none() || (row.thread == ROOM && row.sender == "x.eve"),
                    "an untrusted node's envelope was read here: {} in {}", row.sender, row.thread);
        }
        assert!(matches!(n.ingest(env.clone()), Ok(None)), "duplicate stored twice");
        let _ = islandmail_fuzz_harness::node::format_message(row, 2000, "http://127.0.0.1:1");
        let _ = row.to_message();
    }
    let _ = i.reader;
});
