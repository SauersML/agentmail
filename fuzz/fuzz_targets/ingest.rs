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
    ts_back_s: u32,
    salt: [u8; 16],
    reader: u8,
}

fn node() -> &'static Node {
    static N: OnceLock<Node> = OnceLock::new();
    N.get_or_init(|| world::node(world::node_a()))
}

fuzz_target!(|i: In| {
    let n = node();
    let l = world::list(1);
    let now = islandmail_core::now_millis();
    let ts_ms = now - i64::from(i.ts_back_s % 86_400) * 1000;
    let agents = l.agents(&[], &|_| None, ts_ms);
    let (signer, default_from) = match i.signer % 3 { 0 => (world::alice(), "a.alice"), 1 => (world::bob(), "a.bob"), _ => (world::carol(), "c.carol") };
    let from = if i.from.is_empty() { default_from.to_string() } else { i.from.clone() };
    let files: Vec<serde_json::Value> = serde_json::from_str(&i.files).unwrap_or_default();
    let m = world::Mail {
        from, to: i.to.clone(), thread: i.thread.clone(), text: i.text.clone(), meta: i.meta.clone(), files,
        blobs: i.blobs.iter().take(12).map(|b| blake3::Hash::from_bytes(*b).to_hex().to_string()).collect(),
        parents: i.parents.iter().take(20).map(|p| blake3::hash(&[*p]).to_hex().to_string()).collect(),
        private: i.private, ts_ms, salt: i.salt,
    };
    let Ok(env) = world::envelope(&l, &agents, &world::node_b(), &signer, &m, None) else { return };
    let first = n.ingest(env.clone());
    if let Ok(Some(row)) = &first {
        assert_eq!(row.env_id, env.id);
        assert!(matches!(n.ingest(env.clone()), Ok(None)), "duplicate stored twice");
        let _ = islandmail_fuzz_harness::node::format_message(row, 2000, "http://127.0.0.1:1");
        let _ = row.to_message();
    }
    let _ = i.reader;
});
