//! The islandmail-node modules compiled as a library (the node itself is a binary), plus fixed worlds: seeds, a trust
//! file and nodes on temporary stores. Shared by the fuzz targets and the protocol property tests.
#![allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::all)]

// Every module the node declares in its main.rs (see build.rs), each at its source file.
include!(concat!(env!("OUT_DIR"), "/node_modules.rs"));

pub mod world;

/// `net::answer`: a member node's sync request, answered.
pub fn sync_answer(node: &node::Node, peer: &[u8; 32], req: &[u8]) -> anyhow::Result<Vec<u8>> {
    net::answer(node, peer, req)
}

/// `net::trust_message`: a gossiped certificate or revocation; None for anything else.
pub fn gossip_trust(node: &node::Node, raw: &[u8]) -> Option<anyhow::Result<bool>> {
    net::trust_message(node, raw)
}

/// Marks every invite of `node` unspent again (fuzz targets reset between inputs).
pub fn unspend_invites(node: &node::Node) {
    node.store.conn().execute("UPDATE join_invites SET spent_by = NULL, spent_ms = NULL", []).unwrap();
}

/// Every stored row as (env_id, mode, sender, thread, text), by env_id: what a node holds, for comparing nodes.
pub fn rows(node: &node::Node) -> Vec<(String, String, String, String, Option<String>)> {
    let db = node.store.conn();
    let mut st = db.prepare("SELECT env_id, mode, sender, thread, text FROM messages ORDER BY env_id").unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap()
        .collect::<rusqlite::Result<_>>().unwrap()
}
