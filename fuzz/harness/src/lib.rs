//! The islandmail-node modules compiled as a library (the node itself is a binary), plus fixed worlds: seeds, a trust
//! file and nodes on temporary stores. Shared by the fuzz targets and the protocol property tests.
#![allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::all)]

#[path = "../../../crates/islandmail-node/src/api.rs"]
pub mod api;
#[path = "../../../crates/islandmail-node/src/config.rs"]
pub mod config;
#[path = "../../../crates/islandmail-node/src/encryption_keys.rs"]
pub mod encryption_keys;
#[path = "../../../crates/islandmail-node/src/homes.rs"]
pub mod homes;
#[path = "../../../crates/islandmail-node/src/invite.rs"]
pub mod invite;
#[path = "../../../crates/islandmail-node/src/mcpl.rs"]
pub mod mcpl;
#[path = "../../../crates/islandmail-node/src/migrate.rs"]
pub mod migrate;
#[path = "../../../crates/islandmail-node/src/net.rs"]
pub mod net;
#[path = "../../../crates/islandmail-node/src/node.rs"]
pub mod node;
#[path = "../../../crates/islandmail-node/src/private_fs.rs"]
pub mod private_fs;
#[path = "../../../crates/islandmail-node/src/store.rs"]
pub mod store;
#[path = "../../../crates/islandmail-node/src/ui.rs"]
pub mod ui;

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
