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
