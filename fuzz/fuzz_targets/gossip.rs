//! A gossip message from a member node: a certificate, a revocation, or an envelope, as `net` hands it to the node.
#![no_main]
use std::sync::OnceLock;

use islandmail_fuzz_harness::{node::Node, world};
use libfuzzer_sys::fuzz_target;

fn node() -> &'static Node {
    static N: OnceLock<Node> = OnceLock::new();
    N.get_or_init(|| world::node(world::node_a()))
}

fuzz_target!(|data: &[u8]| {
    let n = node();
    if islandmail_fuzz_harness::gossip_trust(n, data).is_none() {
        if let Ok(env) = serde_json::from_slice::<islandmail_core::Envelope>(data) {
            let _ = n.ingest(env.clone());
            // A second copy is a duplicate, never a second row.
            assert!(!matches!(n.ingest(env), Ok(Some(_))), "the same envelope stored twice");
        }
    }
});
