//! MCP over WebSocket (/mcpl): newline-delimited JSON-RPC frames from a signed-in agent, through every method and
//! tool the node answers, on a node holding some mail.
#![no_main]
use std::sync::{Arc, OnceLock};

use arbitrary::Arbitrary;
use islandmail_fuzz_harness::{mcpl, node::Node, world};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    frames: Vec<&'a str>,
    bob: bool,
}

fn node() -> &'static Arc<Node> {
    static N: OnceLock<Arc<Node>> = OnceLock::new();
    N.get_or_init(|| {
        let n = Arc::new(world::node(world::node_a()));
        let now = islandmail_core::now_millis();
        for i in 0..3 {
            n.ingest(world::plain(&format!("hello {i} @a.bob"), "general", now - 1000 * i, i as u8)).unwrap();
        }
        n
    })
}

fuzz_target!(|i: In| {
    let n = node();
    let (seed, name, sub) = if i.bob { (world::bob(), "a.bob", "agent:bob@test") } else { (world::alice(), "a.alice", "agent:alice@test") };
    let token = islandmail_core::agent_token::mint(&seed, name, sub, &world::node_a().public(), islandmail_core::now_millis(), 600);
    let who = n.verify(&token).map_err(|e| e.message).unwrap();
    let frames: Vec<&str> = i.frames.iter().take(16).copied().collect();
    for out in mcpl::fuzz_frames(n.clone(), who, &frames) {
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok(), "the node sent a frame that is not JSON: {out}");
    }
});
