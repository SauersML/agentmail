//! A sync request (ALPN islandmail/sync/1) from a member node: any bytes to `answer`, against a node holding mail,
//! a certificate and a blob.
#![no_main]
use std::sync::OnceLock;

use islandmail_fuzz_harness::{node::Node, world};
use libfuzzer_sys::fuzz_target;

fn node() -> &'static Node {
    static N: OnceLock<Node> = OnceLock::new();
    N.get_or_init(|| {
        let n = world::node(world::node_a());
        let now = islandmail_core::now_millis();
        for i in 0..5 {
            n.ingest(world::plain(&format!("hello {i}"), "t", now - 1000 * i, i as u8)).unwrap();
        }
        let c = islandmail_core::Cert::issue(&world::node_a(), "c.carol", &world::carol().public(), &islandmail_core::now_ts());
        let _ = n.take_cert(&c);
        let blob = vec![9u8; 64];
        n.store.put_blob(&blake3::hash(&blob).to_hex(), &blob, now).unwrap();
        n
    })
}

fuzz_target!(|data: &[u8]| {
    let n = node();
    let peer = world::node_b().public();
    if let Ok(resp) = islandmail_fuzz_harness::sync_answer(n, &peer, data) {
        let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert!(v.is_object());
    }
    // Only member nodes get answers.
    assert!(islandmail_fuzz_harness::sync_answer(n, &world::alice().public(), data).is_err());
});
