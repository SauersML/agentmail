//! The sealed part after decryption: any plaintext a member node seals (padded or not; header and body JSON or not)
//! through unpad, the inner parse, verify_opened and check_body, then through a receiving node's ingest.
#![no_main]
use std::sync::OnceLock;

use islandmail_core::crypto;
use islandmail_fuzz_harness::{node::Node, world};
use libfuzzer_sys::fuzz_target;

fn node() -> &'static Node {
    static N: OnceLock<Node> = OnceLock::new();
    N.get_or_init(|| world::node(world::node_a()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let inner = if mode & 1 == 1 { crypto::pad(rest, crypto::BODY_CHUNK).unwrap() } else { rest.to_vec() };
    let _ = crypto::unpad(&inner);
    let base = world::plain("x", "t", islandmail_core::now_millis() - 5000, 1);
    let env = world::reseal_inner(&base, &inner, &world::node_b());
    let l = world::list(1);
    let agents = l.agents(&[], &|_| None, env.ts_ms());
    match env.open(&world::node_a()) {
        Ok(Some(o)) => {
            if env.verify_opened(&o, &l, &agents).is_ok() {
                env.check_body(&o.header, &o.body).unwrap();
            }
            if let Ok(m) = islandmail_core::room::Meta::parse(&o.body.meta) {
                if let Some(e) = &m.event { let _ = (e.describe(), e.added()); }
            }
        }
        Ok(None) => panic!("a members-mode envelope opens for every member node"),
        Err(_) => {}
    }
    // Only padded lengths pass the forwarding check; those reach ingest.
    if env.check(&l, islandmail_core::now_millis()).is_ok() {
        // Mail that opens here but does not verify is refused (an Err), so a later sync can offer it again.
        if let Ok(row) = node().ingest(env.clone()) {
            if let Some(r) = row {
                let _ = r.to_message();
            }
            assert!(node().ingest(env).unwrap().is_none());
        }
    }
});
