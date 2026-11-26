//! The one request an untrusted key may make (ALPN islandmail/join/1): any bytes from any peer key, and well-signed
//! replies with fuzzer-chosen layouts against a live invite. Only the exact invited name is ever trusted, and only
//! once per nonce.
#![no_main]
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use islandmail_fuzz_harness::{invite, node::Node, world};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    raw: &'a [u8],
    peer: u8,
    flags: u8,
    use_nonce: bool,
    name: &'a str,
    rest: &'a [u8],
}

struct S {
    node: Node,
    nonce: [u8; 16],
    seq: std::sync::atomic::AtomicU64,
}

fn state() -> &'static S {
    static S_: OnceLock<S> = OnceLock::new();
    S_.get_or_init(|| {
        let node = world::node(world::node_a());
        let inv = world::make_invite(&node, "e.erin", "a.alice/plan");
        let nonce = invite::read_invite(&inv, islandmail_core::now_millis()).unwrap().nonce;
        S { node, nonce, seq: 1.into() }
    })
}

/// Back to the starting trust file and an unspent invite, so every input sees the same node.
fn reset(s: &S) {
    let seq = s.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 100;
    let l = world::list(seq.max(s.node.members_seq() + 1));
    std::fs::write(s.node.opts.members_file.as_ref().unwrap(), serde_json::to_vec(&l).unwrap()).unwrap();
    s.node.reload_members(&l).unwrap();
    islandmail_fuzz_harness::unspend_invites(&s.node);
}

fuzz_target!(|i: In| {
    let s = state();
    let peer = world::seed(50 + i.peer % 4);
    let before = s.node.members.read().unwrap().clone();
    let _ = invite::handshake(&s.node, &peer.public(), i.raw);
    // A well-signed reply with a fuzzer-chosen layout.
    let mut p = vec![i.flags];
    p.extend_from_slice(&world::NETWORK);
    p.extend_from_slice(&peer.public());
    p.extend_from_slice(&if i.use_nonce { s.nonce } else { [0; 16] });
    p.push(i.name.len().min(255) as u8);
    p.extend_from_slice(&i.name.as_bytes()[..i.name.len().min(255)]);
    p.extend_from_slice(i.rest);
    let reply = world::sign_reply(&peer, &p);
    let out: serde_json::Value = serde_json::from_slice(&invite::handshake(&s.node, &peer.public(), reply.as_bytes())).unwrap();
    let after = s.node.members.read().unwrap().clone();
    if out["ok"] == true {
        assert_eq!(out["name"], "e.erin", "trusted for a name it was not invited for: {out}");
        let entry = after.node_by_key(&peer.public()).expect("joined node listed");
        assert!(entry.names.iter().all(|n| n == "e.erin"), "{entry:?}");
        // Nothing else changed: same pins, and every other node kept its names.
        assert_eq!(after.members, before.members);
        for n in &before.nodes {
            assert_eq!(after.nodes.iter().find(|m| m.key == n.key).map(|m| &m.names), Some(&n.names));
        }
        // The nonce is spent: another key with the same reply layout is refused.
        let other = world::seed(60);
        let r2 = world::reply(&other, &s.nonce, "e.erin", &[]);
        let v: serde_json::Value = serde_json::from_slice(&invite::handshake(&s.node, &other.public(), r2.as_bytes())).unwrap();
        assert!(v["ok"] != true, "a spent nonce admitted a second node: {v}");
        reset(s);
    } else {
        assert_eq!(after, before, "a refused join changed the trust file: {out}");
    }
});
