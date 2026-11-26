//! Compact invites (`im1…`) and replies (`imr1…`): raw strings as pasted, and fuzzer-chosen payloads signed by the
//! key they name (so the byte layout behind the signature is what gets fuzzed).
#![no_main]
use arbitrary::Arbitrary;
use islandmail_fuzz_harness::{invite, world};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    raw: &'a str,
    flags: u8,
    exp_s: u32,
    nonce: [u8; 16],
    rest: &'a [u8],
}

fuzz_target!(|i: In| {
    let now = 1_700_000_000_000;
    let _ = invite::read_invite(i.raw, now);
    let _ = invite::read_reply(i.raw);
    let key = world::seed(40);
    let mut p = vec![i.flags];
    p.extend_from_slice(&world::NETWORK);
    p.extend_from_slice(&key.public());
    p.extend_from_slice(&i.exp_s.to_be_bytes());
    p.extend_from_slice(&i.nonce);
    p.extend_from_slice(i.rest);
    if let Ok(inv) = invite::read_invite(&world::sign_invite(&key, &p), now) {
        assert!(inv.exp > now && islandmail_core::cert::valid_name(&inv.name));
        assert_eq!(inv.node.key, islandmail_core::keys::fmt_key(&key.public()));
    }
    // The reply layout has no expiry.
    let mut r = vec![i.flags];
    r.extend_from_slice(&world::NETWORK);
    r.extend_from_slice(&key.public());
    r.extend_from_slice(&i.nonce);
    r.extend_from_slice(i.rest);
    if let Ok(rep) = invite::read_reply(&world::sign_reply(&key, &r)) {
        assert!(islandmail_core::cert::valid_name(&rep.name));
        assert_eq!(rep.node.names.len(), 0);
    }
});
