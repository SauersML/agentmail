//! Agent tokens as the API sees them in `Authorization: Bearer`: raw strings, and fuzzer-chosen claims signed by a
//! pinned agent (so every check after the signature runs).
#![no_main]
use arbitrary::Arbitrary;
use islandmail_core::{agent_token, paseto};
use islandmail_fuzz_harness::world;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    token: &'a str,
    claims: &'a [u8],
    signer: u8,
    now_s: u32,
}

fuzz_target!(|i: In| {
    let l = world::list(1);
    let agents = l.agents(&[], &|_| None, 0);
    let node = world::node_a().public();
    let now = 1_700_000_000_000 + i64::from(i.now_s) * 1000;
    let _ = agent_token::verify(i.token, &agents, &node, now);
    let signer = if i.signer % 2 == 0 { world::alice() } else { world::bob() };
    let t = paseto::sign(&signer, i.claims, b"", agent_token::IMPLICIT);
    if let Ok(c) = agent_token::verify(&t, &agents, &node, now) {
        // Accepted: it names the signer's own entry, for this node, live now.
        let a = agents.iter().find(|a| a.name == c.name).unwrap();
        assert_eq!(islandmail_core::keys::fmt_key(&a.key), c.key);
        assert_eq!(a.key, signer.public());
        assert!(c.exp_ms > now);
    }
});
