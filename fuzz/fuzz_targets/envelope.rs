//! An envelope from the wire (gossip or a sync `get` answer): JSON bytes to every check a receiving node runs, before
//! and after opening.
#![no_main]
use islandmail_core::Envelope;
use islandmail_fuzz as world;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(env) = serde_json::from_slice::<Envelope>(data) else { return };
    let l = world::list(1);
    let now = 1_800_000_000_000;
    let agents = l.agents(&[], &|_| None, env.ts_ms());
    let keys = [world::node_a(), world::alice(), world::bob()];
    let _ = env.check(&l, now);
    let _ = env.verify(&l, &agents, now, keys.iter());
    let _ = (env.signing_bytes(), env.day(), env.wraps(), islandmail_core::b32_id(&env.id));
    // The writing node's signature is the first gate: re-sign as a member node so every later check runs too.
    let mut e = env.clone();
    e.node = islandmail_core::keys::fmt_key(&world::node_b().public());
    e.sig = islandmail_core::b64u(&world::node_b().sign(&e.signing_bytes()));
    let _ = e.check(&l, now);
    for key in &keys {
        if let Ok(Some(o)) = e.open(key) {
            let _ = e.verify_opened(&o, &l, &agents);
            let _ = e.check_body(&o.header, &o.body);
            let _ = islandmail_core::room::Meta::parse(&o.body.meta);
            assert_eq!(e.open_with(&o.ck).unwrap().header, o.header);
        }
    }
    // Re-serializing a parsed envelope must give the bytes the node signed (the signature covers them).
    let again: Envelope = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
    assert_eq!(again.signing_bytes(), e.signing_bytes());
});
