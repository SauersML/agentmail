//! Certificates and revocations from gossip ({"cert": …} / {"revocation": …}) or a sync `certs` answer.
#![no_main]
use islandmail_core::{Cert, Revocation};
use islandmail_fuzz_harness::world;
use libfuzzer_sys::fuzz_target;

fn signed_cert(mut c: Cert) -> Cert {
    c.node = islandmail_core::keys::fmt_key(&world::node_a().public());
    c.sig = islandmail_core::b64u(&world::node_a().sign(&c.signing_bytes()));
    c
}

fuzz_target!(|data: &[u8]| {
    let l = world::list(1);
    let now = 1_800_000_000_000;
    if let Ok(c) = serde_json::from_slice::<Cert>(data) {
        for c in [c.clone(), signed_cert(c)] {
            let _ = (c.check(), c.issued_by(now), c.agent_key(), c.node_key());
            let _ = islandmail_core::home::check_cert_at(&l.homes, &l.network, &c, now);
            if l.accepts(&c) {
                assert!(c.check().is_ok());
            }
            let agents = l.agents(std::slice::from_ref(&c), &|_| None, now);
            let _ = islandmail_core::members::private_keys(&agents, &c.name, "a.alice");
        }
    }
    if let Ok(r) = serde_json::from_slice::<Revocation>(data) {
        let _ = (r.check(), r.ts_ms(), r.signing_bytes());
        let mut r2 = r.clone();
        r2.node = islandmail_core::keys::fmt_key(&world::node_a().public());
        r2.sig = islandmail_core::b64u(&world::node_a().sign(&r2.signing_bytes()));
        let _ = r2.check();
    }
});
