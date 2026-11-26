//! A peer's announced encryption key (sync `certs` answer) and the trust file's home entries with their proofs.
#![no_main]
use islandmail_core::home::{HomeEntry, HomeProof};
use islandmail_core::node_key::NodeEncryptionKey;
use islandmail_fuzz_harness::world;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let now = 1_700_000_000_000;
    if let Ok(k) = serde_json::from_slice::<NodeEncryptionKey>(data) {
        let _ = k.verify(&world::node_b().public(), &world::network(), now);
        let _ = k.verify(&world::node_b().public(), &k.network, k.epoch.saturating_mul(islandmail_core::node_key::ROTATION_MS));
    }
    if let Ok((h, name, key, p)) = serde_json::from_slice::<(HomeEntry, String, String, HomeProof)>(data) {
        if h.validate().is_ok() {
            let _ = h.covers(&name);
            let _ = h.check(&name, &key, &p, &islandmail_core::home::audience(&world::network()), now);
        }
    }
});
