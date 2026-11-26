//! The trust file (local, but edited by invite/join/accept and by hand) and every derivation from it.
#![no_main]
use islandmail_fuzz_harness::{config::Config, world};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(l) = Config::parse_members(data) else { return };
    // A parsed list is a validated one.
    l.validate().unwrap();
    let _ = (l.topic(), l.all_keys(), l.node_keys());
    let agents = l.agents(&[], &|_| None, 0);
    for a in agents.iter().take(8) {
        let _ = islandmail_core::members::private_keys(&agents, &a.name, "a.alice");
        let _ = l.permits_agent_key(&a.name, &a.key);
    }
    for n in l.nodes.iter().take(8) {
        let _ = n.covers("c.carol");
    }
    let again = Config::parse_members(&serde_json::to_vec(&l).unwrap()).unwrap();
    assert_eq!(again, l);
    let _ = world::network();
});
