//! The small decoders every parser leans on: base64url, base58 (invites), base32 ids and id prefixes, timestamps, keys
//! and hex seeds, addresses and room names. Each round-trips where it claims to.
#![no_main]
use islandmail_core as core;
use islandmail_fuzz_harness::invite::{b58, b58_decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 2048 {
        assert_eq!(b58_decode(&b58(data)).unwrap(), data);
    }
    assert_eq!(core::b64u_decode(&core::b64u(data)).unwrap(), data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    if s.len() <= 1024 {
        if let Some(b) = b58_decode(s) {
            assert_eq!(b58(&b), s, "one base58 spelling per byte string");
        }
    }
    let _ = core::b64u_decode(s);
    let _ = core::b32_id(s);
    let _ = core::short_id(s);
    if let Some((lo, hi)) = core::id_prefix_range(s) {
        assert!(lo <= hi && lo.len() == 64 && hi.len() == 64);
        let id = core::b32_id(&lo);
        assert!(id.starts_with(&s.to_ascii_lowercase()), "{id} {s}");
    }
    if let Some(ms) = core::parse_ts(s) {
        assert_eq!(core::ts_from_millis(ms), s);
    }
    if let Ok(k) = core::keys::parse_key(s) {
        let _ = core::keys::x25519_public(&k);
        let _ = core::keys::fmt_key(&k);
    }
    if let Ok(seed) = core::keys::Seed::from_hex(s) {
        assert_eq!(seed.to_hex(), s.to_ascii_lowercase());
    }
    let _ = (core::addr::norm(s), core::addr::is_broadcast(s), core::addr::addressed_to(s, &["a.alice", "b."]));
    let _ = (core::cert::valid_name(s), core::cert::valid_agent_name(s), core::cert::valid_namespace_entry(s));
    let _ = core::cert::entry_covers(s, "c.carol");
    let _ = (core::home::split_name(s), core::home::valid_domain(s), core::home::is_home_name(s));
    let _ = (core::room::valid_room_name(s), core::room::valid_room_id(s), core::room::dm_pair(s), core::room::creator_of(s));
    if core::room::valid_room_id(s) {
        let _ = core::room::room_to(s);
    }
    let m = core::room::mentions_in(s);
    assert!(m.len() <= core::room::MAX_MENTIONS);
    let _ = core::aid1::valid_jti(s);
    let _ = core::envelope::is_id(s);
});
