//! Room fields: meta JSON as the sender signed it, and sequences of events folded into a room state and planned.
#![no_main]
use arbitrary::Arbitrary;
use islandmail_core::room::{self, Event, Folded, Meta};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    meta: &'a str,
    id: &'a str,
    events: Vec<(u16, u8, &'a str)>,
    from: u8,
}

const WHO: [&str; 4] = ["a.alice", "a.bob", "c.carol", "A.Alice"];

fuzz_target!(|i: In| {
    let _ = Meta::parse(i.meta);
    let parsed: Vec<(String, &str, Event)> = i.events.iter().take(64).filter_map(|(t, w, raw)| {
        let e: Event = serde_json::from_str(raw).ok()?;
        Some((format!("2026-01-01T00:00:{:02}.{:03}Z", t / 1000 % 60, t % 1000), WHO[*w as usize % 4], e))
    }).collect();
    let ids: Vec<String> = (0..parsed.len()).map(|n| format!("{n:064x}")).collect();
    let mut folded: Vec<Folded> = parsed.iter().zip(&ids)
        .map(|((ts, from, e), id)| Folded { id, ts, from, event: e }).collect();
    for id in [i.id, "a.alice/plan", "dm:a.alice+a.bob", "general"] {
        let mut f: Vec<Folded> = folded.iter().map(|x| Folded { id: x.id, ts: x.ts, from: x.from, event: x.event }).collect();
        let s = room::fold(id, &mut f);
        // Folding is order-independent: the same events in reverse give the same state.
        let mut r: Vec<Folded> = f.into_iter().rev().collect();
        assert_eq!(room::fold(id, &mut r), s, "fold depends on input order");
        let from = WHO[i.from as usize % 4];
        let _ = room::plan(id, Some(&s), from, parsed.first().map(|p| &p.2));
        let _ = room::plan(id, None, from, None);
        let _ = (s.private(), s.is_member(from));
    }
    folded.clear();
});
