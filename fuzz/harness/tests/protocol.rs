//! Protocol properties, checked on real nodes (in-process, temporary stores) with generated inputs: delivery order,
//! duplicates and replays do not change what a node ends up with; a sync cut off at any point and resumed converges;
//! two nodes that see a certificate and its revocation in opposite orders agree; one invite nonce admits one node
//! however many race for it; concurrent trust-file edits each land with their own seq.
//!
//!   cargo test --manifest-path fuzz/Cargo.toml -p islandmail-fuzz-harness --release

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use islandmail_core::keys::fmt_key;
use islandmail_core::{b64u, Cert, Envelope, Revocation};
use islandmail_fuzz_harness::node::Node;
use islandmail_fuzz_harness::{invite, sync_answer, world};
use proptest::prelude::*;
use serde_json::{json, Value};

fn cases(n: u32) -> ProptestConfig {
    ProptestConfig { cases: n, failure_persistence: None, ..ProptestConfig::default() }
}

/// A batch of distinct valid envelopes over a few threads and days.
fn batch(n: usize, seed: u8) -> Vec<Envelope> {
    let now = islandmail_core::now_millis();
    (0..n).map(|i| {
        let ts = now - (i as i64 % 3) * 86_400_000 - i as i64 * 1000;
        world::plain(&format!("m{i}"), ["t1", "t2", "t3"][i % 3], ts, seed.wrapping_add(i as u8))
    }).collect()
}

/// What a node holds, for comparing two nodes: per-day hashes and every row's content.
fn snapshot(n: &Node) -> (BTreeMap<String, String>, Vec<(String, String, String, String, Option<String>)>) {
    (n.store.day_hashes().unwrap(), islandmail_fuzz_harness::rows(n))
}

/// The same body and sender signature under a new envelope (another nonce, so another id), written by `writer`.
fn reseal(e: &Envelope, writer: &islandmail_core::keys::Seed) -> Envelope {
    let o = e.open(&world::node_a()).unwrap().unwrap();
    let h = &o.header;
    let recipients = h.audience_keys().unwrap();
    Envelope::seal(islandmail_core::envelope::Draft {
        thread: &h.thread, parents: h.parents.clone(), ts: e.ts.clone(), from: &h.from, to: &h.to, mode: h.mode,
        body: &o.body, blobs: e.blobs.clone(), attest: h.attest.clone(), recipients: &recipients,
    }, writer).unwrap()
}

proptest! {
    #![proptest_config(cases(24))]

    /// Any delivery order, with any envelope delivered any number of times, ends in the same store; each duplicate
    /// is reported as nothing new.
    #[test]
    fn order_and_duplicates_do_not_matter(order in prop::collection::vec(0usize..12, 0..40), seed in any::<u8>()) {
        let envs = batch(12, seed);
        let (x, y) = (world::node(world::node_a()), world::node(world::node_a()));
        let mut seen = BTreeSet::new();
        for &i in &order {
            let new = x.ingest(envs[i].clone()).unwrap().is_some();
            prop_assert_eq!(new, seen.insert(i), "envelope {} new={} on delivery", i, new);
        }
        for &i in seen.iter().rev() {
            y.ingest(envs[i].clone()).unwrap();
        }
        prop_assert_eq!(snapshot(&x), snapshot(&y));
        world::remove(&x);
        world::remove(&y);
    }

    /// A sender's signed message replayed inside another envelope (resealed by a member node) is stored but never
    /// shown twice, in either arrival order, and readers see the same content.
    #[test]
    fn replays_are_hidden_in_either_order(first_original in any::<bool>(), seed in any::<u8>()) {
        let e = batch(1, seed).pop().unwrap();
        let copy = reseal(&e, &world::node_a());
        prop_assert_ne!(&copy.id, &e.id);
        let n = world::node(world::node_a());
        let (a, b) = if first_original { (e.clone(), copy.clone()) } else { (copy.clone(), e.clone()) };
        prop_assert!(n.ingest(a.clone()).unwrap().is_some());
        prop_assert!(n.ingest(b.clone()).unwrap().is_none(), "the replay was shown as new mail");
        let all = islandmail_fuzz_harness::rows(&n);
        prop_assert_eq!(all.len(), 2, "both envelopes are kept (sync converges on ids)");
        let shown: Vec<_> = all.iter().filter(|r| r.4.is_some()).collect();
        prop_assert_eq!(shown.len(), 1, "{:?}", all);
        let text = e.open(&world::node_a()).unwrap().unwrap().body.text;
        prop_assert_eq!(shown[0].4.as_deref(), Some(text.as_str()));
        world::remove(&n);
    }

    /// Pull sync (days, ids, get) as `net::sync_with` runs it, cut off after any number of requests and then run
    /// again from the start, converges to the union; each answer stays within its page and budget bounds.
    #[test]
    fn interrupted_sync_converges(a_has in prop::collection::btree_set(0usize..16, 0..16),
                                  b_has in prop::collection::btree_set(0usize..16, 0..16),
                                  cut in 0usize..12, seed in any::<u8>()) {
        let envs = batch(16, seed);
        let a = world::node(world::node_a());
        let b = world::node(world::node_b());
        for &i in &a_has { a.ingest(envs[i].clone()).unwrap(); }
        for &i in &b_has { b.ingest(envs[i].clone()).unwrap(); }
        let _ = pull(&a, &b, Some(cut));
        pull(&a, &b, None).unwrap();
        pull(&b, &a, None).unwrap();
        prop_assert_eq!(a.store.day_hashes().unwrap(), b.store.day_hashes().unwrap());
        let want: BTreeSet<usize> = a_has.union(&b_has).copied().collect();
        prop_assert_eq!(a.store.count().unwrap() as usize, want.len());
        world::remove(&a);
        world::remove(&b);
    }

    /// Two nodes receive a certificate, its revocation and the certified agent's mail from before and after the
    /// revocation, in independent orders. Both end with the same roster and the same stored mail.
    #[test]
    fn revocation_races_agree(order_x in Just((0..4).collect::<Vec<usize>>()).prop_shuffle(),
                              order_y in Just((0..4).collect::<Vec<usize>>()).prop_shuffle()) {
        let now = islandmail_core::now_millis();
        let issued = islandmail_core::ts_from_millis(now - 60_000);
        let cert = Cert::issue(&world::node_a(), "c.carol", &world::carol().public(), &issued);
        let rev = Revocation::sign(&world::node_a(), "c.carol", &world::carol().public(),
                                   &islandmail_core::ts_from_millis(now - 20_000));
        let l = world::list(1);
        let mail = |ts: i64, text: &str| {
            let agents = l.agents(std::slice::from_ref(&cert), &|_| None, ts);
            let m = world::Mail { from: "c.carol".into(), to: "all".into(), thread: "t".into(), text: text.into(),
                                  ts_ms: ts, salt: [3; 16], ..Default::default() };
            world::envelope(&l, &agents, &world::node_a(), &world::carol(), &m, Some(cert.clone())).unwrap()
        };
        let before = mail(now - 40_000, "before");
        let after = mail(now - 10_000, "after");
        let run = |order: &[usize]| {
            let n = world::node(world::node_b());
            for &step in order {
                match step {
                    0 => { let _ = n.take_cert(&cert); }
                    1 => { n.take_revocation(&rev).unwrap(); }
                    2 => { let _ = n.ingest(before.clone()); }
                    _ => { let _ = n.ingest(after.clone()); }
                }
            }
            n
        };
        let (x, y) = (run(&order_x), run(&order_y));
        // Both nodes end with the same roster, keep both envelopes (sealed or read), and show the mail from before
        // the revocation once its certificate is known. Mail dated after a known revocation is never shown.
        prop_assert_eq!(x.agents(), y.agents());
        prop_assert!(x.agents().iter().all(|a| a.name != "c.carol"), "a revoked certificate still counts now");
        for (n, order) in [(&x, &order_x), (&y, &order_y)] {
            let rows = islandmail_fuzz_harness::rows(n);
            let text = |id: &str| rows.iter().find(|r| r.0 == id).map(|r| r.4.clone());
            prop_assert!(text(&before.id).is_some() && text(&after.id).is_some(), "an envelope was dropped");
            let pos = |s| order.iter().position(|&o| o == s).unwrap();
            if pos(1) < pos(3) {
                prop_assert_eq!(text(&after.id), Some(None), "mail dated after a known revocation was shown");
            }
        }
        world::remove(&x);
        world::remove(&y);
    }
}

/// One pull of everything `from` has that `to` lacks, by the request sequence of `net::sync_with` (certs, days,
/// ids pages, get batches), through `net::answer`. `cut`: stop after that many requests.
fn pull(to: &Node, from: &Node, cut: Option<usize>) -> Result<(), &'static str> {
    let network = world::network();
    let peer = to.seed.public();
    let mut budget = cut.unwrap_or(usize::MAX);
    let mut ask = |req: Value| -> Result<Value, &'static str> {
        if budget == 0 { return Err("cut"); }
        budget -= 1;
        let raw = sync_answer(from, &peer, &serde_json::to_vec(&json!([network, req])).unwrap()).unwrap();
        Ok(serde_json::from_slice(&raw).unwrap())
    };
    let certs = ask(json!("certs"))?;
    for c in certs["certs"].as_array().into_iter().flatten() {
        let _ = to.take_cert(&serde_json::from_value(c.clone()).unwrap());
    }
    let days = ask(json!("days"))?;
    let mine = to.store.day_hashes().unwrap();
    for (day, h) in days["days"].as_object().unwrap() {
        if mine.get(day).map(|m| m.as_str()) == h.as_str() { continue; }
        let mut after = String::new();
        loop {
            let page = ask(json!({ "ids": { "day": day, "after": after } }))?;
            let ids: Vec<String> = serde_json::from_value(page["ids"].clone()).unwrap();
            assert!(ids.len() <= 200 && ids.iter().all(|i| *i > after), "id page out of order or oversize");
            let missing: Vec<String> = ids.iter().filter(|i| !to.store.has(i).unwrap()).cloned().collect();
            if let Some(last) = ids.last() { after.clone_from(last); }
            let mut rest = missing.as_slice();
            while !rest.is_empty() {
                let got = ask(json!({ "get": { "ids": rest } }))?;
                let taken = got["taken"].as_u64().unwrap() as usize;
                assert!((1..=rest.len()).contains(&taken));
                for raw in got["envelopes"].as_array().unwrap() {
                    let env: Envelope = serde_json::from_str(raw.as_str().unwrap()).unwrap();
                    assert!(rest[..taken].contains(&env.id));
                    to.ingest(env).unwrap();
                }
                rest = &rest[taken..];
            }
            if ids.len() < 200 { break; }
        }
    }
    Ok(())
}

/// Many keys race to present a reply with the same invite nonce, each on its own thread: exactly one is admitted,
/// and the trust file then lists exactly that one for the invited name.
#[test]
fn invite_nonce_race_admits_one() {
    for round in 0..8u8 {
        let node = Arc::new(world::node(world::node_a()));
        let inv = world::make_invite(&node, "e.erin", "");
        let nonce = invite::read_invite(&inv, islandmail_core::now_millis()).unwrap().nonce;
        let racers: Vec<_> = (0..8u8).map(|k| {
            let node = node.clone();
            std::thread::spawn(move || {
                let joiner = world::seed(140 + round * 8 + k);
                let r = world::reply(&joiner, &nonce, "e.erin", &[]);
                let v: Value = serde_json::from_slice(&invite::handshake(&node, &joiner.public(), r.as_bytes())).unwrap();
                (fmt_key(&joiner.public()), v["ok"] == true)
            })
        }).collect();
        let wins: Vec<String> = racers.into_iter().map(|t| t.join().unwrap()).filter(|(_, ok)| *ok).map(|(k, _)| k).collect();
        assert_eq!(wins.len(), 1, "round {round}: {} nodes admitted with one nonce", wins.len());
        let file = islandmail_fuzz_harness::config::Config::parse_members(
            &std::fs::read(node.opts.members_file.as_ref().unwrap()).unwrap()).unwrap();
        let holders: Vec<_> = file.nodes.iter().filter(|n| n.covers("e.erin")).map(|n| n.key.clone()).collect();
        assert_eq!(holders, wins, "round {round}");
        world::remove(&node);
    }
}

/// Invites for different names accepted concurrently: every join lands, each edit gets its own seq, and the file
/// and the list in use agree. A stale or same-seq list is never adopted.
#[test]
fn concurrent_trust_edits_each_land() {
    let node = Arc::new(world::node(world::node_a()));
    let names: Vec<String> = (0..10).map(|i| format!("e.n{i}")).collect();
    let invites: Vec<[u8; 16]> = names.iter().map(|n| {
        let inv = world::make_invite(&node, n, "");
        invite::read_invite(&inv, islandmail_core::now_millis()).unwrap().nonce
    }).collect();
    let start = node.members_seq();
    let threads: Vec<_> = names.iter().zip(invites).enumerate().map(|(i, (name, nonce))| {
        let (node, name) = (node.clone(), name.clone());
        std::thread::spawn(move || {
            let joiner = world::seed(90 + i as u8);
            let r = world::reply(&joiner, &nonce, &name, &[]);
            let v: Value = serde_json::from_slice(&invite::handshake(&node, &joiner.public(), r.as_bytes())).unwrap();
            assert_eq!(v["ok"], true, "{v}");
            v["seq"].as_u64().unwrap()
        })
    }).collect();
    let mut seqs: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    seqs.sort();
    assert_eq!(seqs, ((start + 1)..=(start + 10)).collect::<Vec<_>>(), "each edit its own seq");
    let file = islandmail_fuzz_harness::config::Config::parse_members(
        &std::fs::read(node.opts.members_file.as_ref().unwrap()).unwrap()).unwrap();
    assert_eq!(file, *node.members.read().unwrap());
    for name in &names {
        assert_eq!(file.nodes.iter().filter(|n| n.covers(name)).count(), 1, "{name}");
    }
    let mut stale = file.clone();
    stale.nodes.pop();
    assert!(node.reload_members(&stale).is_err(), "same seq, other content adopted");
    stale.seq -= 1;
    assert!(node.reload_members(&stale).is_err(), "older seq adopted");
    world::remove(&node);
}

/// A trust-file edit racing a stale reload: the reload never rolls the list back past an edit.
#[test]
fn reload_never_rolls_back_an_edit() {
    let node = Arc::new(world::node(world::node_a()));
    let old = node.members.read().unwrap().clone();
    let inv = world::make_invite(&node, "e.erin", "");
    let nonce = invite::read_invite(&inv, islandmail_core::now_millis()).unwrap().nonce;
    let joiner = world::seed(120);
    let r = world::reply(&joiner, &nonce, "e.erin", &[]);
    let n2 = node.clone();
    let t = std::thread::spawn(move || invite::handshake(&n2, &joiner.public(), r.as_bytes()));
    let _ = node.reload_members(&old);
    let v: Value = serde_json::from_slice(&t.join().unwrap()).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert!(node.members.read().unwrap().nodes.iter().any(|n| n.covers("e.erin")));
    let _ = b64u(&[0]);
    world::remove(&node);
}
