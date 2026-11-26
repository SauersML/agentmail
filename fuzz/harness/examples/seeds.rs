//! Writes well-formed starting inputs for the raw-bytes fuzz targets into DIR/<target>/ (fuzz/seeds in the repo), so each
//! starts past the JSON and framing layers:  cargo run --example seeds -- fuzz/seeds

use std::path::Path;

use islandmail_core::{agent_token, b64u, keys::fmt_key, Cert, Revocation};
use islandmail_fuzz_harness::world;
use serde_json::json;

fn put(dir: &Path, target: &str, name: &str, data: impl AsRef<[u8]>) {
    let d = dir.join(target);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(name), data).unwrap();
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: seeds DIR");
    let dir = Path::new(&dir);
    let now = islandmail_core::now_millis();
    let env = world::plain("hello @a.bob https://example.org", "a.alice/plan", now - 1000, 1);
    put(dir, "envelope", "plain", serde_json::to_vec(&env).unwrap());
    put(dir, "gossip", "envelope", serde_json::to_vec(&env).unwrap());
    let cert = Cert::issue(&world::node_a(), "c.carol", &world::carol().public(), &islandmail_core::ts_from_millis(now));
    let rev = Revocation::sign(&world::node_a(), "c.carol", &world::carol().public(), &islandmail_core::ts_from_millis(now));
    put(dir, "cert", "cert", serde_json::to_vec(&cert).unwrap());
    put(dir, "cert", "revocation", serde_json::to_vec(&rev).unwrap());
    put(dir, "gossip", "cert", json!({ "cert": cert }).to_string());
    put(dir, "gossip", "revocation", json!({ "revocation": rev }).to_string());
    let mut l = world::list(3);
    l.relays = vec!["https://relay.example.org".into()];
    put(dir, "trust_file", "list", serde_json::to_vec_pretty(&l).unwrap());
    let net = world::network();
    for (n, req) in [json!("days"), json!("certs"), json!({ "ids": { "day": "2026-01-01", "after": "" } }),
                     json!({ "get": { "ids": [env.id] } }), json!({ "blob": { "id": env.id } }),
                     json!({ "certs_for": { "issuer": fmt_key(&world::node_a().public()) } })].iter().enumerate() {
        put(dir, "sync_request", &format!("req{n}"), json!([net, req]).to_string());
    }
    let epoch = now.div_euclid(islandmail_core::node_key::ROTATION_MS);
    let key = islandmail_core::node_key::NodeEncryptionKey::issue(&world::node_b(), &net, epoch, &world::seed(20));
    put(dir, "node_key", "key", serde_json::to_vec(&key).unwrap());
    put(dir, "codecs", "token", agent_token::mint(&world::alice(), "a.alice", "agent:alice@test",
                                                 &world::node_a().public(), now, 600));
    put(dir, "codecs", "id", islandmail_core::b32_id(&env.id));
    put(dir, "codecs", "ts", islandmail_core::ts_from_millis(now));
    let meta = json!({ "room": "a.alice/plan", "mentions": ["a.bob"], "event": { "op": "create", "private": true,
                       "members": ["a.bob"], "topic": "plans" } }).to_string();
    let inner = json!({ "h": { "thread": "t", "parents": [], "from": "a.alice", "to": "all", "mode": "members",
                               "audience": [], "attest": { "key": fmt_key(&world::alice().public()), "digest": "0".repeat(64), "sig": "" } },
                        "b": { "text": "hi", "files": [], "salt": b64u(&[1; 16]), "meta": meta } }).to_string();
    put(dir, "sealed_body", "inner", [&[1u8][..], inner.as_bytes()].concat());
}
