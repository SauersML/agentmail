//! Fixed keys, a trust file and nodes for the fuzz targets and property tests. Everything is deterministic except
//! the temporary paths, so a crashing input replays the same way.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use islandmail_core::envelope::{post_digest_meta, Attest, Body, Draft, Envelope, Mode, PostStatement};
use islandmail_core::keys::{fmt_key, PublicKey, Seed};
use islandmail_core::members::{self, Member, MemberList, NodeEntry};
use islandmail_core::{b64u, Cert};

use crate::node::{Node, Opts};
use crate::store::Store;

pub const NETWORK: [u8; 32] = [7; 32];

/// Node A, node B, then agents: alice (pinned, a.alice), bob (pinned, a.bob), carol (certified by node A as c.carol).
pub fn seed(i: u8) -> Seed {
    Seed::from_bytes([i + 1; 32])
}
pub fn node_a() -> Seed { seed(0) }
pub fn node_b() -> Seed { seed(1) }
pub fn alice() -> Seed { seed(10) }
pub fn bob() -> Seed { seed(11) }
pub fn carol() -> Seed { seed(12) }

pub fn network() -> String {
    b64u(&NETWORK)
}

/// The trust file every node in the world starts from.
pub fn list(seq: u64) -> MemberList {
    MemberList {
        v: 1,
        network: network(),
        seq,
        members: vec![
            Member { name: "a.alice".into(), sub: "agent:alice@test".into(), key: fmt_key(&alice().public()) },
            Member { name: "a.bob".into(), sub: "agent:bob@test".into(), key: fmt_key(&bob().public()) },
        ],
        nodes: vec![
            NodeEntry { name: "na".into(), key: fmt_key(&node_a().public()), addrs: vec!["192.0.2.1:4433".into()],
                        names: vec!["c.".into()] },
            NodeEntry { name: "nb".into(), key: fmt_key(&node_b().public()), addrs: vec![], names: vec!["d.".into()] },
        ],
        relays: vec![],
    }
}

static N: AtomicU64 = AtomicU64::new(0);

/// A fresh path under the temp dir (TMPDIR=/dev/shm keeps fuzzing off the disk).
pub fn temp_path(what: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("islandmail-fuzz-{}-{n}-{what}", std::process::id()))
}

/// A node with `seed` on a fresh store, trusting `list`, with its own trust file (so invite/join/accept work).
pub fn node_with(seed: Seed, list: &MemberList) -> Node {
    let db = temp_path("store.sqlite");
    let trust = temp_path("trust.json");
    std::fs::write(&trust, serde_json::to_vec(list).unwrap()).unwrap();
    let store = Store::open(&db).unwrap();
    store.bind_roster(&seed.public(), list).unwrap();
    let opts = Opts { public_url: "http://127.0.0.1:1".into(), relay: vec!["n0".into()], members_file: Some(trust),
                      ..Default::default() };
    Node::new(store, list.clone(), seed, opts, tokio::sync::mpsc::channel(1 << 16).0)
}

pub fn node(seed: Seed) -> Node {
    node_with(seed, &list(1))
}

/// Removes a node's store and trust file (call when a test is done with it).
pub fn remove(node: &Node) {
    if let Some(p) = &node.opts.members_file {
        let _ = std::fs::remove_file(p);
    }
}

/// What a valid envelope carries; every field is the fuzzer's or the test's choice.
#[derive(Clone, Debug, Default)]
pub struct Mail {
    pub from: String,
    pub to: String,
    pub thread: String,
    pub text: String,
    pub meta: String,
    pub files: Vec<serde_json::Value>,
    pub blobs: Vec<String>,
    pub parents: Vec<String>,
    pub private: bool,
    pub ts_ms: i64,
    pub salt: [u8; 16],
}

/// An envelope signed by `signer` as `m.from` and written by `writer`, with recipients as the node would pick them.
pub fn envelope(list: &MemberList, agents: &[members::Agent], writer: &Seed, signer: &Seed, m: &Mail,
                cert: Option<Cert>) -> anyhow::Result<Envelope> {
    let mode = if m.private { Mode::Private } else { Mode::Members };
    let recipients: Vec<PublicKey> = match mode {
        Mode::Members => list.all_keys(),
        Mode::Private => members::private_keys(agents, &m.to, &m.from),
    };
    let ts = islandmail_core::ts_from_millis(m.ts_ms);
    let digest = post_digest_meta(&m.salt, &m.text, &m.files, &m.meta)?;
    let sub = members::find(agents, &m.from, &signer.public()).map(|a| a.sub.clone())
        .unwrap_or_else(|| islandmail_core::cert::agent_sub(&m.from));
    let st = PostStatement { from: &m.from, sub: &sub, to: &m.to, thread: &m.thread, mode, ts: &ts, digest: &digest,
                             blobs: &m.blobs, recipients: &recipients }.signing_bytes(list);
    let attest = Attest { key: fmt_key(&signer.public()), digest, sig: b64u(&signer.sign(&st)), cert };
    let body = Body { text: m.text.clone(), files: m.files.clone(), salt: b64u(&m.salt), meta: m.meta.clone() };
    Envelope::seal(Draft { thread: &m.thread, parents: m.parents.clone(), ts, from: &m.from, to: &m.to, mode,
                           body: &body, blobs: m.blobs.clone(), attest, recipients: &recipients }, writer)
}

/// The associated data of an envelope's outer fields (`envelope::outer_ad`), for sealing fuzzer-chosen inner bytes.
pub fn outer_ad(env: &Envelope) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!(["islandmail/sealed/v1", env.v, env.ts, env.node, env.blobs])).unwrap()
}

/// `env` with its ciphertext replaced by `inner` (already padded, or not: the fuzzer's choice) sealed to every
/// member key, re-signed by its writing node `writer`.
pub fn reseal_inner(env: &Envelope, inner: &[u8], writer: &Seed) -> Envelope {
    let l = list(1);
    let targets = islandmail_core::crypto::identity_targets(&l.all_keys()).unwrap();
    let mut e = env.clone();
    e.node = fmt_key(&writer.public());
    let sealed = islandmail_core::crypto::seal(inner, &outer_ad(&e), &targets).unwrap();
    e.ciphertext = b64u(&sealed.ciphertext);
    e.epk = b64u(&sealed.epk);
    e.keys = sealed.keys.iter().map(|w| islandmail_core::envelope::WrappedKey { t: b64u(&w.tag), k: b64u(&w.k) }).collect();
    e.id = blake3::hash(&sealed.ciphertext).to_hex().to_string();
    e.sig = b64u(&writer.sign(&e.signing_bytes()));
    e
}

/// A plain members-mode message from alice, written by node B, at `ts_ms`.
pub fn plain(text: &str, thread: &str, ts_ms: i64, salt: u8) -> Envelope {
    let l = list(1);
    let agents = l.agents(&[], &|_| None, ts_ms);
    let m = Mail { from: "a.alice".into(), to: "all".into(), thread: thread.into(), text: text.into(), ts_ms,
                   salt: [salt; 16], ..Default::default() };
    envelope(&l, &agents, &node_b(), &alice(), &m, None).unwrap()
}

/// A node's operator signature on an invite/join/accept body (`invite::operator_statement`).
pub fn operator_signed(node: &Node, action: &str, arg: &str, mut body: serde_json::Value) -> serde_json::Value {
    let ts = islandmail_core::now_ts();
    let st = crate::invite::operator_statement(action, &fmt_key(&node.seed.public()), &ts, arg);
    body["ts"] = ts.into();
    body["sig"] = b64u(&node.seed.sign(st.as_bytes())).into();
    body
}

/// A signed invite from `node` for `name` (`room` may be empty).
pub fn make_invite(node: &Node, name: &str, room: &str) -> String {
    let ttl = 604800;
    let body = serde_json::json!({ "name": name, "room": room, "from": "a.alice", "ttl_s": ttl });
    let body = operator_signed(node, "invite", &format!("{name}|{room}|a.alice|{ttl}|"), body);
    crate::invite::invite(node, &body).map_err(|e| anyhow::anyhow!("{}", e.message)).unwrap()["invite"]
        .as_str().unwrap().to_string()
}

/// The compact reply bytes (`imr1` layout) for `payload` after the flags byte, signed by `seed`.
pub fn sign_reply(seed: &Seed, payload: &[u8]) -> String {
    let sig = seed.sign(&[b"islandmail/invite-reply/v1\n".as_slice(), payload].concat());
    format!("imr1{}", crate::invite::b58(&[payload, &sig].concat()))
}

/// The compact invite bytes (`im1` layout), signed by `seed`.
pub fn sign_invite(seed: &Seed, payload: &[u8]) -> String {
    let sig = seed.sign(&[b"islandmail/invite/v1\n".as_slice(), payload].concat());
    format!("im1{}", crate::invite::b58(&[payload, &sig].concat()))
}

/// A reply from `joiner` to the invite with `nonce`, presenting `name`.
pub fn reply(joiner: &Seed, nonce: &[u8; 16], name: &str, addrs: &[std::net::SocketAddr]) -> String {
    let mut p = vec![if addrs.is_empty() { 0 } else { 4 }];
    p.extend_from_slice(&NETWORK);
    p.extend_from_slice(&joiner.public());
    p.extend_from_slice(nonce);
    p.push(name.len() as u8);
    p.extend_from_slice(name.as_bytes());
    if !addrs.is_empty() {
        p.push(addrs.len() as u8);
        for a in addrs {
            match a.ip() {
                std::net::IpAddr::V4(ip) => { p.push(4); p.extend_from_slice(&ip.octets()); }
                std::net::IpAddr::V6(ip) => { p.push(6); p.extend_from_slice(&ip.octets()); }
            }
            p.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    sign_reply(joiner, &p)
}
