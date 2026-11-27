//! One-step joining. The inviting node issues an invite with a one-time nonce and keeps it (table `invites`). The
//! joining node dials the inviting node on JOIN_ALPN, the one request an untrusted key may make, and presents a
//! reply: its node key, addrs, the invited name and the nonce, signed by its node key (the QUIC handshake also proves
//! the key). The inviting node checks the nonce (issued here, unexpired, unused), the name (exactly the invited one,
//! held by nobody else here), trusts the joining node for exactly that name and spends the nonce under one lock,
//! then answers. When the inviting node cannot be reached, join prints the reply instead and the inviter runs
//! `accept REPLY`, which runs the same check. The room add is made by the inviting agent's own client on its next run
//! (GET /api/invites/joined lists the joins it has not seen), since only that agent can sign it.
//!
//! Host-owner steps (invite, join, accept) arrive over the loopback API signed with this node's key
//! (`operator_statement`). The node writes its own trust file (seq + 1, other entries kept) and adopts it at once.
//!
//! Both strings are base58 of raw bytes (str = u8 length + UTF-8; u32 big-endian):
//!
//!   im1 + base58(flags u8 | network 32 | node key 32 | exp u32 (unix s) | nonce 16 | names str (comma-separated)
//!                | [from str] | [room str] | [for key: first 4 bytes] | [names: n u8, n str] | [addrs]
//!                | [relay URLs: n u8, n str] | sig 64)
//!   imr1 + base58(flags u8 | network 32 | node key 32 | nonce 16 | names str | [addrs] | sig 64)
//!
//! flags: 1 relay n0, 2 relay URLs, 4 addrs, 8 names, 16 from, 32 room, 64 for key (a key-bound invite: only the node
//! whose key starts with those 4 bytes may join; the inviting node keeps the whole key and checks it). addrs = n u8, then per address 4 | IPv4 4 |
//! port u16 or 6 | IPv6 16 | port u16. sig is the node key's Ed25519 signature over "islandmail/invite/v1\n" (reply:
//! "islandmail/invite-reply/v1\n") + every byte before it. Derived, not sent: the inviting node's names default to
//! [from], its entry name is from (else its first name); the joining node's entry name is the invited name.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Mutex;

use islandmail_core::cert::{self, valid_name, valid_namespace_entry};
use islandmail_core::keys::{fmt_key, parse_key};
use islandmail_core::members::NodeEntry;
use islandmail_core::{b64u, b64u_decode, now_millis, MemberList};
use serde_json::{json, Value};

use crate::node::{ApiError, Node};

pub const INVITE_PREFIX: &str = "im1";
pub const REPLY_PREFIX: &str = "imr1";
const INVITE_CTX: &[u8] = b"islandmail/invite/v1\n";
const REPLY_CTX: &[u8] = b"islandmail/invite-reply/v1\n";
pub const MAX_INVITE_LIFE_MS: i64 = 7 * 24 * 3600 * 1000;
const SKEW_MS: i64 = 300_000;
const N0: u8 = 1;
const URLS: u8 = 2;
const ADDRS: u8 = 4;
const NAMES: u8 = 8;
const FROM: u8 = 16;
const ROOM: u8 = 32;
const FOR_KEY: u8 = 64;
/// A key-less invite (first contact) lasts a day unless asked otherwise; one bound to a node key, a week.
pub const KEYLESS_LIFE_S: i64 = 24 * 3600;
pub const MAX_NAMES_PER_INVITE: usize = 8;

#[derive(Clone, Debug)]
pub struct Invite {
    pub network: String,
    /// The inviting node, as the joiner will list it.
    pub node: NodeEntry,
    /// The relays the inviter uses: its network's (trust file "relays"), then its own config's ("n0" when it opted in).
    pub relay: Vec<String>,
    /// The exact agent names the inviter will trust the joining node for, comma-separated.
    pub name: String,
    /// The inviting agent, if one asked: whom to write to first.
    pub from: Option<String>,
    /// A room the joined agent is added to on accept.
    pub room: Option<String>,
    pub exp: i64,
    /// One-time: the inviting node keeps it until a node joins with it.
    pub nonce: [u8; 16],
    /// A key-bound invite: the first 4 bytes of the only node key that may join (a check for the joiner; the inviting node holds the whole key).
    pub for_key: Option<[u8; 4]>,
}

/// The names of a comma list: each a valid exact agent name, distinct, at most MAX_NAMES_PER_INVITE.
pub fn split_names(list: &str) -> Result<Vec<String>, String> {
    let names: Vec<String> = list.split(',').map(|n| n.trim().to_string()).collect();
    let mut seen = std::collections::HashSet::new();
    if names.len() > MAX_NAMES_PER_INVITE || !names.iter().all(|n| valid_name(n) && seen.insert(islandmail_core::addr::norm(n))) {
        return Err(format!("names must be 1 to {MAX_NAMES_PER_INVITE} distinct exact agent names, comma-separated \
                            (letters, digits, . _ -; not ending in '.')"));
    }
    Ok(names)
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub network: String,
    /// The joining node: its key and addrs (it is trusted for the invite's name only).
    pub node: NodeEntry,
    pub name: String,
    pub nonce: [u8; 16],
}

/* base58 (Bitcoin alphabet) */

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn b58(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 { digits.push((carry % 58) as u8); carry /= 58; }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    std::iter::repeat_n(b'1', zeros).chain(digits.iter().rev().map(|&d| B58[d as usize])).map(char::from).collect()
}

pub fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = B58.iter().position(|&x| x == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 { bytes.push((carry & 0xff) as u8); carry >>= 8; }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    Some(std::iter::repeat_n(0, zeros).chain(bytes.into_iter().rev()).collect())
}

/* the byte layout */

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn put(&mut self, b: &[u8]) -> &mut Self { self.0.extend_from_slice(b); self }
    fn str(&mut self, s: &str) -> &mut Self { self.0.push(s.len().min(255) as u8); self.put(&s.as_bytes()[..s.len().min(255)]) }
    fn addrs(&mut self, addrs: &[String]) {
        let list: Vec<SocketAddr> = addrs.iter().filter_map(|a| a.parse().ok()).take(255).collect();
        self.0.push(list.len() as u8);
        for a in list {
            match a.ip() {
                IpAddr::V4(ip) => self.put(&[4]).put(&ip.octets()),
                IpAddr::V6(ip) => self.put(&[6]).put(&ip.octets()),
            };
            self.put(&a.port().to_be_bytes());
        }
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n { return Err("is cut short".into()); }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], String> { Ok(self.take(N)?.try_into().unwrap()) }
    fn str(&mut self) -> Result<String, String> {
        let n = self.u8()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "holds a name that is not UTF-8".into())
    }
    fn addrs(&mut self) -> Result<Vec<String>, String> {
        (0..self.u8()?).map(|_| {
            let ip: IpAddr = match self.u8()? {
                4 => self.arr::<4>()?.into(),
                6 => self.arr::<16>()?.into(),
                _ => return Err("holds an unknown address type".to_string()),
            };
            Ok(SocketAddr::new(ip, u16::from_be_bytes(self.arr()?)).to_string())
        }).collect()
    }
}

fn key_bytes(k: &str) -> [u8; 32] {
    parse_key(k).expect("valid key")
}

fn network_bytes(n: &str) -> Result<[u8; 32], String> {
    b64u_decode(n).and_then(|b| b.try_into().ok()).ok_or_else(|| "invalid network ID".into())
}

fn seal(prefix: &str, ctx: &[u8], mut w: W, node: &Node) -> String {
    let sig = node.seed.sign(&[ctx, &w.0].concat());
    w.put(&sig);
    format!("{prefix}{}", b58(&w.0))
}

/// The payload of a sealed string, after checking its signature by the node key at bytes 1..33.
fn open(s: &str, prefix: &str, ctx: &[u8], what: &str) -> Result<Vec<u8>, String> {
    let body = s.trim().strip_prefix(prefix).ok_or_else(|| format!("that is not {what} (it starts with {prefix})"))?;
    let raw = b58_decode(body).ok_or_else(|| format!("{what} is damaged (not base58)"))?;
    if raw.len() < 1 + 32 + 32 + 64 { return Err(format!("{what} is cut short")); }
    let (payload, sig) = raw.split_at(raw.len() - 64);
    let key: [u8; 32] = payload[33..65].try_into().unwrap();
    if !islandmail_core::keys::verify(&key, &[ctx, payload].concat(), sig) {
        return Err(format!("{what} signature does not match its node key (changed or damaged)"));
    }
    Ok(payload.to_vec())
}

fn check_entry(n: &NodeEntry) -> Result<(), String> {
    if n.name.is_empty() || n.name.len() > 64 || n.names.len() > islandmail_core::members::MAX_NAMES
        || !n.names.iter().all(|e| valid_namespace_entry(e)) {
        return Err("invalid node entry".into());
    }
    Ok(())
}

fn encode_invite(inv: &Invite, node: &Node) -> String {
    let derived = inv.from.as_ref().is_some_and(|f| inv.node.names == [f.clone()]);
    let urls: Vec<&String> = inv.relay.iter().filter(|r| *r != "n0").collect();
    let flags = if inv.relay.iter().any(|r| r == "n0") { N0 } else { 0 } | if urls.is_empty() { 0 } else { URLS }
        | if inv.node.addrs.is_empty() { 0 } else { ADDRS } | if derived { 0 } else { NAMES }
        | if inv.from.is_some() { FROM } else { 0 } | if inv.room.is_some() { ROOM } else { 0 }
        | if inv.for_key.is_some() { FOR_KEY } else { 0 };
    let mut w = W::default();
    w.put(&[flags]).put(&network_bytes(&inv.network).expect("own network")).put(&key_bytes(&inv.node.key))
        .put(&((inv.exp / 1000) as u32).to_be_bytes()).put(&inv.nonce).str(&inv.name);
    if let Some(f) = &inv.from { w.str(f); }
    if let Some(r) = &inv.room { w.str(r); }
    if let Some(k) = &inv.for_key { w.put(k); }
    if !derived {
        w.0.push(inv.node.names.len() as u8);
        for n in &inv.node.names { w.str(n); }
    }
    if !inv.node.addrs.is_empty() { w.addrs(&inv.node.addrs); }
    if !urls.is_empty() {
        w.0.push(urls.len() as u8);
        for u in urls { w.str(u); }
    }
    seal(INVITE_PREFIX, INVITE_CTX, w, node)
}

pub fn read_invite(s: &str, now: i64) -> Result<Invite, String> {
    let raw = open(s, INVITE_PREFIX, INVITE_CTX, "an invite")?;
    let mut r = R(&raw);
    let bad = |e: String| format!("invite {e}");
    let flags = r.u8()?;
    let network = b64u(&r.arr::<32>()?);
    let key = fmt_key(&r.arr::<32>()?);
    let exp = u32::from_be_bytes(r.arr()?) as i64 * 1000;
    let nonce = r.arr::<16>()?;
    let name = r.str().map_err(bad)?;
    let from = if flags & FROM != 0 { Some(r.str().map_err(bad)?) } else { None };
    let room = if flags & ROOM != 0 { Some(r.str().map_err(bad)?) } else { None };
    let for_key = if flags & FOR_KEY != 0 { Some(r.arr::<4>()?) } else { None };
    let names = if flags & NAMES != 0 { (0..r.u8()?).map(|_| r.str()).collect::<Result<Vec<_>, _>>().map_err(bad)? }
                else { vec![from.clone().ok_or("invite is malformed (no names)")?] };
    let addrs = if flags & ADDRS != 0 { r.addrs().map_err(bad)? } else { vec![] };
    let mut relay = if flags & N0 != 0 { vec!["n0".to_string()] } else { vec![] };
    if flags & URLS != 0 { for _ in 0..r.u8()? { relay.push(r.str().map_err(bad)?); } }
    if !r.0.is_empty() || flags & !127 != 0 { return Err("invite is malformed".into()); }
    let node_name = from.clone().or_else(|| names.first().map(|n| n.trim_end_matches('.').to_string())).unwrap_or("peer".into());
    let inv = Invite { network, node: NodeEntry { name: node_name, key, addrs, names }, relay, name, from, room, exp, nonce,
                       for_key };
    check_entry(&inv.node).map_err(bad)?;
    split_names(&inv.name).map_err(bad)?;
    if inv.exp > now + MAX_INVITE_LIFE_MS + SKEW_MS {
        return Err("invite runs longer than 7 days".into());
    }
    if now >= inv.exp {
        return Err(format!("invite expired at {}", islandmail_core::ts_from_millis(inv.exp)));
    }
    Ok(inv)
}

fn encode_reply(r: &Reply, node: &Node) -> String {
    let mut w = W::default();
    w.put(&[if r.node.addrs.is_empty() { 0 } else { ADDRS }]).put(&network_bytes(&r.network).expect("own network"))
        .put(&key_bytes(&r.node.key)).put(&r.nonce).str(&r.name);
    if !r.node.addrs.is_empty() { w.addrs(&r.node.addrs); }
    seal(REPLY_PREFIX, REPLY_CTX, w, node)
}

/// `islandmail-node invite-info INVITE`: what a checked invite holds, for setting up a fresh host before its node runs.
pub fn info(s: &str) -> Result<Value, String> {
    let i = read_invite(s, now_millis())?;
    Ok(json!({ "network": i.network, "relay": i.relay, "name": i.name, "names": split_names(&i.name)?, "from": i.from,
               "room": i.room, "for_key_prefix": i.for_key.map(|k| b64u(&k)),
               "exp": islandmail_core::ts_from_millis(i.exp),
               "node": { "name": i.node.name, "key": i.node.key, "addrs": i.node.addrs, "names": i.node.names } }))
}

pub fn read_reply(s: &str) -> Result<Reply, String> {
    let raw = open(s, REPLY_PREFIX, REPLY_CTX, "a reply")?;
    let mut r = R(&raw);
    let bad = |e: String| format!("reply {e}");
    let flags = r.u8()?;
    let network = b64u(&r.arr::<32>()?);
    let key = fmt_key(&r.arr::<32>()?);
    let nonce = r.arr::<16>()?;
    let name = r.str().map_err(bad)?;
    let addrs = if flags & ADDRS != 0 { r.addrs().map_err(bad)? } else { vec![] };
    if !r.0.is_empty() || flags & !ADDRS != 0 || split_names(&name).is_err() { return Err("reply is malformed".into()); }
    Ok(Reply { network, node: NodeEntry { name: name.clone(), key, addrs, names: vec![] }, name, nonce })
}

/* the store: outstanding invites */

pub fn init(db: &rusqlite::Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS join_invites (nonce TEXT PRIMARY KEY, name TEXT NOT NULL, room TEXT NOT NULL,
                      from_ TEXT NOT NULL, exp INTEGER NOT NULL, for_key TEXT, spent_by TEXT, spent_ms INTEGER,
                      told INTEGER NOT NULL DEFAULT 0);")?;
    Ok(())
}

/// What the host owner signs with the node key to ask for one step: action is invite, join or accept.
pub fn operator_statement(action: &str, node_key: &str, ts: &str, arg: &str) -> String {
    format!("islandmail-operator|v1|{action}|{node_key}|{ts}|{arg}")
}

fn operator(node: &Node, body: &Value, action: &str, arg: &str) -> Result<(), ApiError> {
    let f = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let me = node.seed.public();
    let ok = islandmail_core::parse_ts(f("ts")).is_some_and(|t| (t - now_millis()).abs() <= SKEW_MS)
        && islandmail_core::keys::verify(&me, operator_statement(action, &fmt_key(&me), f("ts"), arg).as_bytes(),
                                          &b64u_decode(f("sig")).unwrap_or_default());
    if ok { Ok(()) } else {
        Err(ApiError::new(401, format!("{action} requests are signed by this node's key (islandmail.py {action} --config CONFIG)")))
    }
}

/// Who on this trust file already holds `name`: a node whose names cover it, or a pinned agent.
fn holder(list: &MemberList, name: &str, except: Option<&str>) -> Option<String> {
    if list.member_by_name(name).is_some() {
        return Some("an agent pinned in this trust file".into());
    }
    list.nodes.iter().find(|n| Some(n.key.as_str()) != except && n.covers(name)).map(|n| format!("node {:?}", n.name))
}

/// Whether two namespace entries can cover a common name (an exact name, or a prefix ending in '.').
fn overlaps(a: &str, b: &str) -> bool {
    let (a, b) = (islandmail_core::addr::norm(a), islandmail_core::addr::norm(b));
    match (a.ends_with('.'), b.ends_with('.')) {
        (false, false) => a == b,
        (true, false) => b.starts_with(&a),
        (false, true) => a.starts_with(&b),
        (true, true) => a.starts_with(&b) || b.starts_with(&a),
    }
}

/// An inviting node signs its own `names` into the invite. Trusting them as given would let it certify (impersonate,
/// and read the private mail of) agents this host already gives to another node, its own included, or pins: refuse
/// any of its names that overlaps one held here by anyone but the inviter itself.
fn claims_held(list: &MemberList, inviter: &NodeEntry) -> Option<String> {
    for e in &inviter.names {
        if let Some(m) = list.members.iter().find(|m| cert::entry_covers(e, &m.name)) {
            return Some(format!("{e} (it covers {}, pinned in this trust file)", m.name));
        }
        if let Some(n) = list.nodes.iter().find(|n| n.key != inviter.key && n.names.iter().any(|x| overlaps(e, x))) {
            return Some(format!("{e} (node {:?} holds it here)", n.name));
        }
    }
    None
}

static EDIT: Mutex<()> = Mutex::new(());

/// Edits the trust file on disk (the source of truth) and adopts the result: seq one above both the file and the
/// list in use. `f` may refuse.
fn edit_trust(node: &Node, f: impl FnOnce(&mut MemberList, &str) -> Result<(), ApiError>) -> Result<MemberList, ApiError> {
    edit_trust_with(node, |list, me, _| f(list, me))
}

/// `edit_trust` with a store transaction for `f`'s own writes (an invite's spend), committed only once the edited
/// trust file is valid and on disk: a refused edit spends nothing. A crash between the two leaves the trust file
/// edited and the invite unspent, which the same node completes on its next try (its names are already its own, so
/// no other node can use the invite).
fn edit_trust_with(node: &Node, f: impl FnOnce(&mut MemberList, &str, &rusqlite::Transaction) -> Result<(), ApiError>)
    -> Result<MemberList, ApiError> {
    let _g = EDIT.lock().unwrap();
    let path = node.opts.members_file.as_deref().ok_or_else(|| ApiError::new(503, "this node has no trust file to edit"))?;
    crate::private_fs::check_writers(path).map_err(|e| ApiError::new(409, format!("{e:#}")))?;
    let mut list = crate::config::Config::parse_members(&std::fs::read(path).map_err(anyhow::Error::from)?)
        .map_err(|e| ApiError::new(409, format!("trust file is not valid now: {e:#}")))?;
    let cur = node.members.read().unwrap().seq;
    if list.network != node.members.read().unwrap().network {
        return Err(ApiError::new(409, "trust file names another network than the one this node runs; restart it first"));
    }
    let committed = {
        let mut db = node.store.conn();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(anyhow::Error::from)?;
        f(&mut list, &fmt_key(&node.seed.public()), &tx)?;
        list.seq = list.seq.max(cur) + 1;
        list.validate().map_err(|e| ApiError::new(409, format!("{e:#}")))?;
        write_atomic(path, &serde_json::to_vec_pretty(&list).expect("JSON"))?;
        tx.commit()
    };
    // The file is written either way: adopt it, as the trust watcher would.
    node.reload_members(&list).map_err(|e| ApiError::new(409, format!("{e:#}")))?;
    committed.map_err(anyhow::Error::from)?;
    // As when the trust watcher adopts a change: held identities newly in our names, and a sync with the new peer now.
    node.certify_identities();
    node.resync.notify_one();
    Ok(list)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), ApiError> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp-{}", b64u(&islandmail_core::random_bytes::<6>())));
    let r = (|| -> std::io::Result<()> {
        // Owner-only whatever the umask, so the node never writes a trust file it would then refuse.
        let mut f = crate::private_fs::options().write(true).create_new(true).open(&tmp)?;
        // Keep who may read it (iroh-relay's allowlist, say); never group or other write.
        #[cfg(unix)]
        if let Ok(md) = std::fs::metadata(path) {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(md.permissions().mode() & 0o755))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() { let _ = std::fs::remove_file(&tmp); }
    r.map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()).into())
}

fn own_entry(node: &Node) -> Result<NodeEntry, ApiError> {
    node.members.read().unwrap().node_by_key(&node.seed.public()).cloned()
        .ok_or_else(|| ApiError::new(409, "this node is not on its own trust file"))
}

fn arg_str<'a>(body: &'a Value, k: &str) -> &'a str {
    body.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// POST /api/invites {name, room?, from?, ttl_s?, ts, sig}: a signed invite for one exact name.
pub fn invite(node: &Node, body: &Value) -> Result<Value, ApiError> {
    let (name, room, from, for_key) = (arg_str(body, "name"), arg_str(body, "room"), arg_str(body, "from"), arg_str(body, "key"));
    let ttl = body.get("ttl_s").and_then(|v| v.as_i64()).unwrap_or(0);
    operator(node, body, "invite", &format!("{name}|{room}|{from}|{ttl}|{for_key}"))?;
    let names = split_names(name).map_err(|e| ApiError::new(400, format!("--name: {e}")))?;
    let name = &names.join(",");
    let bound = match for_key {
        "" => None,
        k => Some(parse_key(k).ok().filter(|b| fmt_key(b) == k)
            .ok_or_else(|| ApiError::new(400, "--key must be a node key, ed25519:… (islandmail.py nodekey prints it)"))?),
    };
    let ttl = if ttl == 0 { if bound.is_some() { MAX_INVITE_LIFE_MS / 1000 } else { KEYLESS_LIFE_S } } else { ttl };
    if !(1..=MAX_INVITE_LIFE_MS / 1000).contains(&ttl) {
        return Err(ApiError::new(400, "ttl_s must be 1 second to 7 days"));
    }
    if room.len() > 200 || room.contains(['|', '\n']) || from.len() > 120 {
        return Err(ApiError::new(400, "invalid room or from"));
    }
    for n in &names {
        if let Some(h) = holder(&node.members.read().unwrap(), n, None) {
            return Err(ApiError::new(409, format!("{n} is already held here by {h}; invite with a name nobody holds")));
        }
    }
    if name.len() + room.len() + from.len() > 200 {
        return Err(ApiError::new(400, "name, room and from are too long for an invite"));
    }
    let network = node.members.read().unwrap().network.clone();
    let exp_s = ((now_millis() + 999) / 1000 + ttl) as u32;
    let nonce = islandmail_core::random_bytes::<16>();
    let inv = Invite {
        nonce,
        for_key: bound.map(|k| k[..4].try_into().unwrap()),
        relay: crate::net::relay_entries(&node.members.read().unwrap(), &node.opts.relay),
        network, node: own_entry(node)?, name: name.into(),
        from: (!from.is_empty()).then(|| from.into()), room: (!room.is_empty()).then(|| room.into()), exp: exp_s as i64 * 1000,
    };
    let s = encode_invite(&inv, node);
    node.store.conn().execute("INSERT INTO join_invites (nonce, name, room, from_, exp, for_key) VALUES (?, ?, ?, ?, ?, ?)",
                              rusqlite::params![b64u(&nonce), name, room, from, inv.exp, bound.map(|k| fmt_key(&k))])?;
    Ok(json!({ "invite": s, "exp": islandmail_core::ts_from_millis(inv.exp) }))
}

/// A join on its way: the checked invite and the reply this node presents to the inviting node.
pub struct JoinPlan {
    pub inv: Invite,
    pub reply: String,
}

/// What the inviting node said to the presented reply, or why it could not be asked.
pub enum Outcome {
    Answered(Value),
    Unreachable(String),
}

/// POST /api/joins {invite, ts, sig}, first half: check the invite and make the reply. Nothing changes yet.
pub fn join_prepare(node: &Node, body: &Value) -> Result<JoinPlan, ApiError> {
    let raw = arg_str(body, "invite").trim();
    operator(node, body, "join", raw)?;
    let inv = read_invite(raw, now_millis()).map_err(|e| ApiError::new(400, e))?;
    let network = node.members.read().unwrap().network.clone();
    if inv.network != network {
        return Err(ApiError::new(409, format!(
            "this node is on network {network}; the invite is for {}. A node belongs to one network: join from a fresh node \
             (islandmail.py join with a new --config)", inv.network)));
    }
    let me_key = fmt_key(&node.seed.public());
    if inv.node.key == me_key {
        return Err(ApiError::new(409, "this invite is from this node"));
    }
    if inv.for_key.is_some_and(|k| node.seed.public()[..4] != k) {
        return Err(ApiError::new(409, format!("this invite is for another node key (starting {}), not this node's {me_key}",
                                               b64u(&inv.for_key.unwrap()))));
    }
    for n in split_names(&inv.name).map_err(|e| ApiError::new(400, e))? {
        if inv.node.covers(&n) {
            return Err(ApiError::new(409, format!("the inviting node claims {n} itself")));
        }
        if let Some(h) = holder(&node.members.read().unwrap(), &n, Some(&me_key)) {
            return Err(ApiError::new(409, format!("{n} is held here by {h}")));
        }
    }
    if let Some(c) = claims_held(&node.members.read().unwrap(), &inv.node) {
        return Err(ApiError::new(409, format!("the inviting node claims a name held here: {c}")));
    }
    let mut mine = own_entry(node)?;
    mine.name = inv.name.clone();
    let reply = encode_reply(&Reply { network, node: mine, name: inv.name.clone(), nonce: inv.nonce }, node);
    Ok(JoinPlan { inv, reply })
}

/// Second half: unless the inviting node refused, trust it and make sure this node may certify the invited name.
pub fn join_finish(node: &Node, plan: JoinPlan, outcome: Outcome) -> Result<Value, ApiError> {
    let (joined, why) = match outcome {
        Outcome::Answered(v) if v["ok"] == true => (true, None),
        Outcome::Answered(v) => return Err(ApiError::new(409, format!("the inviting node refused: {}",
                                                                      v["error"].as_str().unwrap_or("no reason given")))),
        Outcome::Unreachable(why) => (false, Some(why)),
    };
    let inv = plan.inv;
    let mut added_name = false;
    let mut suggested: Vec<String> = Vec::new();
    let names = split_names(&inv.name).map_err(|e| ApiError::new(400, e))?;
    let list = edit_trust(node, |list, me| {
        // A fresh host (this node alone on its trust file) takes the inviter's relays: it has no others and may need
        // them to reach the inviter. An existing host keeps its own: an inviter must not route all of its traffic
        // through relays of the inviter's choosing. Those it lacks are suggested.
        let fresh = list.nodes.iter().all(|n| n.key == me);
        for n in &names {
            if let Some(h) = holder(list, n, Some(me)) {
                return Err(ApiError::new(409, format!("{n} is held here by {h}")));
            }
        }
        if let Some(c) = claims_held(list, &inv.node) {
            return Err(ApiError::new(409, format!("the inviting node claims a name held here: {c}")));
        }
        let mine = list.nodes.iter_mut().find(|n| n.key == me).expect("own entry");
        for n in &names {
            if !mine.covers(n) {
                mine.names.push(n.clone());
                added_name = true;
            }
        }
        match list.nodes.iter_mut().find(|n| n.key == inv.node.key) {
            Some(n) => *n = inv.node.clone(),
            None => list.nodes.push(inv.node.clone()),
        }
        // n0 stays a per-node choice (config "relay").
        for r in inv.relay.iter().filter(|r| *r != "n0") {
            if list.relays.contains(r) { continue; }
            if fresh { list.relays.push(r.clone()); } else { suggested.push(r.clone()); }
        }
        Ok(())
    })?;
    Ok(json!({
        "joined": joined, "unreachable": why, "reply": if joined { Value::Null } else { plan.reply.into() },
        "network": list.network, "seq": list.seq,
        "inviter": { "name": inv.node.name, "key": inv.node.key, "names": inv.node.names }, "from": inv.from,
        "name": inv.name, "names": names, "added_name": added_name, "room": inv.room,
        "relay": { "invite": inv.relay, "node": crate::net::relay_entries(&list, &node.opts.relay), "suggested": suggested },
    }))
}

/// Trust the node of `reply` for exactly the name of the invite whose nonce it carries, and spend that nonce, both
/// under the trust-edit lock. `peer`: the key the QUIC handshake proved, for a reply that arrived over JOIN_ALPN.
fn admit(node: &Node, reply: &str, peer: Option<&str>) -> Result<Value, ApiError> {
    let r = read_reply(reply).map_err(|e| ApiError::new(400, e))?;
    if peer.is_some_and(|p| p != r.node.key) {
        return Err(ApiError::new(403, "the reply names another node key than the connection"));
    }
    if r.network != node.members.read().unwrap().network || r.node.key == fmt_key(&node.seed.public()) {
        return Err(ApiError::new(400, "this reply answers no invite of this node"));
    }
    let nonce = b64u(&r.nonce);
    let name = r.name.clone();
    let mut row: Option<(String, String)> = None;
    let list = edit_trust_with(node, |list, _, db| {
        type InviteRow = (String, String, String, i64, Option<String>, Option<String>);
        let got: Option<InviteRow> = db.query_row(
            "SELECT name, room, from_, exp, spent_by, for_key FROM join_invites WHERE nonce = ?", [&nonce],
            |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, x.get(5)?))).ok();
        let Some((want, room, from, exp, spent, for_key)) = got else {
            return Err(ApiError::new(403, "no such invite here (unknown nonce)"));
        };
        if let Some(by) = spent {
            if by == r.node.key { row = Some((room, from)); return Ok(()); }  // the same node again: nothing to do
            return Err(ApiError::new(409, "this invite was already used"));
        }
        if now_millis() >= exp {
            return Err(ApiError::new(403, format!("the invite expired at {}", islandmail_core::ts_from_millis(exp))));
        }
        if for_key.as_ref().is_some_and(|k| *k != r.node.key) {
            return Err(ApiError::new(403, "this invite is bound to another node key"));
        }
        if want != name {
            return Err(ApiError::new(403, format!("the invite was for {want:?}, not {name:?}")));
        }
        let names: Vec<String> = want.split(',').map(String::from).collect();
        for n in &names {
            if let Some(h) = holder(list, n, Some(&r.node.key)) {
                return Err(ApiError::new(409, format!("{n} is already held here by {h}; refusing to hand it to another node")));
            }
        }
        let entry = match list.nodes.iter().position(|n| n.key == r.node.key) {
            Some(i) => &mut list.nodes[i],
            None => {
                list.nodes.push(NodeEntry { name: names[0].clone(), key: r.node.key.clone(), addrs: vec![], names: vec![] });
                list.nodes.last_mut().unwrap()
            }
        };
        entry.addrs = r.node.addrs.clone();
        for n in &names {
            if !entry.names.iter().any(|e| e.eq_ignore_ascii_case(n)) { entry.names.push(n.clone()); }
        }
        // Spent in the transaction that commits only with the trust file written (edit_trust_with).
        let n = db.execute("UPDATE join_invites SET spent_by = ?, spent_ms = ? WHERE nonce = ? AND spent_by IS NULL",
                           rusqlite::params![r.node.key, now_millis(), nonce]).map_err(anyhow::Error::from)?;
        if n != 1 { return Err(ApiError::new(409, "this invite was already used")); }
        row = Some((room, from));
        Ok(())
    })?;
    let (room, from) = row.expect("set on success");
    tracing::info!("node {} joined with an invite for {name}", r.node.key);
    Ok(json!({ "ok": true, "name": name, "room": (!room.is_empty()).then_some(room), "from": (!from.is_empty()).then_some(from),
               "node": { "name": name.split(',').next().unwrap_or(""), "key": r.node.key }, "seq": list.seq }))
}


/// POST /api/accepts {reply, ts, sig}: the inviting node could not be reached at join; the owner hands in the reply.
pub fn accept(node: &Node, body: &Value) -> Result<Value, ApiError> {
    let raw = arg_str(body, "reply").trim();
    operator(node, body, "accept", raw)?;
    admit(node, raw, None)
}

/// At most `max` events per key in the last minute.
fn allow(key: &str, max: usize) -> bool {
    static SEEN: std::sync::OnceLock<Mutex<std::collections::HashMap<String, Vec<i64>>>> = std::sync::OnceLock::new();
    let now = now_millis();
    let mut m = SEEN.get_or_init(Default::default).lock().unwrap();
    if m.len() > 10_000 { m.retain(|_, v| v.iter().any(|&t| t > now - 60_000)); }
    let v = m.entry(key.to_string()).or_default();
    v.retain(|&t| t > now - 60_000);
    if v.len() >= max { return false; }
    v.push(now);
    true
}

pub const MAX_JOIN_REQUEST: usize = 1024;

/// Whether `req` is a well-signed reply naming the nonce of an unspent, unexpired invite of this node.
fn names_open_invite(node: &Node, req: &[u8]) -> bool {
    let Some(r) = std::str::from_utf8(req).ok().and_then(|r| read_reply(r).ok()) else { return false };
    node.store.conn().query_row("SELECT 1 FROM join_invites WHERE nonce = ? AND spent_by IS NULL AND exp > ?",
                                rusqlite::params![b64u(&r.nonce), now_millis()], |_| Ok(())).is_ok()
}

/// One request on JOIN_ALPN from `peer` (any key): the answer, as JSON bytes. Rate-limited per key and overall.
pub fn handshake(node: &Node, peer: &[u8; 32], req: &[u8]) -> Vec<u8> {
    let peer = fmt_key(peer);
    // Keys cost nothing, so the overall limit is the one that binds; a reply carrying the nonce of an invite still open
    // here is not counted against it, or anyone could keep every invited node out with 30 bogus attempts a minute.
    let out = if !allow(&peer, 5) || (!names_open_invite(node, req) && !allow("join:all", 30)) {
        json!({ "error": "too many join attempts; try again in a minute" })
    } else {
        match std::str::from_utf8(req).map_err(|_| ApiError::new(400, "not text")).and_then(|r| admit(node, r, Some(&peer))) {
            Ok(v) => v,
            Err(e) => {
                tracing::info!("join attempt from {peer} refused: {}", e.message);
                json!({ "error": e.message })
            }
        }
    };
    out.to_string().into_bytes()
}

/// GET /api/invites/joined: nodes that joined with an invite `from` this agent, not yet seen by it.
pub fn joined_for(node: &Node, from: &str) -> Result<Value, ApiError> {
    let db = node.store.conn();
    let mut st = db.prepare("SELECT nonce, name, room, spent_by, spent_ms FROM join_invites
                             WHERE spent_by IS NOT NULL AND told = 0 AND lower(from_) = lower(?) ORDER BY spent_ms")?;
    let rows = st.query_map([from], |x| Ok(json!({ "nonce": x.get::<_, String>(0)?, "name": x.get::<_, String>(1)?,
        "room": x.get::<_, String>(2)?, "node": x.get::<_, String>(3)?, "at": islandmail_core::ts_from_millis(x.get(4)?) })))?;
    Ok(json!({ "joined": rows.collect::<rusqlite::Result<Vec<_>>>()? }))
}

/// The room adds this node can make itself: joins with an invite from an agent whose key it holds (identities_dir, or
/// lent for a session, as for MCPL agents), once every joined name's agent is known here. The node posts the add event and the history
/// grants as that agent, as its client would, and marks the join seen. Others wait for the agent's own client.
pub fn complete_held(node: &Node) {
    let rows: Vec<(String, String, String, String)> = {
        let db = node.store.conn();
        let Ok(mut st) = db.prepare("SELECT nonce, name, room, from_ FROM join_invites
                                     WHERE spent_by IS NOT NULL AND told = 0 AND room != '' AND from_ != ''") else { return };
        st.query_map([], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?)))
            .map(|r| r.filter_map(Result::ok).collect()).unwrap_or_default()
    };
    static FAILED: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);
    for (nonce, names, room, from) in rows {
        if FAILED.lock().unwrap().as_ref().is_some_and(|f| f.contains(&nonce)) { continue; }
        let agents = node.agents();
        let names: Vec<String> = names.split(',').map(String::from).collect();
        if !names.iter().all(|n| islandmail_core::members::named(&agents, n).next().is_some()) { continue; }
        let Some(who) = islandmail_core::members::named(&agents, &from)
            .map(|a| crate::node::Caller { key: fmt_key(&a.key), name: a.name.clone(), sub: a.sub.clone(), exp_ms: i64::MAX })
            .find(|w| node.local_key(w).is_some()) else { continue };
        match add_as(node, &who, &room, &names) {
            Ok(note) => {
                let _ = joined_seen(node, &from, &nonce);
                tracing::info!("added {} to {room} for {from}, who invited them{note}", names.join(", "));
            }
            // Once per join: the agent's own client adds them on its next run instead.
            Err(e) => if FAILED.lock().unwrap().get_or_insert_default().insert(nonce) {
                tracing::warn!("adding {} to {room} for {from}: {}", names.join(", "), e.message);
            },
        }
    }
}

/// A room add made by the node for a held identity: the membership event, the grants (a private room's history),
/// then the creator's vouch, as `room_send` and the client do after an add. In an open CREATOR/NAME room the vouch
/// carries on with the grant of its membership events (`Node::grant_open_events`); another member's add sends it here.
fn add_as(node: &Node, who: &crate::node::Caller, room: &str, names: &[String]) -> Result<String, ApiError> {
    let event = json!({ "op": "add", "members": names });
    let ev: islandmail_core::room::Event = serde_json::from_value(event.clone()).map_err(|e| ApiError::new(400, format!("{e}")))?;
    let (members, agents) = (node.members.read().unwrap().clone(), node.agents());
    let plan = node.room_plan(room, &who.name, Some(&ev), &members, &agents)?;
    let text = format!("added {}", names.iter().map(|n| format!("@{n}")).collect::<Vec<_>>().join(", "));
    node.post(who, &json!({ "to": plan.to, "thread": room, "text": text, "mode": plan.mode.as_str(), "room": room, "event": event }))?;
    let mut note = String::new();
    if plan.mode == islandmail_core::Mode::Private {
        let keys = node.room_keys(who, room)?;
        for n in names {
            for chunk in keys.chunks(500) {
                let meta = serde_json::to_string(&json!({ "grant": chunk })).expect("JSON");
                node.post(who, &json!({ "to": n, "thread": room, "mode": "private", "meta": meta,
                                        "text": format!("key grant: {} earlier messages of {room}", chunk.len()) }))?;
            }
        }
        note = format!("; {} earlier messages granted", keys.len());
    }
    if islandmail_core::room::creator_of(room).is_some_and(|c| islandmail_core::addr::same(c, &who.name)) {
        if let Err(e) = node.send_vouch(who, room) {
            tracing::warn!("{room}: could not post the creator's vouch: {}", e.message);
        }
    } else if plan.mode != islandmail_core::Mode::Private {
        node.grant_open_events(who, room)?;
    }
    Ok(note)
}

/// POST /api/invites/joined {nonce}: this agent has seen (and done the room add for) that join.
pub fn joined_seen(node: &Node, from: &str, nonce: &str) -> Result<Value, ApiError> {
    let n = node.store.conn().execute("UPDATE join_invites SET told = 1 WHERE nonce = ? AND lower(from_) = lower(?) AND spent_by IS NOT NULL",
                                      [nonce, from])?;
    Ok(json!({ "updated": n }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips() {
        for b in [vec![], vec![0], vec![0, 0, 1, 255], (0..=255u8).collect::<Vec<_>>()] {
            assert_eq!(b58_decode(&b58(&b)).unwrap(), b);
        }
        assert_eq!(b58(b"hello world"), "StV1DL6CwTryKyV");
        assert!(b58_decode("0OIl").is_none());
    }

    fn node_on(network: [u8; 32], names: &[&str]) -> Node {
        let seed = islandmail_core::keys::Seed::generate();
        let list = MemberList { v: 1, network: b64u(&network), seq: 1, members: vec![], relays: vec![],
            nodes: vec![NodeEntry { name: "a".into(), key: fmt_key(&seed.public()), addrs: vec!["192.0.2.7:4433".into()],
                                    names: names.iter().map(|n| n.to_string()).collect() }] };
        let tag = b64u(&islandmail_core::random_bytes::<9>());
        let path = std::env::temp_dir().join(format!("islandmail-invite-{tag}.sqlite"));
        let trust = std::env::temp_dir().join(format!("islandmail-invite-{tag}.json"));
        std::fs::write(&trust, serde_json::to_vec(&list).unwrap()).unwrap();
        let store = crate::store::Store::open(&path).unwrap();
        store.bind_roster(&seed.public(), &list).unwrap();
        let opts = crate::node::Opts { public_url: "http://x".into(), relay: vec!["n0".into()], members_file: Some(trust),
                                       ..Default::default() };
        Node::new(store, list, seed, opts, tokio::sync::mpsc::channel(1).0)
    }

    fn signed(n: &Node, action: &str, arg: &str, mut body: Value) -> Value {
        let ts = islandmail_core::now_ts();
        let st = operator_statement(action, &fmt_key(&n.seed.public()), &ts, arg);
        body["ts"] = ts.into();
        body["sig"] = b64u(&n.seed.sign(st.as_bytes())).into();
        body
    }

    fn make(n: &Node, name: &str, room: &str) -> String {
        make_for(n, name, room, "").unwrap()
    }

    fn make_for(n: &Node, name: &str, room: &str, key: &str) -> Result<String, ApiError> {
        let body = json!({ "name": name, "room": room, "from": "alice", "ttl_s": 0, "key": key });
        Ok(invite(n, &signed(n, "invite", &format!("{name}|{room}|alice|0|{key}"), body))?["invite"].as_str().unwrap().into())
    }

    /// A joining node's reply to `inv`, presenting `name`.
    fn reply_of(j: &Node, inv: &str, name: &str) -> String {
        let i = read_invite(inv, now_millis()).unwrap();
        encode_reply(&Reply { network: i.network, node: NodeEntry { name: name.into(), key: fmt_key(&j.seed.public()),
                              addrs: vec!["192.0.2.9:4433".into()], names: vec![] }, name: name.into(), nonce: i.nonce }, j)
    }

    fn answer(a: &Node, j: &Node, reply: &str) -> Value {
        serde_json::from_slice(&handshake(a, &j.seed.public(), reply.as_bytes())).unwrap()
    }

    #[test]
    fn the_join_handshake_spends_the_nonce_once_for_exactly_the_name() {
        let a = node_on([3u8; 32], &["alice"]);
        let (b, c) = (node_on([3u8; 32], &[]), node_on([3u8; 32], &[]));
        let inv = make(&a, "bob", "alice/plan");
        let r = reply_of(&b, &inv, "bob");
        assert!(r.starts_with("imr1") && r.len() <= 260, "{} chars", r.len());
        // Presented by another key than the connection's: refused.
        let v: Value = serde_json::from_slice(&handshake(&a, &c.seed.public(), r.as_bytes())).unwrap();
        assert!(v["error"].as_str().unwrap().contains("another node key"), "{v}");
        let v = answer(&a, &b, &r);
        assert_eq!((v["ok"].as_bool(), v["name"].as_str(), v["room"].as_str()), (Some(true), Some("bob"), Some("alice/plan")), "{v}");
        let entry = a.members.read().unwrap().node_by_key(&b.seed.public()).cloned().unwrap();
        assert_eq!((entry.names, entry.addrs), (vec!["bob".to_string()], vec!["192.0.2.9:4433".to_string()]));
        assert_eq!(answer(&a, &b, &r)["ok"], true, "the same node again is a no-op");
        assert!(answer(&a, &c, &reply_of(&c, &inv, "bob"))["error"].as_str().unwrap().contains("already used"));
        // The inviting agent sees the join once.
        assert_eq!(joined_for(&a, "alice").unwrap()["joined"].as_array().unwrap().len(), 1);
        let nonce = joined_for(&a, "alice").unwrap()["joined"][0]["nonce"].as_str().unwrap().to_string();
        joined_seen(&a, "alice", &nonce).unwrap();
        assert!(joined_for(&a, "alice").unwrap()["joined"].as_array().unwrap().is_empty());
        // Another name than the invited one; a name this node holds; an unknown nonce; a changed byte.
        let inv2 = make(&a, "carol", "");
        // (a fresh joining node for each try: the handshake allows a few attempts per key and minute)
        let fresh = || node_on([3u8; 32], &[]);
        let d = fresh();
        assert!(answer(&a, &d, &reply_of(&d, &inv2, "dave"))["error"].as_str().unwrap().contains("not \"dave\""));
        let other = node_on([3u8; 32], &["alice"]);
        let stranger = make(&other, "carol", "");
        let d = fresh();
        assert!(answer(&a, &d, &reply_of(&d, &stranger, "carol"))["error"].as_str().unwrap().contains("unknown nonce"));
        let d = fresh();
        let mut raw = b58_decode(&reply_of(&d, &inv2, "carol")[4..]).unwrap();
        raw[1 + 32 + 32 + 16 + 1] ^= 1;
        assert!(answer(&a, &d, &format!("imr1{}", b58(&raw)))["error"].as_str().unwrap().contains("signature"));
        // carol becomes ours before the join: refused.
        edit_trust(&a, |list, me| { list.nodes.iter_mut().find(|n| n.key == me).unwrap().names.push("carol".into()); Ok(()) }).unwrap();
        let d = fresh();
        assert!(answer(&a, &d, &reply_of(&d, &inv2, "carol"))["error"].as_str().unwrap().contains("already held"));
        // Key-bound: only that node may join, and the invite lasts a week (key-less: a day).
        let (e, f) = (fresh(), fresh());
        let bound = make_for(&a, "morel,skizy", "", &fmt_key(&e.seed.public())).unwrap();
        let i = read_invite(&bound, now_millis()).unwrap();
        println!("key-bound invite for two names: {} chars", bound.len());
        assert!(bound.len() <= 280 && i.for_key == Some(e.seed.public()[..4].try_into().unwrap()), "{} chars", bound.len());
        assert!(i.exp - now_millis() > 6 * 24 * 3600 * 1000);
        assert!(read_invite(&inv2, now_millis()).unwrap().exp - now_millis() <= KEYLESS_LIFE_S * 1000 + 2000);
        assert!(answer(&a, &f, &reply_of(&f, &bound, "morel,skizy"))["error"].as_str().unwrap().contains("bound to another"));
        assert!(answer(&a, &e, &reply_of(&e, &bound, "morel"))["error"].as_str().unwrap().contains("not \"morel\""));
        assert_eq!(answer(&a, &e, &reply_of(&e, &bound, "morel,skizy"))["ok"], true);
        let names = a.members.read().unwrap().node_by_key(&e.seed.public()).unwrap().names.clone();
        assert_eq!(names, vec!["morel".to_string(), "skizy".to_string()]);
        assert!(make_for(&a, "x,x", "", "").is_err() && make_for(&a, "a.", "", "").is_err() && make_for(&a, "q", "", "ed25519:no").is_err());
        // A flood from one key is cut off after a few tries.
        let d = fresh();
        let flood: Vec<Value> = (0..8).map(|_| answer(&a, &d, "imr1junk")).collect();
        assert!(flood.iter().any(|v| v["error"].as_str().unwrap().contains("too many")));
        // Bogus attempts from many keys fill the overall limit, but a reply to an open invite still gets through
        // (found by the fuzz/ protocol tests: 30 junk attempts a minute kept every invited node out).
        for _ in 0..8 {
            let d = fresh();
            for _ in 0..5 { answer(&a, &d, "imr1junk"); }
        }
        let (inv3, g) = (make(&a, "gail", ""), fresh());
        assert!(answer(&a, &fresh(), "imr1junk")["error"].as_str().unwrap().contains("too many"));
        assert_eq!(answer(&a, &g, &reply_of(&g, &inv3, "gail"))["ok"], true);
    }

    #[test]
    fn a_refused_trust_edit_does_not_spend_the_invite() {
        let a = node_on([7u8; 32], &["alice"]);
        let b = node_on([7u8; 32], &[]);
        // b is trusted here already, for as many names as a node may hold: one more makes the trust file invalid.
        let full: Vec<String> = (0..islandmail_core::members::MAX_NAMES).map(|i| format!("b{i}")).collect();
        let bkey = fmt_key(&b.seed.public());
        edit_trust(&a, |list, _| {
            list.nodes.push(NodeEntry { name: "b".into(), key: bkey.clone(), addrs: vec![], names: full.clone() });
            Ok(())
        }).unwrap();
        let seq = a.members.read().unwrap().seq;
        let inv = make(&a, "bob", "");
        let r = reply_of(&b, &inv, "bob");
        let v = answer(&a, &b, &r);
        assert!(v["error"].as_str().unwrap().contains("more than"), "{v}");
        let unspent = |n: &Node| n.store.conn().query_row("SELECT count(*) FROM join_invites WHERE spent_by IS NULL",
                                                          [], |x| x.get::<_, i64>(0)).unwrap();
        assert_eq!(unspent(&a), 1, "the refused join left the invite unspent");
        assert_eq!(a.members.read().unwrap().seq, seq, "and the trust file as it was");
        // Room made: the same invite works.
        edit_trust(&a, |list, _| { list.nodes.iter_mut().find(|n| n.key == bkey).unwrap().names.pop(); Ok(()) }).unwrap();
        assert_eq!(answer(&a, &b, &r)["ok"], true);
        assert_eq!(unspent(&a), 0);
        assert!(a.members.read().unwrap().node_by_key(&b.seed.public()).unwrap().names.contains(&"bob".to_string()));
    }

    #[test]
    fn only_a_fresh_host_takes_the_inviters_relays() {
        let a = node_on([6u8; 32], &["alice"]);
        let url = "https://relay.example.org".to_string();
        a.members.write().unwrap().relays = vec![url.clone()];
        let make = |name: &str| invite(&a, &signed(&a, "invite", &format!("{name}|||604800|"), json!({ "name": name, "ttl_s": 604800, "key": "" })))
            .unwrap()["invite"].as_str().unwrap().to_string();
        let join = |j: &Node, inv: &str| {
            let plan = join_prepare(j, &signed(j, "join", inv, json!({ "invite": inv }))).map_err(|e| e.message).unwrap();
            join_finish(j, plan, Outcome::Unreachable("test".into())).map_err(|e| e.message).unwrap()
        };
        // A fresh host: this node alone on its trust file.
        let fresh = node_on([6u8; 32], &[]);
        let out = join(&fresh, &make("bob"));
        assert_eq!(fresh.members.read().unwrap().relays, vec![url.clone()]);
        assert!(out["relay"]["suggested"].as_array().unwrap().is_empty(), "{out}");
        // An existing host (it trusts another node already) keeps its relays; the inviter's are only suggested.
        let old = node_on([6u8; 32], &["carol"]);
        let other = islandmail_core::keys::Seed::generate();
        edit_trust(&old, |list, _| {
            list.nodes.push(NodeEntry { name: "x".into(), key: fmt_key(&other.public()), addrs: vec![], names: vec!["x".into()] });
            Ok(())
        }).unwrap();
        let out = join(&old, &make("dave"));
        assert!(old.members.read().unwrap().relays.is_empty());
        assert_eq!(out["relay"]["suggested"], json!([url]), "{out}");
    }

    #[test]
    fn a_joining_host_refuses_an_inviter_that_claims_names_held_here() {
        // The joining host already runs a node for carol and trusts another node for ops.; the inviting node's
        // invite (which it signs itself) claims carol and ops.x as its own names.
        let a = node_on([5u8; 32], &["carol", "ops.x"]);
        let j = node_on([5u8; 32], &["carol"]);
        let other = islandmail_core::keys::Seed::generate();
        edit_trust(&j, |list, _| {
            list.nodes.push(NodeEntry { name: "ops".into(), key: fmt_key(&other.public()), addrs: vec![], names: vec!["ops.".into()] });
            Ok(())
        }).unwrap();
        let inv = invite(&a, &signed(&a, "invite", "bob|||604800|", json!({ "name": "bob", "ttl_s": 604800, "key": "" })))
            .unwrap()["invite"].as_str().unwrap().to_string();
        let err = join_prepare(&j, &signed(&j, "join", &inv, json!({ "invite": inv }))).err().expect("refused");
        assert_eq!(err.status, 409, "{}", err.message);
        assert!(err.message.contains("carol"), "{}", err.message);
        // Nothing changed: the inviting node is not trusted here.
        assert!(j.members.read().unwrap().node_by_key(&a.seed.public()).is_none());
        // An inviter that claims only names nobody here holds is fine.
        let a2 = node_on([5u8; 32], &["dave"]);
        let inv2 = invite(&a2, &signed(&a2, "invite", "bob|||604800|", json!({ "name": "bob", "ttl_s": 604800, "key": "" })))
            .unwrap()["invite"].as_str().unwrap().to_string();
        let plan = join_prepare(&j, &signed(&j, "join", &inv2, json!({ "invite": inv2 }))).map_err(|e| e.message).unwrap();
        join_finish(&j, plan, Outcome::Unreachable("test".into())).map_err(|e| e.message).unwrap();
        assert!(j.members.read().unwrap().node_by_key(&a2.seed.public()).is_some());
    }

    fn node() -> Node {
        node_on([7u8; 32], &["alice"])
    }
    #[test]
    fn invites_round_trip_and_refuse_tampering_and_expiry() {
        let n = node();
        let now = now_millis();
        let body = |name: &str, room: &str| {
            let ts = islandmail_core::now_ts();
            let arg = format!("{name}|{room}|alice|604800|");
            let st = operator_statement("invite", &fmt_key(&n.seed.public()), &ts, &arg);
            json!({ "name": name, "room": room, "from": "alice", "ttl_s": 604800, "ts": ts, "sig": b64u(&n.seed.sign(st.as_bytes())) })
        };
        let s = invite(&n, &body("bob", "alice/plan")).unwrap()["invite"].as_str().unwrap().to_string();
        assert!(s.starts_with("im1") && s.len() <= 260, "{} chars: {s}", s.len());
        let inv = read_invite(&s, now).unwrap();
        assert_eq!((inv.name.as_str(), inv.room.as_deref(), inv.from.as_deref()), ("bob", Some("alice/plan"), Some("alice")));
        assert_eq!(inv.node.names, vec!["alice".to_string()]);
        assert_eq!(inv.node.addrs, vec!["192.0.2.7:4433".to_string()]);
        assert_eq!(inv.relay, vec!["n0".to_string()]);
        assert_eq!(inv.node.key, fmt_key(&n.seed.public()));
        // Any changed byte breaks the signature.
        let mut raw = b58_decode(&s[3..]).unwrap();
        raw[1 + 32 + 32 + 4 + 16 + 1] ^= 1;
        assert!(read_invite(&format!("im1{}", b58(&raw)), now).unwrap_err().contains("signature"));
        assert!(read_invite(&s, inv.exp).unwrap_err().contains("expired"));
        assert!(read_invite(&s.replace("im1", "imr1"), now).is_err());
        let rs = reply_of(&n, &s, "bob");
        assert_eq!(read_reply(&rs).unwrap().nonce, inv.nonce);
        let plain = invite(&n, &body("bob", "")).unwrap()["invite"].as_str().unwrap().len();
        // An invite carries the network's relays (trust file) and the node's own (here n0, opted in).
        n.members.write().unwrap().relays = vec!["https://relay.example.org".into()];
        let s2 = invite(&n, &body("dave", "")).unwrap()["invite"].as_str().unwrap().to_string();
        assert_eq!(read_invite(&s2, now).unwrap().relay, vec!["n0".to_string(), "https://relay.example.org".into()]);
        println!("invite {} chars with a room, {plain} without; reply {} chars", s.len(), rs.len());
    }
}
