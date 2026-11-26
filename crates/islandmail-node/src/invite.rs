//! One-step joining: an invite (signed by the inviting node), the joiner's reply (signed by the joining node), and the
//! trust-file edits each step makes. The host owner asks for each step over the loopback API with a request signed by
//! this node's key (`operator_statement`), as `islandmail.py invite / join / accept` do. The node writes its own
//! trust file (seq + 1, other entries kept) and adopts it at once.
//!
//! Both are short base58 strings of raw bytes (str = u8 length + UTF-8; u32 big-endian):
//!
//!   im1 + base58(flags u8 | network 32 | node key 32 | exp u32 (unix s) | ticket 16 | name str
//!                | [from str] | [room str] | [names: n u8, n str] | [addrs] | [relay URLs: n u8, n str] | sig 64)
//!   imr1 + base58(flags u8 | network 32 | node key 32 | exp u32 | ticket 16 | name str | [room str] | [addrs] | sig 64)
//!
//! flags: 1 relay n0, 2 relay URLs, 4 addrs, 8 names, 16 from, 32 room. addrs = n u8, then per address 4 | IPv4 4 |
//! port u16 or 6 | IPv6 16 | port u16. sig is the node key's Ed25519 signature over "islandmail/invite/v1\n" (reply:
//! "islandmail/invite-reply/v1\n") + every byte before it. Derived, not sent: the inviting node's names default to
//! [from], its entry name is from (else its first name); the joining node's entry name is the invited name. The ticket
//! is the first 16 bytes of the inviting node's (deterministic) signature over network, exp, name and room, so accept
//! checks that its own node issued the invite, still unexpired, without keeping any state.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Mutex;

use islandmail_core::cert::{valid_name, valid_namespace_entry};
use islandmail_core::keys::{fmt_key, parse_key};
use islandmail_core::members::NodeEntry;
use islandmail_core::{b64u, b64u_decode, now_millis, MemberList};
use serde_json::{json, Value};

use crate::node::{ApiError, Node};

pub const INVITE_PREFIX: &str = "im1";
pub const REPLY_PREFIX: &str = "imr1";
const INVITE_CTX: &[u8] = b"islandmail/invite/v1\n";
const REPLY_CTX: &[u8] = b"islandmail/invite-reply/v1\n";
const TICKET_CTX: &[u8] = b"islandmail/invite-ticket/v1\n";
pub const MAX_INVITE_LIFE_MS: i64 = 7 * 24 * 3600 * 1000;
const SKEW_MS: i64 = 300_000;
const N0: u8 = 1;
const URLS: u8 = 2;
const ADDRS: u8 = 4;
const NAMES: u8 = 8;
const FROM: u8 = 16;
const ROOM: u8 = 32;

#[derive(Clone, Debug)]
pub struct Invite {
    pub network: String,
    /// The inviting node, as the joiner will list it.
    pub node: NodeEntry,
    /// The inviter's relay setting (config "relay").
    pub relay: Vec<String>,
    /// The one exact agent name the inviter will trust the joining node for.
    pub name: String,
    /// The inviting agent, if one asked: whom to write to first.
    pub from: Option<String>,
    /// A room the joined agent is added to on accept.
    pub room: Option<String>,
    pub exp: i64,
    pub ticket: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub network: String,
    /// The joining node: its key and addrs (accept trusts it for the invite's name only).
    pub node: NodeEntry,
    pub name: String,
    pub room: Option<String>,
    pub exp: i64,
    pub ticket: [u8; 16],
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

/// The ticket only the inviting node can make: it ties name, room and expiry to this node and network.
fn ticket(node: &Node, network: &[u8; 32], exp_s: u32, name: &str, room: &str) -> [u8; 16] {
    let mut w = W::default();
    w.put(TICKET_CTX).put(network).put(&exp_s.to_be_bytes()).str(name).str(room);
    node.seed.sign(&w.0)[..16].try_into().unwrap()
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
        | if inv.from.is_some() { FROM } else { 0 } | if inv.room.is_some() { ROOM } else { 0 };
    let mut w = W::default();
    w.put(&[flags]).put(&network_bytes(&inv.network).expect("own network")).put(&key_bytes(&inv.node.key))
        .put(&((inv.exp / 1000) as u32).to_be_bytes()).put(&inv.ticket).str(&inv.name);
    if let Some(f) = &inv.from { w.str(f); }
    if let Some(r) = &inv.room { w.str(r); }
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
    let ticket = r.arr::<16>()?;
    let name = r.str().map_err(bad)?;
    let from = if flags & FROM != 0 { Some(r.str().map_err(bad)?) } else { None };
    let room = if flags & ROOM != 0 { Some(r.str().map_err(bad)?) } else { None };
    let names = if flags & NAMES != 0 { (0..r.u8()?).map(|_| r.str()).collect::<Result<Vec<_>, _>>().map_err(bad)? }
                else { vec![from.clone().ok_or("invite is malformed (no names)")?] };
    let addrs = if flags & ADDRS != 0 { r.addrs().map_err(bad)? } else { vec![] };
    let mut relay = if flags & N0 != 0 { vec!["n0".to_string()] } else { vec![] };
    if flags & URLS != 0 { for _ in 0..r.u8()? { relay.push(r.str().map_err(bad)?); } }
    if !r.0.is_empty() || flags & !63 != 0 { return Err("invite is malformed".into()); }
    let node_name = from.clone().or_else(|| names.first().map(|n| n.trim_end_matches('.').to_string())).unwrap_or("peer".into());
    let inv = Invite { network, node: NodeEntry { name: node_name, key, addrs, names }, relay, name, from, room, exp, ticket };
    check_entry(&inv.node).map_err(bad)?;
    if !valid_name(&inv.name) {
        return Err("invite is malformed".into());
    }
    if inv.exp > now + MAX_INVITE_LIFE_MS + SKEW_MS {
        return Err("invite runs longer than 7 days".into());
    }
    if now >= inv.exp {
        return Err(format!("invite expired at {}", islandmail_core::ts_from_millis(inv.exp)));
    }
    Ok(inv)
}

fn encode_reply(r: &Reply, node: &Node) -> String {
    let flags = if r.node.addrs.is_empty() { 0 } else { ADDRS } | if r.room.is_some() { ROOM } else { 0 };
    let mut w = W::default();
    w.put(&[flags]).put(&network_bytes(&r.network).expect("own network")).put(&key_bytes(&r.node.key))
        .put(&((r.exp / 1000) as u32).to_be_bytes()).put(&r.ticket).str(&r.name);
    if let Some(room) = &r.room { w.str(room); }
    if !r.node.addrs.is_empty() { w.addrs(&r.node.addrs); }
    seal(REPLY_PREFIX, REPLY_CTX, w, node)
}

/// `islandmail-node invite-info INVITE`: what a checked invite holds, for setting up a fresh host before its node runs.
pub fn info(s: &str) -> Result<Value, String> {
    let i = read_invite(s, now_millis())?;
    Ok(json!({ "network": i.network, "relay": i.relay, "name": i.name, "from": i.from, "room": i.room,
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
    let exp = u32::from_be_bytes(r.arr()?) as i64 * 1000;
    let ticket = r.arr::<16>()?;
    let name = r.str().map_err(bad)?;
    let room = if flags & ROOM != 0 { Some(r.str().map_err(bad)?) } else { None };
    let addrs = if flags & ADDRS != 0 { r.addrs().map_err(bad)? } else { vec![] };
    if !r.0.is_empty() || flags & !(ADDRS | ROOM) != 0 || !valid_name(&name) { return Err("reply is malformed".into()); }
    Ok(Reply { network, node: NodeEntry { name: name.clone(), key, addrs, names: vec![] }, name, room, exp, ticket })
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

static EDIT: Mutex<()> = Mutex::new(());

/// Edits the trust file on disk (the source of truth) and adopts the result: seq one above both the file and the
/// list in use. `f` may refuse.
fn edit_trust(node: &Node, f: impl FnOnce(&mut MemberList, &str) -> Result<(), ApiError>) -> Result<MemberList, ApiError> {
    let _g = EDIT.lock().unwrap();
    let path = node.opts.members_file.as_deref().ok_or_else(|| ApiError::new(503, "this node has no trust file to edit"))?;
    let mut list = crate::config::Config::parse_members(&std::fs::read(path).map_err(anyhow::Error::from)?)
        .map_err(|e| ApiError::new(409, format!("trust file is not valid now: {e:#}")))?;
    let cur = node.members.read().unwrap().seq;
    if list.network != node.members.read().unwrap().network {
        return Err(ApiError::new(409, "trust file names another network than the one this node runs; restart it first"));
    }
    f(&mut list, &fmt_key(&node.seed.public()))?;
    list.seq = list.seq.max(cur) + 1;
    list.validate().map_err(|e| ApiError::new(409, format!("{e:#}")))?;
    write_atomic(path, &serde_json::to_vec_pretty(&list).expect("JSON"))?;
    node.reload_members(&list).map_err(|e| ApiError::new(409, format!("{e:#}")))?;
    // As when the trust watcher adopts a change: held identities newly in our names, and a sync with the new peer now.
    node.certify_identities();
    node.resync.notify_one();
    Ok(list)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), ApiError> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp-{}", b64u(&islandmail_core::random_bytes::<6>())));
    let r = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
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
    let (name, room, from) = (arg_str(body, "name"), arg_str(body, "room"), arg_str(body, "from"));
    let ttl = body.get("ttl_s").and_then(|v| v.as_i64()).unwrap_or(MAX_INVITE_LIFE_MS / 1000);
    operator(node, body, "invite", &format!("{name}|{room}|{from}|{ttl}"))?;
    if !valid_name(name) {
        return Err(ApiError::new(400, "--name must be one exact agent name (letters, digits, . _ -; not ending in '.')"));
    }
    if !(1..=MAX_INVITE_LIFE_MS / 1000).contains(&ttl) {
        return Err(ApiError::new(400, "ttl_s must be 1 second to 7 days"));
    }
    if room.len() > 200 || room.contains(['|', '\n']) || from.len() > 120 {
        return Err(ApiError::new(400, "invalid room or from"));
    }
    if let Some(h) = holder(&node.members.read().unwrap(), name, None) {
        return Err(ApiError::new(409, format!("{name} is already held here by {h}; invite with a name nobody holds")));
    }
    if name.len() + room.len() + from.len() > 200 {
        return Err(ApiError::new(400, "name, room and from are too long for an invite"));
    }
    let network = node.members.read().unwrap().network.clone();
    let exp_s = ((now_millis() + 999) / 1000 + ttl) as u32;
    let inv = Invite {
        ticket: ticket(node, &network_bytes(&network).map_err(|e| ApiError::new(500, e))?, exp_s, name, room),
        network, node: own_entry(node)?, relay: node.opts.relay.clone(), name: name.into(),
        from: (!from.is_empty()).then(|| from.into()), room: (!room.is_empty()).then(|| room.into()), exp: exp_s as i64 * 1000,
    };
    Ok(json!({ "invite": encode_invite(&inv, node), "exp": islandmail_core::ts_from_millis(inv.exp) }))
}

/// POST /api/joins {invite, ts, sig}: trust the inviting node, make sure this node may certify the invited name, and
/// answer with a reply for the inviter.
pub fn join(node: &Node, body: &Value) -> Result<Value, ApiError> {
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
    if inv.node.covers(&inv.name) {
        return Err(ApiError::new(409, format!("the inviting node claims {} itself", inv.name)));
    }
    let mut added_name = false;
    let list = edit_trust(node, |list, me| {
        if let Some(h) = holder(list, &inv.name, Some(me)) {
            return Err(ApiError::new(409, format!("{} is held here by {h}", inv.name)));
        }
        let mine = list.nodes.iter_mut().find(|n| n.key == me).expect("own entry");
        if !mine.covers(&inv.name) {
            mine.names.push(inv.name.clone());
            added_name = true;
        }
        match list.nodes.iter_mut().find(|n| n.key == inv.node.key) {
            Some(n) => *n = inv.node.clone(),
            None => list.nodes.push(inv.node.clone()),
        }
        Ok(())
    })?;
    let mine = list.node_by_key(&node.seed.public()).cloned().expect("own entry");
    let reply = Reply { network: network.clone(), node: mine, name: inv.name.clone(), room: inv.room.clone(), exp: inv.exp,
                        ticket: inv.ticket };
    Ok(json!({
        "reply": encode_reply(&reply, node), "network": network, "seq": list.seq,
        "inviter": { "name": inv.node.name, "key": inv.node.key, "names": inv.node.names }, "from": inv.from,
        "name": inv.name, "added_name": added_name, "room": inv.room,
        "relay": { "invite": inv.relay, "node": node.opts.relay },
    }))
}

/// POST /api/accepts {reply, ts, sig}: trust the joining node for exactly the name this node's invite offered.
pub fn accept(node: &Node, body: &Value) -> Result<Value, ApiError> {
    let raw = arg_str(body, "reply").trim();
    operator(node, body, "accept", raw)?;
    let r = read_reply(raw).map_err(|e| ApiError::new(400, e))?;
    let me_key = fmt_key(&node.seed.public());
    let network = node.members.read().unwrap().network.clone();
    let exp_s = (r.exp / 1000) as u32;
    if r.network != network || r.node.key == me_key
        || ticket(node, &network_bytes(&network).map_err(|e| ApiError::new(500, e))?, exp_s, &r.name,
                  r.room.as_deref().unwrap_or("")) != r.ticket {
        return Err(ApiError::new(400, "this reply answers no invite of this node (another node's, or altered)"));
    }
    if now_millis() >= r.exp {
        return Err(ApiError::new(400, format!("the invite expired at {}", islandmail_core::ts_from_millis(r.exp))));
    }
    let inv = &r;
    let name = r.name.clone();
    let list = edit_trust(node, |list, _| {
        if list.network != inv.network {
            return Err(ApiError::new(409, "the invite was for another network"));
        }
        if let Some(h) = holder(list, &name, Some(&r.node.key)) {
            return Err(ApiError::new(409, format!("{name} is already held here by {h}; refusing to hand it to another node")));
        }
        match list.nodes.iter_mut().find(|n| n.key == r.node.key) {
            Some(n) => {
                n.addrs = r.node.addrs.clone();
                if !n.names.iter().any(|e| e.eq_ignore_ascii_case(&name)) { n.names.push(name.clone()); }
            }
            None => list.nodes.push(NodeEntry { name: r.node.name.clone(), key: r.node.key.clone(), addrs: r.node.addrs.clone(),
                                                names: vec![name.clone()] }),
        }
        Ok(())
    })?;
    Ok(json!({ "name": name, "room": inv.room, "node": { "name": r.node.name, "key": r.node.key }, "seq": list.seq }))
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

    fn node() -> Node {
        let seed = islandmail_core::keys::Seed::generate();
        let list = MemberList { v: 1, network: b64u(&[7u8; 32]), seq: 1, members: vec![], homes: vec![],
            nodes: vec![NodeEntry { name: "a".into(), key: fmt_key(&seed.public()), addrs: vec!["192.0.2.7:4433".into()],
                                    names: vec!["alice".into()] }] };
        let path = std::env::temp_dir().join(format!("islandmail-invite-{}.sqlite", b64u(&islandmail_core::random_bytes::<9>())));
        let store = crate::store::Store::open(&path).unwrap();
        store.bind_roster(&seed.public(), &list).unwrap();
        let opts = crate::node::Opts { public_url: "http://x".into(), relay: vec!["n0".into()], ..Default::default() };
        Node::new(store, list, seed, opts, tokio::sync::mpsc::channel(1).0)
    }

    #[test]
    fn invites_round_trip_and_refuse_tampering_and_expiry() {
        let n = node();
        let now = now_millis();
        let body = |name: &str, room: &str| {
            let ts = islandmail_core::now_ts();
            let arg = format!("{name}|{room}|alice|604800");
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
        // The reply's ticket proves the invite was this node's, for this name and room only.
        let r = Reply { network: inv.network.clone(), node: NodeEntry { name: "bob".into(), key: fmt_key(&n.seed.public()),
                        addrs: vec![], names: vec![] }, name: "bob".into(), room: inv.room.clone(), exp: inv.exp, ticket: inv.ticket };
        let exp_s = (inv.exp / 1000) as u32;
        assert_eq!(ticket(&n, &[7u8; 32], exp_s, "bob", "alice/plan"), r.ticket);
        assert_ne!(ticket(&n, &[7u8; 32], exp_s, "carol", "alice/plan"), r.ticket);
        let rs = encode_reply(&r, &n);
        assert!(rs.starts_with("imr1") && rs.len() <= 260, "{} chars", rs.len());
        assert_eq!(read_reply(&rs).unwrap().ticket, inv.ticket);
        let plain = invite(&n, &body("bob", "")).unwrap()["invite"].as_str().unwrap().len();
        println!("invite {} chars with a room, {plain} without; reply {} chars", s.len(), rs.len());
    }
}
