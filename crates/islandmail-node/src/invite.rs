//! One-step joining: an invite (signed by the inviting node), the joiner's reply (signed by the joining node), and the
//! trust-file edits each step makes. The host owner asks for each step over the loopback API with a request signed by
//! this node's key (`operator_statement`), as `islandmail.py invite / join / accept` do. The node writes its own
//! trust file (seq + 1, other entries kept) and adopts it at once.
//!
//!   islandmail-invite1.<b64u payload JSON>.<b64u sig over "islandmail/invite/v1\n" + payload>
//!   islandmail-reply1.<b64u payload JSON>.<b64u sig over "islandmail/invite-reply/v1\n" + payload>

use std::path::Path;
use std::sync::Mutex;

use islandmail_core::cert::{valid_name, valid_namespace_entry};
use islandmail_core::keys::{fmt_key, parse_key};
use islandmail_core::members::NodeEntry;
use islandmail_core::{b64u, b64u_decode, now_millis, MemberList};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::node::{ApiError, Node};

pub const INVITE_PREFIX: &str = "islandmail-invite1.";
pub const REPLY_PREFIX: &str = "islandmail-reply1.";
const INVITE_CTX: &str = "islandmail/invite/v1\n";
const REPLY_CTX: &str = "islandmail/invite-reply/v1\n";
pub const MAX_INVITE_LIFE_MS: i64 = 7 * 24 * 3600 * 1000;
const SKEW_MS: i64 = 300_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub v: u32,
    pub network: String,
    /// The inviting node, as the joiner will list it.
    pub node: NodeEntry,
    /// The inviter's relay setting (config "relay").
    pub relay: Vec<String>,
    /// The one exact agent name the inviter will trust the joining node for.
    pub name: String,
    /// The inviting agent, if one asked: whom to write to first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// A room the joined agent is added to on accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub v: u32,
    pub network: String,
    /// The joining node's entry (its own names are ignored: accept trusts it for the invite's name only).
    pub node: NodeEntry,
    /// The invite this answers, whole: accept checks its own signature on it.
    pub invite: String,
    pub iat: i64,
}

fn seal(prefix: &str, ctx: &str, payload: &impl Serialize, node: &Node) -> String {
    let raw = serde_json::to_vec(payload).expect("JSON");
    let sig = node.seed.sign(&[ctx.as_bytes(), &raw].concat());
    format!("{prefix}{}.{}", b64u(&raw), b64u(&sig))
}

/// The payload bytes of a sealed string and the key that must have signed them (read from the payload itself).
fn open<T: for<'de> Deserialize<'de>>(s: &str, prefix: &str, ctx: &str, signer: impl Fn(&T) -> &str) -> Result<T, String> {
    let rest = s.trim().strip_prefix(prefix).ok_or_else(|| format!("does not start with {prefix}"))?;
    let (p, sig) = rest.split_once('.').ok_or("is cut short")?;
    let (raw, sig) = (b64u_decode(p).ok_or("is not base64url")?, b64u_decode(sig).ok_or("is not base64url")?);
    let v: T = serde_json::from_slice(&raw).map_err(|e| format!("is not readable ({e})"))?;
    let key = parse_key(signer(&v)).map_err(|_| "names no valid node key")?;
    if !islandmail_core::keys::verify(&key, &[ctx.as_bytes(), &raw].concat(), &sig) {
        return Err("signature does not match its node key (changed or damaged)".into());
    }
    Ok(v)
}

fn check_entry(n: &NodeEntry) -> Result<(), String> {
    parse_key(&n.key).map_err(|_| "invalid node key")?;
    if n.name.is_empty() || n.name.len() > 64 || n.names.len() > islandmail_core::members::MAX_NAMES
        || !n.names.iter().all(|e| valid_namespace_entry(e))
        || !n.addrs.iter().all(|a| a.parse::<std::net::SocketAddr>().is_ok()) {
        return Err("invalid node entry".into());
    }
    Ok(())
}

pub fn read_invite(s: &str, now: i64) -> Result<Invite, String> {
    let inv: Invite = open(s, INVITE_PREFIX, INVITE_CTX, |i: &Invite| &i.node.key).map_err(|e| format!("invite {e}"))?;
    check_entry(&inv.node).map_err(|e| format!("invite: {e}"))?;
    if inv.v != 1 || !valid_name(&inv.name) || inv.exp <= inv.iat || inv.exp - inv.iat > MAX_INVITE_LIFE_MS {
        return Err("invite is malformed".into());
    }
    if inv.iat > now + SKEW_MS {
        return Err("invite is dated in the future".into());
    }
    if now >= inv.exp {
        return Err(format!("invite expired at {}", islandmail_core::ts_from_millis(inv.exp)));
    }
    Ok(inv)
}

pub fn read_reply(s: &str) -> Result<Reply, String> {
    let r: Reply = open(s, REPLY_PREFIX, REPLY_CTX, |r: &Reply| &r.node.key).map_err(|e| format!("reply {e}"))?;
    check_entry(&r.node).map_err(|e| format!("reply: {e}"))?;
    if r.v != 1 { return Err("reply is malformed".into()); }
    Ok(r)
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
    let now = now_millis();
    let members = node.members.read().unwrap().clone();
    let inv = Invite {
        v: 1, network: members.network.clone(), node: own_entry(node)?, relay: node.opts.relay.clone(), name: name.into(),
        from: (!from.is_empty()).then(|| from.into()), room: (!room.is_empty()).then(|| room.into()),
        iat: now, exp: now + ttl * 1000,
    };
    Ok(json!({ "invite": seal(INVITE_PREFIX, INVITE_CTX, &inv, node), "exp": islandmail_core::ts_from_millis(inv.exp) }))
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
    let reply = Reply { v: 1, network: network.clone(), node: mine, invite: raw.into(), iat: now_millis() };
    Ok(json!({
        "reply": seal(REPLY_PREFIX, REPLY_CTX, &reply, node), "network": network, "seq": list.seq,
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
    let inv = read_invite(&r.invite, now_millis()).map_err(|e| ApiError::new(400, e))?;
    let me_key = fmt_key(&node.seed.public());
    if inv.node.key != me_key {
        return Err(ApiError::new(400, "this reply answers another node's invite"));
    }
    if r.network != inv.network || r.node.key == me_key {
        return Err(ApiError::new(400, "reply does not match the invite"));
    }
    let name = inv.name.clone();
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
    fn tampered_and_expired_invites_are_refused() {
        let seed = islandmail_core::keys::Seed::generate();
        let inv = Invite {
            v: 1, network: b64u(&[7u8; 32]), relay: vec![], name: "bob".into(), from: None, room: None, iat: 1_000, exp: 10_000,
            node: NodeEntry { name: "a".into(), key: fmt_key(&seed.public()), addrs: vec![], names: vec!["alice".into()] },
        };
        let raw = serde_json::to_vec(&inv).unwrap();
        let sig = seed.sign(&[INVITE_CTX.as_bytes(), &raw].concat());
        let s = format!("{INVITE_PREFIX}{}.{}", b64u(&raw), b64u(&sig));
        assert!(read_invite(&s, 5_000).is_ok());
        assert!(read_invite(&s, 10_000).unwrap_err().contains("expired"));
        let mut bad = inv.clone();
        bad.name = "mallory".into();
        let t = format!("{INVITE_PREFIX}{}.{}", b64u(&serde_json::to_vec(&bad).unwrap()), b64u(&sig));
        assert!(read_invite(&t, 5_000).unwrap_err().contains("signature"));
    }
}
