//! Replication over iroh. One gossip topic carries every new envelope (and every newly adopted member list);
//! anti-entropy (a small request/response protocol on its own ALPN) runs with each member node on every gossip
//! NeighborUp and every `sync_secs`: exchange member lists (the newest operator-signed one wins), compare per-day hashes
//! of envelope-id sets, list ids of the days that differ, fetch the missing envelopes, then fetch attachment blobs
//! referenced by stored envelopes and not yet here, then ask for grants (the content key re-wrapped for this node) for
//! members-mode envelopes written before this node joined the list. Only member nodes may connect at all (an after-handshake hook
//! checks the current member list), since envelopes carry sender tokens.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, AfterHandshakeOutcome, Connection, EndpointHooks, WeakConnectionHandle};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;
use mailcore::keys::parse_key;
use mailcore::{Envelope, MemberList};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::node::{Node, Outbound};

pub const SYNC_ALPN: &[u8] = b"agent-mail/sync/1";
const MAX_GOSSIP: usize = 1 << 20;
const MAX_REQ: usize = 1 << 20;
const MAX_RESP: usize = 64 << 20;
const IDS_PER_GET: usize = 200;
/// A `get` answer stops adding envelopes past this many bytes (it always carries at least one), so it stays under
/// MAX_RESP even when every envelope is near the size limit (200 of those are ~110 MiB); the asker requests the rest.
const GET_BUDGET: usize = 32 << 20;
const GRANTS_PER_CALL: usize = 500;
/// Our own relay URLs from the config (set once at start).
static OWN_RELAYS: std::sync::OnceLock<Vec<RelayUrl>> = std::sync::OnceLock::new();

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Req {
    Days,
    Ids { days: Vec<String> },
    Get { ids: Vec<String> },
    Members,
    Blob { id: String },
    /// Content keys re-wrapped for the asking node, for members-mode envelopes it stored before it joined.
    Grants { ids: Vec<String> },
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Resp {
    #[serde(default)]
    days: BTreeMap<String, String>,
    #[serde(default)]
    ids: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    envelopes: Vec<String>,
    #[serde(default)]
    members: Option<MemberList>,
    #[serde(default)]
    blob: Option<String>,
    #[serde(default)]
    grants: BTreeMap<String, mailcore::envelope::Grant>,
    /// For `get`: how many of the requested ids this answer covers (the rest did not fit; ask again for them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    taken: Option<usize>,
}

/// Rejects every connection (both directions) from or to a key that is not a node on the current member list, and
/// keeps weak handles of the ones it accepts so a node removed from the list later loses them too (the check alone
/// runs only at the handshake: a removed node's open gossip connection would keep receiving every envelope).
#[derive(Debug, Clone)]
struct MemberGate {
    node: Arc<Node>,
    open: Arc<std::sync::Mutex<Vec<WeakConnectionHandle>>>,
}

impl MemberGate {
    /// Closes every open connection whose peer is no longer a node on the current list. Returns how many.
    fn close_removed(&self) -> usize {
        let members = self.node.members.read().unwrap().clone();
        let mut closed = 0;
        self.open.lock().unwrap().retain(|w| match w.upgrade() {
            None => false,
            Some(c) if members.is_node(c.remote_id().as_bytes()) => true,
            Some(c) => {
                tracing::warn!("closing connection to {}: no longer on the member list", c.remote_id().fmt_short());
                c.close(403u32.into(), b"removed from the member list");
                closed += 1;
                false
            }
        });
        closed
    }
}

impl EndpointHooks for MemberGate {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let id = conn.remote_id();
        if self.node.members.read().unwrap().is_node(id.as_bytes()) {
            let mut open = self.open.lock().unwrap();
            open.retain(|w| w.upgrade().is_some());
            open.push(conn.weak_handle());
            AfterHandshakeOutcome::accept()
        } else {
            tracing::warn!("refused connection from non-member {}", id.fmt_short());
            AfterHandshakeOutcome::Reject { error_code: 403u32.into(), reason: b"not a member node".to_vec() }
        }
    }
}

#[derive(Debug, Clone)]
struct SyncProto {
    node: Arc<Node>,
}

impl ProtocolHandler for SyncProto {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            let node = self.node.clone();
            let peer = *conn.remote_id().as_bytes();
            let req = recv.read_to_end(MAX_REQ).await.map_err(AcceptError::from_err)?;
            let resp = tokio::task::spawn_blocking(move || answer(&node, &peer, &req))
                .await
                .map_err(AcceptError::from_err)?
                .map_err(|e| AcceptError::from_boxed(e.into()))?;
            send.write_all(&resp).await.map_err(AcceptError::from_err)?;
            send.finish().map_err(AcceptError::from_err)?;
        }
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node")
    }
}

/// `peer`: the asking node's key (its iroh endpoint id is its Ed25519 node key).
fn answer(node: &Node, peer: &[u8; 32], req: &[u8]) -> Result<Vec<u8>> {
    let req: Req = serde_json::from_slice(req).context("bad sync request")?;
    let mut r = Resp::default();
    match req {
        Req::Days => r.days = node.store.day_hashes()?,
        Req::Ids { days } => {
            for d in days.into_iter().take(400) {
                let ids = node.store.ids_for_day(&d)?;
                r.ids.insert(d, ids);
            }
        }
        Req::Get { ids } => {
            let ids: Vec<String> = ids.into_iter().take(IDS_PER_GET).collect();
            let (envelopes, taken) = get_within(node, &ids, GET_BUDGET)?;
            r.envelopes = envelopes;
            r.taken = Some(taken);
        }
        Req::Members => r.members = Some(node.members.read().unwrap().clone()),
        Req::Blob { id } => r.blob = node.store.get_blob(&id)?.map(|b| mailcore::b64u(&b)),
        Req::Grants { ids } => {
            let ids: Vec<String> = ids.into_iter().take(GRANTS_PER_CALL).collect();
            r.grants = node.grants_for(&ids, peer)?;
        }
    }
    Ok(serde_json::to_vec(&r)?)
}

/// The stored envelopes among `ids`, in order, until `budget` bytes (at least one), and how many ids that covered.
fn get_within(node: &Node, ids: &[String], budget: usize) -> Result<(Vec<String>, usize)> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for (i, id) in ids.iter().enumerate() {
        if let Some(e) = node.store.envelopes(std::slice::from_ref(id))?.pop() {
            if !out.is_empty() && bytes + e.len() > budget {
                return Ok((out, i));
            }
            bytes += e.len();
            out.push(e);
        }
    }
    Ok((out, ids.len()))
}

async fn call(conn: &Connection, req: &Req) -> Result<Resp> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&serde_json::to_vec(req)?).await?;
    send.finish()?;
    let bytes = recv.read_to_end(MAX_RESP).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Kept alive for the node's lifetime (dropping the router stops accepting).
#[allow(dead_code)]
pub struct Net {
    pub endpoint: Endpoint,
    pub router: Router,
}

#[derive(Clone)]
struct Ctx {
    endpoint: Endpoint,
    node: Arc<Node>,
    lookup: MemoryLookup,
    sender: GossipSender,
    gate: MemberGate,
}

impl Ctx {
    fn peers(&self) -> Vec<EndpointId> {
        peers(&self.node, &self.lookup)
    }
}

/// Other member nodes, with their listed addresses added to the address book.
fn peers(node: &Node, lookup: &MemoryLookup) -> Vec<EndpointId> {
    {
        let me = node.seed.public();
        let members = node.members.read().unwrap().clone();
        let mut out = Vec::new();
        for n in &members.nodes {
            let Ok(key) = parse_key(&n.key) else { continue };
            if key == me {
                continue;
            }
            let Ok(id) = EndpointId::from_bytes(&key) else { continue };
            let mut a = EndpointAddr::new(id);
            let mut has_relay = false;
            for s in &n.addrs {
                if let Ok(sa) = s.parse::<SocketAddr>() {
                    a = a.with_ip_addr(sa);
                } else if let Ok(u) = s.parse::<RelayUrl>() {
                    a = a.with_relay_url(u);
                    has_relay = true;
                }
            }
            // A peer with no listed relay is assumed reachable through our own relay(s), so nodes find each other
            // without n0's address lookup.
            if !has_relay {
                for u in OWN_RELAYS.get().into_iter().flatten() {
                    a = a.with_relay_url(u.clone());
                }
            }
            lookup.add_endpoint_info(a);
            out.push(id);
        }
        out
    }
}

impl Ctx {
    async fn announce_members(&self) {
        self.gate.close_removed();
        let list = self.node.members.read().unwrap().clone();
        if let Ok(b) = serde_json::to_vec(&list) {
            let _ = self.sender.broadcast(Bytes::from(b)).await;
        }
        let _ = self.sender.join_peers(self.peers()).await;
    }

    /// Pulls everything `peer` has that we lack. Returns how many envelopes were new here.
    async fn sync_with(&self, peer: EndpointId) -> Result<usize> {
        let node = &self.node;
        let conn = self.endpoint.connect(EndpointAddr::new(peer), SYNC_ALPN).await?;
        if let Some(list) = call(&conn, &Req::Members).await?.members {
            match node.adopt_members(&list) {
                Ok(true) => self.announce_members().await,
                Ok(false) => {}
                Err(e) => tracing::warn!("member list from {} refused: {e:#}", peer.fmt_short()),
            }
        }
        let theirs = call(&conn, &Req::Days).await?.days;
        let n2 = node.clone();
        let mine = tokio::task::spawn_blocking(move || n2.store.day_hashes()).await??;
        let differ: Vec<String> = theirs.iter().filter(|(d, h)| mine.get(*d) != Some(*h)).map(|(d, _)| d.clone()).collect();
        let mut added = 0;
        for days in differ.chunks(100) {
            let ids = call(&conn, &Req::Ids { days: days.to_vec() }).await?.ids;
            // Day by day, oldest first, each day's envelopes in time order (imports by old number), so local numbers
            // follow time and imported history keeps its old numbers on a node catching up from empty.
            for day_ids in ids.into_values() {
                let mut missing = Vec::new();
                for id in day_ids {
                    if mailcore::envelope::is_id(&id) && !node.store.has(&id)? {
                        missing.push(id);
                    }
                }
                let mut envs = Vec::new();
                for chunk in missing.chunks(IDS_PER_GET) {
                    // A peer answers as many as fit in its byte budget and says how many ids it covered; ask for the rest.
                    let mut rest: &[String] = chunk;
                    while !rest.is_empty() {
                        let resp = call(&conn, &Req::Get { ids: rest.to_vec() }).await?;
                        for raw in resp.envelopes {
                            match serde_json::from_str::<Envelope>(&raw) {
                                Ok(e) => envs.push(e),
                                Err(e) => tracing::warn!("sync from {}: unreadable envelope: {e}", peer.fmt_short()),
                            }
                        }
                        match resp.taken {
                            Some(n) if n > 0 && n < rest.len() => rest = &rest[n..],
                            _ => break,
                        }
                    }
                }
                envs.sort_by(|a, b| {
                    let old = |e: &Envelope| match &e.attest {
                        mailcore::Attest::Import { old_id, .. } => *old_id,
                        _ => u64::MAX,
                    };
                    (old(a), &a.ts, &a.id).cmp(&(old(b), &b.ts, &b.id))
                });
                for e in envs {
                    match node.ingest(e) {
                        Ok(Some(_)) => added += 1,
                        Ok(None) => {}
                        Err(e) => tracing::warn!("sync from {}: refused an envelope: {e:#}", peer.fmt_short()),
                    }
                }
            }
        }
        // Attachments: blobs our envelopes name that we lack. The id is the hash, so any peer's copy will do.
        for id in node.store.missing_blobs()? {
            if let Some(b64) = call(&conn, &Req::Blob { id: id.clone() }).await?.blob {
                match mailcore::b64u_decode(&b64) {
                    Some(data) if blake3::hash(&data).to_hex().as_str() == id => {
                        node.store.put_blob(&id, &data, mailcore::now_millis())?;
                        tracing::info!("blob {} ({} bytes) from {}", &id[..12], data.len(), peer.fmt_short());
                    }
                    _ => tracing::warn!("blob {} from {} does not match its id", &id[..12], peer.fmt_short()),
                }
            }
        }
        // Members-mode mail written before this node joined was not wrapped for it: ask for grants.
        let unreadable = node.store.unreadable(GRANTS_PER_CALL)?;
        if !unreadable.is_empty() {
            let grants = call(&conn, &Req::Grants { ids: unreadable }).await?.grants;
            let mut opened = 0;
            for (id, g) in &grants {
                match node.apply_grant(id, g) {
                    Ok(true) => opened += 1,
                    Ok(false) => {}
                    Err(e) => tracing::warn!("grant for {} from {} refused: {e:#}", &id[..12.min(id.len())], peer.fmt_short()),
                }
            }
            if opened > 0 {
                tracing::info!("{} bodies opened with grants from {}", opened, peer.fmt_short());
            }
        }
        conn.close(0u32.into(), b"done");
        Ok(added)
    }
}

pub async fn start(cfg: &Config, node: Arc<Node>, mut outbound: mpsc::UnboundedReceiver<Outbound>) -> Result<Net> {
    let gate = MemberGate { node: node.clone(), open: Default::default() };
    let lookup = MemoryLookup::new();
    let entries = cfg.relay.entries();
    let mut own = Vec::new();
    let mut n0 = false;
    for e in &entries {
        match e.as_str() {
            "disabled" => {}
            "n0" => n0 = true,
            url if url.starts_with("http") => own.push(url.parse::<RelayUrl>().map_err(|err| anyhow!("relay url {url}: {err}"))?),
            other => return Err(anyhow!("relay entries are disabled, n0, or relay URLs, not {other}")),
        }
    }
    if entries.iter().any(|e| e == "disabled") && entries.len() > 1 {
        return Err(anyhow!("relay \"disabled\" cannot be combined with other entries"));
    }
    let _ = OWN_RELAYS.set(own.clone());
    let builder = match (own.is_empty(), n0) {
        (true, false) => Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled),
        (true, true) => Endpoint::builder(presets::N0),
        (false, with_n0) => {
            let map = RelayMap::from_iter(own.iter().cloned());
            if with_n0 {
                map.extend(&iroh::defaults::prod::default_relay_map());
            }
            let preset = if with_n0 { Endpoint::builder(presets::N0) } else { Endpoint::builder(presets::Minimal) };
            preset.relay_mode(RelayMode::Custom(map))
        }
    };
    tracing::info!("relays: {}", if entries.is_empty() { "disabled".to_string() } else { entries.join(", ") });
    let endpoint = builder
        .secret_key(SecretKey::from_bytes(node.seed.bytes()))
        .address_lookup(lookup.clone())
        .hooks(gate.clone())
        .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.iroh_port))?
        .bind()
        .await?;
    tracing::info!("iroh endpoint {} bound", endpoint.id());

    let gossip = Gossip::builder().max_message_size(MAX_GOSSIP).spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(SYNC_ALPN, SyncProto { node: node.clone() })
        .spawn();

    let topic = TopicId::from_bytes(node.members.read().unwrap().topic());
    let first = peers(&node, &lookup);
    let (sender, mut receiver) = gossip.subscribe(topic, first).await?.split();
    let ctx = Ctx { endpoint: endpoint.clone(), node: node.clone(), lookup, sender, gate };

    // Gossip in: envelopes and member lists; NeighborUp starts anti-entropy with that neighbor.
    let c = ctx.clone();
    tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => {
                    let v: serde_json::Value = match serde_json::from_slice(&msg.content) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("gossip: not JSON: {e}");
                            continue;
                        }
                    };
                    if v.get("operator").is_some() && v.get("nodes").is_some() {
                        match serde_json::from_value::<MemberList>(v).map_err(anyhow::Error::from).and_then(|l| c.node.adopt_members(&l)) {
                            Ok(true) => {
                                c.gate.close_removed();
                                let _ = c.sender.join_peers(c.peers()).await;
                            }
                            Ok(false) => {}
                            Err(e) => tracing::warn!("gossip: member list refused: {e:#}"),
                        }
                        continue;
                    }
                    match serde_json::from_value::<Envelope>(v).map_err(anyhow::Error::from).and_then(|e| c.node.ingest(e)) {
                        Ok(Some(r)) => {
                            tracing::info!("gossip: stored #{} {}", r.id, &r.env_id[..12]);
                            // Its attachments come by anti-entropy from whoever delivered it.
                            let env_blobs = c.node.store.missing_blobs().map(|m| !m.is_empty()).unwrap_or(false);
                            if env_blobs {
                                let (c2, from) = (c.clone(), msg.delivered_from);
                                tokio::spawn(async move {
                                    if let Err(e) = c2.sync_with(from).await {
                                        tracing::info!("blob fetch from {} failed: {e:#}", from.fmt_short());
                                    }
                                });
                            }
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!("gossip: refused an envelope: {e:#}"),
                    }
                }
                Ok(Event::NeighborUp(peer)) => {
                    tracing::info!("gossip neighbor up {}", peer.fmt_short());
                    let c2 = c.clone();
                    tokio::spawn(async move {
                        match c2.sync_with(peer).await {
                            Ok(k) => tracing::info!("sync with {}: {k} new", peer.fmt_short()),
                            Err(e) => tracing::info!("sync with {} failed: {e:#}", peer.fmt_short()),
                        }
                    });
                }
                Ok(Event::NeighborDown(peer)) => tracing::info!("gossip neighbor down {}", peer.fmt_short()),
                Ok(Event::Lagged) => tracing::warn!("gossip receiver lagged; anti-entropy will fill the gap"),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("gossip receive error: {e}");
                    break;
                }
            }
        }
    });

    // Gossip out: every envelope this node writes, and member lists it adopts.
    let c = ctx.clone();
    tokio::spawn(async move {
        while let Some(out) = outbound.recv().await {
            let Outbound::Envelope(env) = &out;
            let Ok(bytes) = serde_json::to_vec(env) else { continue };
            if bytes.len() > MAX_GOSSIP {
                continue; // anti-entropy carries it
            }
            if let Err(e) = c.sender.broadcast(Bytes::from(bytes)).await {
                tracing::warn!("gossip broadcast failed (anti-entropy will carry it): {e}");
            }
        }
    });

    // Every sync_secs: pick up a newer member list from the config file, anti-entropy with every member node, and
    // re-join the topic so a restarted or new peer is found again.
    let c = ctx.clone();
    let every = Duration::from_secs(cfg.sync_secs.max(1));
    let cfg2 = cfg.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(file) = cfg2.members() {
                match c.node.adopt_members(&file) {
                    Ok(true) => c.announce_members().await,
                    Ok(false) => {}
                    Err(e) => tracing::warn!("member list file refused: {e:#}"),
                }
            }
            let peers = c.peers();
            for &peer in &peers {
                match tokio::time::timeout(Duration::from_secs(120), c.sync_with(peer)).await {
                    Ok(Ok(k)) if k > 0 => tracing::info!("periodic sync with {}: {k} new", peer.fmt_short()),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("periodic sync with {} failed: {e:#}", peer.fmt_short()),
                    Err(_) => tracing::debug!("periodic sync with {} timed out", peer.fmt_short()),
                }
            }
            let _ = c.sender.join_peers(peers).await;
            tokio::time::sleep(every).await;
        }
    });

    Ok(Net { endpoint, router })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Node, Opts};
    use crate::store::Store;
    use mailcore::envelope::Draft;
    use mailcore::keys::{fmt_key, Seed};
    use mailcore::{Attest, Body, Mode, NodeEntry, TokenPolicy, Verified};

    #[test]
    fn get_answers_stay_within_the_byte_budget() {
        let (op, home, me) = (Seed::generate(), Seed::generate(), Seed::generate());
        let mut list = MemberList {
            v: 1,
            network: "t".into(),
            seq: 1,
            issued: mailcore::now_ts(),
            operator: String::new(),
            members: vec![],
            nodes: vec![NodeEntry { name: "n".into(), key: fmt_key(&me.public()), addrs: vec![] }],
            bridges: vec![],
            sig: String::new(),
        };
        list.sign(&op);
        let policy = TokenPolicy { home_key: home.public(), iss: "h".into(), aud: "mail".into(), scope: "mail:use".into() };
        let path = std::env::temp_dir().join(format!("mailnode-net-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let (tx, _rx) = mpsc::unbounded_channel();
        let recipients = list.all_keys();
        let node = Node::new(Store::open(&path).unwrap(), list, op.public(), policy, me, Opts::default(), tx);
        let v = Verified { sender_sub: "s".into(), sender_kind: String::new(), imported: None, verified: true, attest: "token" };
        let mut ids = Vec::new();
        for i in 0..5 {
            let body = Body { text: format!("{i}").repeat(10_000), ..Default::default() };
            let e = Envelope::seal(
                Draft {
                    thread: "t",
                    parents: vec![],
                    ts: mailcore::now_ts(),
                    from: "a.x",
                    to: "all",
                    mode: Mode::Members,
                    body: &body,
                    blobs: vec![],
                    attest: Attest::Aid1 { token: "aid1.x.y".into() },
                    recipients: &recipients,
                },
                &node.seed,
            )
            .unwrap();
            node.store.insert(&e, &v, Some("x"), "[]", None, 0, 1).unwrap().unwrap();
            ids.push(e.id);
        }
        ids.insert(2, "0".repeat(64)); // one id the peer does not have
        let one = node.store.envelopes(&ids[..1]).unwrap()[0].len();
        // Room for two envelopes: the answer covers the first three ids (the missing one is skipped and counted), and
        // the asker continues from the fourth.
        let (got, taken) = get_within(&node, &ids, one * 2 + 10).unwrap();
        assert_eq!((got.len(), taken), (2, 3));
        let (got, taken) = get_within(&node, &ids[3..], one * 2 + 10).unwrap();
        assert_eq!((got.len(), taken), (2, 2));
        let (got, taken) = get_within(&node, &ids[5..], one * 2 + 10).unwrap();
        assert_eq!((got.len(), taken), (1, 1));
        // Budget smaller than one envelope: still one per answer, so the asker always progresses.
        let (got, taken) = get_within(&node, &ids, 1).unwrap();
        assert_eq!((got.len(), taken), (1, 1));
        let (got, taken) = get_within(&node, &ids, usize::MAX).unwrap();
        assert_eq!((got.len(), taken), (5, 6));
        let _ = std::fs::remove_file(path);
    }
}
