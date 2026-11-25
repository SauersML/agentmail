//! Replication over iroh. One gossip topic carries every new envelope (and every newly adopted member list);
//! anti-entropy (a small request/response protocol on its own ALPN) runs with each member node every
//! `sync_secs`: compare per-day hashes
//! of envelope-id sets, list ids of the days that differ, fetch the missing envelopes, then fetch attachment blobs
//! referenced by stored envelopes and not yet here, then ask for grants (the content key re-wrapped for this node) for
//! members-mode envelopes written before this node joined the list. Only member nodes may connect at all (an after-handshake hook
//! checks the current member list), to protect network membership and traffic metadata.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, AfterHandshakeOutcome, Connection, EndpointHooks, WeakConnectionHandle};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;
use mailcore::keys::parse_key;
use mailcore::Envelope;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::node::Node;

pub const SYNC_ALPN: &[u8] = b"agent-mail/sync/3";
const MAX_GOSSIP: usize = 1 << 20;
const MAX_REQ: usize = 1 << 20;
const MAX_RESP: usize = 64 << 20;
const IDS_PER_GET: usize = 200;
/// A `get` answer stops adding envelopes past this many bytes (it always carries at least one), so it stays under
/// MAX_RESP even when every envelope is near the size limit (200 of those are ~110 MiB); the asker requests the rest.
const GET_BUDGET: usize = 32 << 20;
const GRANTS_PER_CALL: usize = 500;
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Req {
    Days,
    Ids { day: String, after: String },
    Get { ids: Vec<String> },
    Blob { id: String },
    /// Content keys re-wrapped for the asking node, for members-mode envelopes it stored before it joined.
    Grants { ids: Vec<String> },
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Resp {
    #[serde(default)]
    days: BTreeMap<String, String>,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    envelopes: Vec<String>,
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
            // Membership is checked at the handshake; a node taken off a newer member list must also lose a
            // connection it already had, so check again on every request.
            if !node.members.read().unwrap().is_node(&peer) {
                tracing::warn!("closing sync connection of {}: no longer a member node", conn.remote_id().fmt_short());
                conn.close(403u32.into(), b"not a member node");
                return Ok(());
            }
            let req = tokio::time::timeout(Duration::from_secs(30), recv.read_to_end(MAX_REQ)).await
                .map_err(AcceptError::from_err)?.map_err(AcceptError::from_err)?;
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
    anyhow::ensure!(node.members.read().unwrap().is_node(peer), "peer removed from membership");
    let (network, req): (String, Req) = serde_json::from_slice(req).context("bad sync request")?;
    anyhow::ensure!(network == node.members.read().unwrap().network, "different network");
    let mut r = Resp::default();
    match req {
        Req::Days => r.days = node.store.day_hashes()?,
        Req::Ids { day, after } => r.ids = node.store.ids_for_day(&day, &after, IDS_PER_GET)?,
        Req::Get { ids } => {
            let ids: Vec<String> = ids.into_iter().take(IDS_PER_GET).collect();
            let (envelopes, taken) = get_within(node, &ids, GET_BUDGET)?;
            r.envelopes = envelopes;
            r.taken = Some(taken);
        }
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

async fn call(conn: &Connection, network: &str, req: &Req) -> Result<Resp> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&serde_json::to_vec(&(network, req))?).await?;
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
            for addr in &n.addrs {
                if let Ok(sa) = addr.parse::<SocketAddr>() {
                    a = a.with_ip_addr(sa);
                }
            }
            lookup.add_endpoint_info(a);
            out.push(id);
        }
        out
    }
}

impl Ctx {
    /// Pulls everything `peer` has that we lack. Returns how many envelopes were new here.
    async fn sync_with(&self, peer: EndpointId) -> Result<usize> {
        let node = &self.node;
        let conn = self.endpoint.connect(EndpointAddr::new(peer), SYNC_ALPN).await?;
        let network = node.members.read().unwrap().network.clone();
        let theirs = call(&conn, &network, &Req::Days).await?.days;
        let n2 = node.clone();
        let mine = tokio::task::spawn_blocking(move || n2.store.day_hashes()).await??;
        let differ: Vec<String> = theirs.iter().filter(|(d, h)| mine.get(*d) != Some(*h)).map(|(d, _)| d.clone()).collect();
        let mut added = 0;
        for day in differ {
            let mut after = String::new();
            loop {
                let page = call(&conn, &network, &Req::Ids { day: day.clone(), after: after.clone() }).await?.ids;
                anyhow::ensure!(page.len() <= IDS_PER_GET, "oversize id page");
                let mut missing = Vec::new();
                for id in &page {
                    anyhow::ensure!(mailcore::envelope::is_id(id) && id > &after, "invalid peer id page");
                    after.clone_from(id);
                    if !node.store.has(id)? {
                        missing.push(id.clone());
                    }
                }
                let mut rest = missing.as_slice();
                while !rest.is_empty() {
                    let resp = call(&conn, &network, &Req::Get { ids: rest.to_vec() }).await?;
                    let taken = resp.taken.context("missing envelope count")?;
                    anyhow::ensure!((1..=rest.len()).contains(&taken) && resp.envelopes.len() <= taken,
                                    "invalid envelope count");
                    for raw in resp.envelopes {
                        let env: Envelope = serde_json::from_str(&raw)?;
                        anyhow::ensure!(rest[..taken].contains(&env.id), "unsolicited envelope");
                        match node.ingest(env) {
                            Ok(Some(_)) => added += 1,
                            Ok(None) => {}
                            Err(e) => tracing::warn!("sync from {}: refused an envelope: {e:#}", peer.fmt_short()),
                        }
                    }
                    rest = &rest[taken..];
                }
                if page.len() < IDS_PER_GET {
                    break;
                }
            }
        }
        // Attachments: blobs our envelopes name that we lack. The id is the hash, so any peer's copy will do.
        for id in node.store.missing_blobs()? {
            if let Some(b64) = call(&conn, &network, &Req::Blob { id: id.clone() }).await?.blob {
                match mailcore::b64u_decode(&b64) {
                    Some(data) if (40..=crate::node::MAX_FILE + 40).contains(&data.len()) && blake3::hash(&data).to_hex().as_str() == id => {
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
            let grants = call(&conn, &network, &Req::Grants { ids: unreadable.clone() }).await?.grants;
            let mut opened = 0;
            for (id, g) in &grants {
                anyhow::ensure!(unreadable.contains(id), "unsolicited key grant");
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

pub async fn start(cfg: &Config, node: Arc<Node>, mut outbound: mpsc::Receiver<Envelope>) -> Result<Net> {
    let gate = MemberGate { node: node.clone(), open: Default::default() };
    let lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
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

    // Gossip delivers envelopes between periodic syncs.
    let c = ctx.clone();
    tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => {
                    match serde_json::from_slice::<Envelope>(&msg.content).map_err(anyhow::Error::from).and_then(|e| c.node.ingest(e)) {
                        Ok(Some(r)) => {
                            tracing::info!("gossip: stored #{} {}", r.id, &r.env_id[..12]);
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!("gossip: refused an envelope: {e:#}"),
                    }
                }
                Ok(Event::NeighborUp(peer)) => {
                    tracing::info!("gossip neighbor up {}", peer.fmt_short());
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
        while let Some(env) = outbound.recv().await {
            let Ok(bytes) = serde_json::to_vec(&env) else { continue };
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
            match cfg2.members().and_then(|list| c.node.reload_members(&list)) {
                Ok(true) => { c.gate.close_removed(); }
                Ok(false) => {}
                Err(e) => tracing::warn!("local trust file refused: {e:#}"),
            }
            let peers = c.peers();
            futures::stream::iter(peers.iter().copied()).for_each_concurrent(4, |peer| {
                let c = &c;
                async move {
                    match tokio::time::timeout(Duration::from_secs(120), c.sync_with(peer)).await {
                    Ok(Ok(k)) if k > 0 => tracing::info!("periodic sync with {}: {k} new", peer.fmt_short()),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("periodic sync with {} failed: {e:#}", peer.fmt_short()),
                    Err(_) => tracing::debug!("periodic sync with {} timed out", peer.fmt_short()),
                    }
                }
            }).await;
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
    use mailcore::{Attest, Body, Mode, NodeEntry, Verified};

    #[test]
    fn get_answers_stay_within_the_byte_budget() {
        let me = Seed::generate();
        let list = mailcore::MemberList {
            v: 2,
            network: mailcore::b64u(&mailcore::random_bytes::<32>()),
            seq: 1,
            members: vec![],
            nodes: vec![NodeEntry { name: "n".into(), key: fmt_key(&me.public()), addrs: vec![] }],
        };
        let path = std::env::temp_dir().join(format!("mailnode-net-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let (tx, _rx) = mpsc::channel(32);
        let recipients = list.all_keys();
        let node = Node::new(Store::open(&path).unwrap(), list, me, Opts::default(), tx);
        let v = Verified { sender_sub: "s".into() };
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
                    attest: Attest::Agent { key: fmt_key(&node.seed.public()), digest: String::new(), sig: i.to_string() },
                    recipients: &recipients,
                },
                &node.seed,
            )
            .unwrap();
            node.store.insert(&e, &v, Some("x"), "[]", None, 0).unwrap().unwrap();
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
