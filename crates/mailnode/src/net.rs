//! Replication over iroh. One gossip topic carries every new envelope; anti-entropy (a small request/response
//! protocol on its own ALPN) runs with each member node on every gossip NeighborUp and every `sync_secs`: compare
//! per-day hashes of envelope-id sets, list ids of the days that differ, fetch the missing envelopes. Only member nodes
//! may connect at all (an after-handshake hook on the endpoint), since envelopes carry sender tokens.

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, AfterHandshakeOutcome, Connection, EndpointHooks};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use iroh_gossip::api::Event;
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;
use mailcore::keys::parse_key;
use mailcore::Envelope;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::node::Node;

pub const SYNC_ALPN: &[u8] = b"agent-mail/sync/1";
const MAX_GOSSIP: usize = 1 << 20;
const MAX_REQ: usize = 1 << 20;
const MAX_RESP: usize = 64 << 20;
const IDS_PER_GET: usize = 200;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Req {
    Days,
    Ids { days: Vec<String> },
    Get { ids: Vec<String> },
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Resp {
    #[serde(default)]
    days: BTreeMap<String, String>,
    #[serde(default)]
    ids: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    envelopes: Vec<String>,
}

/// Rejects every connection (both directions) from or to a key that is not a member node.
#[derive(Debug, Clone)]
struct MemberGate {
    allowed: Arc<RwLock<HashSet<[u8; 32]>>>,
}

impl EndpointHooks for MemberGate {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let id = conn.remote_id();
        if self.allowed.read().unwrap().contains(id.as_bytes()) {
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
            let req = recv.read_to_end(MAX_REQ).await.map_err(AcceptError::from_err)?;
            let resp = tokio::task::spawn_blocking(move || answer(&node, &req))
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

fn answer(node: &Node, req: &[u8]) -> Result<Vec<u8>> {
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
            r.envelopes = node.store.envelopes(&ids)?;
        }
    }
    Ok(serde_json::to_vec(&r)?)
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

/// Pulls everything `peer` has that we lack. Returns how many envelopes were new here.
async fn sync_with(endpoint: &Endpoint, node: &Arc<Node>, peer: EndpointId) -> Result<usize> {
    let conn = endpoint.connect(EndpointAddr::new(peer), SYNC_ALPN).await?;
    let theirs = call(&conn, &Req::Days).await?.days;
    let n2 = node.clone();
    let mine = tokio::task::spawn_blocking(move || n2.store.day_hashes()).await??;
    let differ: Vec<String> = theirs.iter().filter(|(d, h)| mine.get(*d) != Some(*h)).map(|(d, _)| d.clone()).collect();
    let mut added = 0;
    for days in differ.chunks(100) {
        let ids = call(&conn, &Req::Ids { days: days.to_vec() }).await?.ids;
        let mut missing = Vec::new();
        for id in ids.into_values().flatten() {
            if mailcore::envelope::is_id(&id) && !node.store.has(&id)? {
                missing.push(id);
            }
        }
        for chunk in missing.chunks(IDS_PER_GET) {
            let envs = call(&conn, &Req::Get { ids: chunk.to_vec() }).await?.envelopes;
            for raw in envs {
                match serde_json::from_str::<Envelope>(&raw).map_err(anyhow::Error::from).and_then(|e| node.ingest(e)) {
                    Ok(Some(_)) => added += 1,
                    Ok(None) => {}
                    Err(e) => tracing::warn!("sync from {}: refused an envelope: {e:#}", peer.fmt_short()),
                }
            }
        }
    }
    conn.close(0u32.into(), b"done");
    Ok(added)
}

pub async fn start(cfg: &Config, node: Arc<Node>, mut outbound: mpsc::UnboundedReceiver<Envelope>) -> Result<Net> {
    let members = node.members.read().unwrap().clone();
    let me = node.seed.public();
    let allowed: HashSet<[u8; 32]> = members.node_keys().into_iter().collect();
    let gate = MemberGate { allowed: Arc::new(RwLock::new(allowed)) };

    let lookup = MemoryLookup::new();
    let mut peers = Vec::new();
    for n in &members.nodes {
        let key = parse_key(&n.key)?;
        if key == me {
            continue;
        }
        let id = EndpointId::from_bytes(&key).map_err(|e| anyhow!("node key {}: {e}", n.name))?;
        let mut a = EndpointAddr::new(id);
        for s in &n.addrs {
            let sa: SocketAddr = s.parse().with_context(|| format!("address {s} of node {}", n.name))?;
            a = a.with_ip_addr(sa);
        }
        lookup.add_endpoint_info(a);
        peers.push(id);
    }

    let builder = match cfg.relay.as_str() {
        "disabled" => Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled),
        "n0" => Endpoint::builder(presets::N0),
        other => return Err(anyhow!("relay must be disabled or n0, not {other}")),
    };
    let endpoint = builder
        .secret_key(SecretKey::from_bytes(node.seed.bytes()))
        .address_lookup(lookup.clone())
        .hooks(gate)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.iroh_port))?
        .bind()
        .await?;
    tracing::info!("iroh endpoint {} bound", endpoint.id());

    let gossip = Gossip::builder().max_message_size(MAX_GOSSIP).spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(SYNC_ALPN, SyncProto { node: node.clone() })
        .spawn();

    let topic = TopicId::from_bytes(members.topic());
    let (sender, mut receiver) = gossip.subscribe(topic, peers.clone()).await?.split();

    // Gossip in: envelopes, and NeighborUp starts anti-entropy with that neighbor.
    let (ep, n) = (endpoint.clone(), node.clone());
    tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => match serde_json::from_slice::<Envelope>(&msg.content) {
                    Ok(env) => match n.ingest(env) {
                        Ok(Some(r)) => tracing::info!("gossip: stored #{} {}", r.id, &r.env_id[..12]),
                        Ok(None) => {}
                        Err(e) => tracing::warn!("gossip: refused an envelope: {e:#}"),
                    },
                    Err(e) => tracing::warn!("gossip: not an envelope: {e}"),
                },
                Ok(Event::NeighborUp(peer)) => {
                    tracing::info!("gossip neighbor up {}", peer.fmt_short());
                    let (ep, n) = (ep.clone(), n.clone());
                    tokio::spawn(async move {
                        match sync_with(&ep, &n, peer).await {
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

    // Gossip out: every envelope this node writes.
    let s2 = sender.clone();
    tokio::spawn(async move {
        while let Some(env) = outbound.recv().await {
            let bytes = match serde_json::to_vec(&env) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if bytes.len() > MAX_GOSSIP {
                continue; // anti-entropy carries it
            }
            if let Err(e) = s2.broadcast(Bytes::from(bytes)).await {
                tracing::warn!("gossip broadcast failed (anti-entropy will carry it): {e}");
            }
        }
    });

    // Anti-entropy on a timer with every member node, and re-joining the topic so a restarted peer is found again.
    let (ep, n) = (endpoint.clone(), node.clone());
    let every = Duration::from_secs(cfg.sync_secs.max(1));
    tokio::spawn(async move {
        loop {
            for &peer in &peers {
                match tokio::time::timeout(Duration::from_secs(60), sync_with(&ep, &n, peer)).await {
                    Ok(Ok(k)) if k > 0 => tracing::info!("periodic sync with {}: {k} new", peer.fmt_short()),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("periodic sync with {} failed: {e:#}", peer.fmt_short()),
                    Err(_) => tracing::debug!("periodic sync with {} timed out", peer.fmt_short()),
                }
            }
            let _ = sender.join_peers(peers.clone()).await;
            tokio::time::sleep(every).await;
        }
    });

    Ok(Net { endpoint, router })
}
