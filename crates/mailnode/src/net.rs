//! Authenticated direct-peer replication. Gossip announces envelopes and periodic sync reconciles
//! envelope IDs and referenced attachment blobs between locally trusted peers.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, WeakConnectionHandle};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;
use mailcore::keys::parse_key;
use mailcore::Envelope;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::config::Config;
use crate::node::Node;

pub const SYNC_ALPN: &[u8] = b"agent-mail/sync/4";
const MAX_GOSSIP: usize = 1 << 20;
const MAX_REQ: usize = 1 << 20;
const MAX_RESP: usize = 64 << 20;
const IDS_PER_GET: usize = 200;
/// A `get` answer stops adding envelopes past this many bytes (it always carries at least one), so it stays under
/// MAX_RESP even when every envelope is near the size limit (200 of those are ~110 MiB); the asker requests the rest.
const GET_BUDGET: usize = 32 << 20;
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Req {
    Days,
    Ids { day: String, after: String },
    Get { ids: Vec<String> },
    Blob { id: String },
    /// Every certificate and revocation the peer holds (synced before envelopes, which may need them).
    Certs,
    CertsFor { issuer: String },
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    certs: Vec<mailcore::Cert>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revocations: Vec<mailcore::Revocation>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    more_trust: bool,
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
    async fn before_connect<'a>(&'a self, addr: &'a EndpointAddr, _alpn: &'a [u8]) -> BeforeConnectOutcome {
        if self.node.members.read().unwrap().is_node(addr.id.as_bytes()) {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let id = conn.remote_id();
        let members = self.node.members.read().unwrap();
        if members.is_node(id.as_bytes()) {
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
        Req::Certs => (r.certs, r.revocations, r.more_trust) = node.store.sync_trust(None, crate::store::MAX_SYNC_CERTS)?,
        Req::CertsFor { issuer } => {
            (r.certs, r.revocations, r.more_trust) = node.store.sync_trust(Some(&issuer), crate::store::MAX_CERTS_PER_NODE as usize)?;
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
    relays: Vec<RelayUrl>,
    sender: GossipSender,
    gate: MemberGate,
}

impl Ctx {
    fn peers(&self) -> Vec<EndpointId> {
        peers(&self.node, &self.lookup, &self.relays)
    }
}

/// Other member nodes, with their listed addresses added to the address book.
fn peers(node: &Node, lookup: &MemoryLookup, relays: &[RelayUrl]) -> Vec<EndpointId> {
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
            for url in relays {
                a = a.with_relay_url(url.clone());
            }
            lookup.set_endpoint_info(a);
            out.push(id);
        }
        out
    }
}

impl Ctx {
    async fn apply_trust(&self, trust: Resp, limit: usize) -> Result<()> {
        anyhow::ensure!(trust.certs.len() <= limit && trust.revocations.len() <= limit, "oversize certificate list");
        let node = self.node.clone();
        tokio::task::spawn_blocking(move || {
            for r in &trust.revocations {
                if let Err(e) = node.take_revocation(r) { tracing::debug!("sync: refused a revocation: {e:#}"); }
            }
            for c in &trust.certs {
                if let Err(e) = node.take_cert(c) { tracing::debug!("sync: refused a certificate: {e:#}"); }
            }
        }).await?;
        Ok(())
    }

    /// Pulls everything `peer` has that we lack. Returns how many envelopes were new here.
    async fn sync_with(&self, peer: EndpointId) -> Result<usize> {
        let node = &self.node;
        let conn = self.endpoint.connect(EndpointAddr::new(peer), SYNC_ALPN).await?;
        let network = node.members.read().unwrap().network.clone();
        let trust = call(&conn, &network, &Req::Certs).await?;
        if trust.more_trust {
            // Only a peer advertising a truncated list receives this optional sync-v4 request.
            let issuers = node.members.read().unwrap().node_keys();
            for key in issuers {
                let issuer = mailcore::keys::fmt_key(&key);
                let page = call(&conn, &network, &Req::CertsFor { issuer: issuer.clone() }).await?;
                anyhow::ensure!(!page.more_trust && page.certs.iter().all(|c| c.node == issuer)
                    && page.revocations.iter().all(|r| r.node == issuer), "invalid issuer trust response");
                self.apply_trust(page, crate::store::MAX_CERTS_PER_NODE as usize).await?;
            }
        } else {
            self.apply_trust(trust, crate::store::MAX_SYNC_CERTS).await?;
        }
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
        // Attachments: blobs our envelopes name that we lack. The id is the hash, so any peer can supply a copy.
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
        conn.close(0u32.into(), b"done");
        Ok(added)
    }
}

/// How often the trust file is checked for changes.
pub const TRUST_POLL: Duration = Duration::from_secs(1);

/// Re-reads the trust file every TRUST_POLL and adopts a change (Node::reload_members wakes open sessions);
/// `adopted` runs after each adopted change.
pub async fn watch_trust_file(cfg: Config, node: Arc<Node>, adopted: impl Fn()) {
    let mut last: Option<Vec<u8>> = None;
    let mut tick = tokio::time::interval(TRUST_POLL);
    loop {
        tick.tick().await;
        let raw = match std::fs::read(&cfg.members_file) {
            Ok(raw) => raw,
            Err(e) => {
                tracing::warn!("reading {}: {e}", cfg.members_file.display());
                continue;
            }
        };
        if last.as_ref() == Some(&raw) {
            continue;
        }
        match Config::parse_members(&raw).and_then(|list| node.reload_members(&list)) {
            Ok(true) => adopted(),
            Ok(false) => {}
            Err(e) => {
                tracing::warn!("local trust file refused: {e:#}");
                // A temporary database failure can clear while the file stays the same.
                if e.downcast_ref::<rusqlite::Error>().is_some() { continue; }
            }
        }
        last = Some(raw);
    }
}

/// A gossiped certificate ({"cert": …}) or revocation ({"revocation": …}); None for anything else (an envelope).
fn trust_message(node: &Node, raw: &[u8]) -> Option<Result<bool>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Msg { cert: Option<mailcore::Cert>, revocation: Option<mailcore::Revocation> }
    let m: Msg = serde_json::from_slice(raw).ok()?;
    match (m.cert, m.revocation) {
        (Some(c), None) => Some(node.take_cert(&c)),
        (None, Some(r)) => Some(node.take_revocation(&r)),
        _ => None,
    }
}

fn relay_mode(entries: &[String]) -> Result<RelayMode> {
    if entries.is_empty() { return Ok(RelayMode::Disabled); }
    if entries == ["n0"] { return Ok(RelayMode::Default); }
    let map = RelayMap::empty();
    for entry in entries {
        if entry == "n0" {
            map.extend(&RelayMode::Default.relay_map());
        } else {
            let url: RelayUrl = entry.parse().context("invalid relay URL")?;
            anyhow::ensure!(matches!(url.scheme(), "http" | "https") && url.host().is_some()
                && url.username().is_empty() && url.password().is_none()
                && url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
                "relay must be n0 or an HTTP(S) origin without credentials");
            map.insert(url.clone(), Arc::new(url.into()));
        }
    }
    Ok(RelayMode::Custom(map))
}

pub async fn start(cfg: &Config, node: Arc<Node>, outbound: mpsc::Receiver<Envelope>) -> Result<Net> {
    let builder = Endpoint::builder(presets::Minimal)
        .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.iroh_port))?;
    start_with(builder, cfg, node, outbound).await
}

async fn start_with(builder: iroh::endpoint::Builder, cfg: &Config, node: Arc<Node>, mut outbound: mpsc::Receiver<Envelope>) -> Result<Net> {
    let gate = MemberGate { node: node.clone(), open: Default::default() };
    let lookup = MemoryLookup::new();
    let mode = relay_mode(&cfg.relay)?;
    let relays = mode.relay_map().urls::<Vec<_>>();
    let endpoint = builder
        .relay_mode(mode)
        .secret_key(SecretKey::from_bytes(node.seed.bytes()))
        .hooks(gate.clone())
        .bind()
        .await?;
    tracing::info!("iroh endpoint {} bound", endpoint.id());

    let gossip = Gossip::builder().max_message_size(MAX_GOSSIP).spawn(endpoint.clone());
    // Gossip installs a lookup that accepts relay hints from other peers. Keep dialing under local policy.
    let services = endpoint.address_lookup()?;
    services.clear();
    services.add(lookup.clone());
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(SYNC_ALPN, SyncProto { node: node.clone() })
        .spawn();

    let topic = TopicId::from_bytes(node.members.read().unwrap().topic());
    let first = peers(&node, &lookup, &relays);
    let (sender, mut receiver) = gossip.subscribe(topic, first).await?.split();
    let ctx = Ctx { endpoint: endpoint.clone(), node: node.clone(), lookup, relays, sender, gate };

    // Gossip delivers envelopes between periodic syncs.
    let c = ctx.clone();
    tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => {
                    if let Some(r) = trust_message(&c.node, &msg.content) {
                        match r {
                            Ok(true) => tracing::info!("gossip: new certificate or revocation"),
                            Ok(false) => {}
                            Err(e) => tracing::warn!("gossip: refused a certificate or revocation: {e:#}"),
                        }
                        continue;
                    }
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
                Ok(Event::Lagged) => tracing::warn!("gossip receiver lagged; anti-entropy fills the gap"),
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
                tracing::warn!("gossip broadcast failed (anti-entropy carries it): {e}");
            }
        }
    });

    // Certificates and revocations this node signs.
    let c = ctx.clone();
    let mut trust_out = node.trust_out.subscribe();
    tokio::spawn(async move {
        loop {
            match trust_out.recv().await {
                Ok(msg) => {
                    if let Err(e) = c.sender.broadcast(Bytes::from(msg)).await {
                        tracing::warn!("gossip broadcast failed (anti-entropy carries it): {e}");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // The local trust file, on its own timer: a slow or offline peer never delays a change (a removed agent or
    // node), and open sessions and connections are cut off as soon as it is adopted.
    let gate = ctx.gate.clone();
    tokio::spawn(watch_trust_file(cfg.clone(), node.clone(), move || { gate.close_removed(); }));

    // Every sync_secs: anti-entropy with every member node, and re-join the topic so a restarted or new peer is
    // found again.
    let c = ctx.clone();
    let every = Duration::from_secs(cfg.sync_secs.max(1));
    tokio::spawn(async move {
        loop {
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
    fn relay_selection_is_opt_in() {
        assert_eq!(relay_mode(&[]).unwrap(), RelayMode::Disabled);
        assert_eq!(relay_mode(&["n0".into()]).unwrap(), RelayMode::Default);
        let custom = "https://relay.example.org";
        let url = custom.parse::<RelayUrl>().unwrap();
        let only = relay_mode(&[custom.into()]).unwrap().relay_map();
        assert_eq!(only.urls::<Vec<_>>(), vec![url.clone()]);
        let mixed = relay_mode(&["n0".into(), custom.into()]).unwrap().relay_map();
        assert!(mixed.contains(&url));
        assert_eq!(mixed.len(), RelayMode::Default.relay_map().len() + 1);
        for bad in ["", "garbage", "file:///tmp", "https://user:pass@relay.test", "https://relay.test/?secret"] {
            assert!(relay_mode(&[bad.into()]).is_err());
        }
    }

    #[tokio::test]
    async fn pinned_nodes_sync_over_a_relay_without_udp() -> Result<()> {
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};
        let mut server = ServerConfig::default();
        server.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
        let relay = Server::spawn(server).await?;
        let url = format!("http://{}", relay.http_addr().unwrap());
        let dir = std::env::temp_dir().join(format!("mailnode-relay-{}", mailcore::b64u(&mailcore::random_bytes::<9>())));
        std::fs::create_dir(&dir)?;
        let file = dir.join("members.json");
        let keys = [Seed::generate(), Seed::generate()];
        let agents = [Seed::generate(), Seed::generate()];
        let network = mailcore::b64u(&mailcore::random_bytes::<32>());
        let list = mailcore::MemberList {
            v: 2, network: network.clone(), seq: 1,
            members: vec![mailcore::Member { name: "a1".into(), sub: "agent:a1".into(), key: fmt_key(&agents[1].public()) }],
            nodes: keys.iter().enumerate().map(|(i, key)| NodeEntry {
                name: format!("n{i}"), key: fmt_key(&key.public()), addrs: vec![], names: vec![format!("a{i}")]
            }).collect(),
        };
        std::fs::write(&file, serde_json::to_vec(&list)?)?;
        let cfg = serde_json::from_value(serde_json::json!({
            "data_dir": dir, "members_file": file, "node_key_file": "unused", "relay": [url], "sync_secs": 1
        }))?;
        let mut hosts = Vec::new();
        for (i, key) in keys.into_iter().enumerate() {
            let (tx, rx) = mpsc::channel(4);
            let opts = Opts { identities: vec![(format!("a{i}"), agents[i].clone())], ..Opts::default() };
            let node = Arc::new(Node::new(Store::open(&dir.join(format!("{i}.sqlite")))?, list.clone(), key, opts, tx));
            node.certify_identities();
            let net = start_with(Endpoint::builder(presets::Minimal).clear_ip_transports(), &cfg, node.clone(), rx).await?;
            hosts.push((node, net));
        }
        let (sender, _) = &hosts[0];
        let tok = mailcore::agent_token::mint(&agents[0], "a0", "agent:a0", &sender.seed.public(), mailcore::now_millis(), 60);
        let who = sender.verify(&tok).map_err(|e| anyhow::anyhow!(e.message))?;
        let mail = sender.post(&who, &serde_json::json!({"to": "all", "text": "relay delivery"}))
            .map_err(|e| anyhow::anyhow!(e.message))?;
        tokio::time::timeout(Duration::from_secs(30), async {
            while !hosts[1].0.store.has(&mail.row.env_id)? {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            anyhow::Ok(())
        }).await??;
        let (reader, net) = &hosts[1];
        let tok = mailcore::agent_token::mint(&agents[1], "a1", "agent:a1", &reader.seed.public(), mailcore::now_millis(), 60);
        let who = reader.verify(&tok).map_err(|e| anyhow::anyhow!(e.message))?;
        assert_eq!(reader.store.get(1, &who)?.unwrap().text.as_deref(), Some("relay delivery"));
        let remote = &net.endpoint;
        tokio::time::timeout(Duration::from_secs(10), remote.online()).await?;
        assert!(remote.addr().relay_urls().next().is_some());
        assert!(remote.addr().ip_addrs().next().is_none());
        let peer = hosts[0].1.endpoint.connect(remote.id(), SYNC_ALPN).await?;
        let certs = call(&peer, &network, &Req::Certs).await?.certs;
        assert!(certs.iter().any(|c| c.name == "a1"));
        let issuer = fmt_key(&reader.seed.public());
        let page = call(&peer, &network, &Req::CertsFor { issuer: issuer.clone() }).await?;
        assert!(!page.more_trust && page.certs.len() == 1 && page.certs[0].node == issuer);
        let outsider = Endpoint::builder(presets::Minimal).clear_ip_transports()
            .relay_mode(relay_mode(&cfg.relay)?).bind().await?;
        let attempt = tokio::time::timeout(Duration::from_secs(10), async {
            let conn = outsider.connect(remote.addr(), SYNC_ALPN).await?;
            call(&conn, &network, &Req::Days).await
        }).await?;
        assert!(attempt.is_err(), "an unpinned node got a sync response through the relay");
        outsider.close().await;
        for (_, net) in hosts { net.router.shutdown().await?; }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn get_answers_stay_within_the_byte_budget() {
        let me = Seed::generate();
        let list = mailcore::MemberList {
            v: 2,
            network: mailcore::b64u(&mailcore::random_bytes::<32>()),
            seq: 1,
            members: vec![],
            nodes: vec![NodeEntry { name: "n".into(), key: fmt_key(&me.public()), addrs: vec![], names: vec![] }],
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
                    attest: Attest::Agent { key: fmt_key(&node.seed.public()), digest: String::new(), sig: i.to_string(), cert: None },
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

    #[tokio::test]
    async fn trust_file_changes_cut_off_sessions_on_their_own_timer() {
        let (me, alice) = (Seed::generate(), Seed::generate());
        let dir = std::env::temp_dir().join(format!("mailnode-trust-{}", mailcore::b64u(&mailcore::random_bytes::<9>())));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("members.json");
        let network = mailcore::b64u(&mailcore::random_bytes::<32>());
        let list = |seq: u64, with_alice: bool| mailcore::MemberList {
            v: 2, network: network.clone(), seq,
            members: if with_alice {
                vec![mailcore::Member { name: "a.alice".into(), sub: "agent:a.alice".into(), key: fmt_key(&alice.public()) }]
            } else { vec![] },
            nodes: vec![NodeEntry { name: "n".into(), key: fmt_key(&me.public()), addrs: vec![], names: vec![] }],
        };
        std::fs::write(&file, serde_json::to_vec(&list(1, true)).unwrap()).unwrap();
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "data_dir": dir, "node_key_file": dir.join("node.seed"), "members_file": file })).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let store = Store::open(&dir.join("mail.sqlite")).unwrap();
        store.bind_roster(&me.public(), &list(1, true)).unwrap();
        let node = Arc::new(Node::new(store, list(1, true), me.clone(), Opts::default(), tx));
        let tok = mailcore::agent_token::mint(&alice, "a.alice", "agent:a.alice", &me.public(), mailcore::now_millis(), 600);
        let who = node.verify(&tok).unwrap();
        let mut trust = node.trust.subscribe();
        trust.mark_unchanged();
        let adopted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a2 = adopted.clone();
        tokio::spawn(watch_trust_file(cfg, node.clone(), move || { a2.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!trust.has_changed().unwrap(), "an unchanged file is not adopted again");
        std::fs::write(&file, serde_json::to_vec(&list(2, false)).unwrap()).unwrap();
        tokio::time::timeout(TRUST_POLL * 3, trust.changed()).await.expect("sessions are woken within seconds").unwrap();
        assert!(!node.active(&who), "the removed agent's session is over");
        assert_eq!(adopted.load(std::sync::atomic::Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
