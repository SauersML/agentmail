//! Loopback HTTP API for Islandmail and streams.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequestParts, RawQuery, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::mcpl;
use crate::node::{ApiError, Caller, Node};
use crate::store::{Query, MAX_TEXT};

const HEARTBEAT_MS: u64 = 25_000;
const MAX_STREAMS_PER_SUB: usize = 4;
const MAX_STREAMS: usize = 200;

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Node>,
    pub ui: Arc<crate::ui::Sessions>,
    pub streams: Arc<Mutex<HashMap<String, usize>>>,
    pub sockets: Arc<mcpl::Sockets>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = json_resp(json!({ "error": self.message }), self.status);
        if let Some(s) = self.retry_after {
            r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        r
    }
}

pub fn json_resp(v: Value, status: u16) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap_or(StatusCode::OK), v.to_string()).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/node", get(node_info))
        .route("/api/me", get(me))
        .route("/api/recipients", get(recipients))
        .route("/api/agents", get(agents).post(certify))
        .route("/api/revocations", axum::routing::post(revoke))
        .route("/api/invites", axum::routing::post(|s: State<AppState>, h: HeaderMap, b: Bytes| owner_step(s, h, b, crate::invite::invite)))
        .route("/api/joins", axum::routing::post(join))
        .route("/api/invites/joined", get(joined).post(joined_seen))
        .route("/api/accepts", axum::routing::post(|s: State<AppState>, h: HeaderMap, b: Bytes| owner_step(s, h, b, crate::invite::accept)))
        .route("/api/messages", get(list).post(post))
        .route("/api/messages/{id}", get(one))
        .route("/api/rooms", get(rooms))
        .route("/api/room", get(room))
        .route("/api/room-keys", get(room_keys))
        .route("/api/room-vouch", get(room_vouch))
        .route("/api/room-read", axum::routing::post(room_read))
        .route("/api/ui-sessions", axum::routing::post(ui_session))
        .route("/ui", get(crate::ui::page))
        .route("/ui/api/me", get(crate::ui::me))
        .route("/ui/api/rooms", get(crate::ui::rooms))
        .route("/ui/api/messages", get(crate::ui::messages).post(crate::ui::post))
        .route("/ui/api/rooms/new", axum::routing::post(crate::ui::new_room))
        .route("/ui/api/read", axum::routing::post(crate::ui::mark_read))
        .route("/ui/api/files/{id}", get(crate::ui::file))
        .route("/api/names", get(names))
        .route("/api/stream", get(stream))
        .route(
            "/api/files",
            axum::routing::post(upload).layer(axum::extract::DefaultBodyLimit::max(crate::node::MAX_FILE + 1)),
        )
        .route("/api/files/{id}", get(download))
        .route("/mcpl", get(mcpl::handler))
        .fallback(|| async { ApiError::new(404, "no such endpoint") })
        .with_state(state)
}

/// The Host header values this node answers to: the loopback names with the API's port (and the listen address as
/// written). A page whose own name a DNS rebinding pointed at 127.0.0.1 sends that name, so it reads nothing.
pub fn allowed_hosts(listen: std::net::SocketAddr) -> Vec<String> {
    let port = listen.port();
    let mut out: Vec<String> = ["127.0.0.1", "localhost", "[::1]"].iter().map(|h| format!("{h}:{port}")).collect();
    out.push(listen.to_string());
    if port == 80 {
        out.extend(["127.0.0.1", "localhost", "[::1]"].map(String::from));
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a request's Host is one of `allowed` (exactly, ignoring case). A request without one is refused.
pub fn host_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_ascii_lowercase();
    !host.is_empty() && allowed.contains(&host)
}

pub fn guarded(app: Router, allowed: Vec<String>) -> Router {
    let allowed = Arc::new(allowed);
    app.layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
        let allowed = allowed.clone();
        async move {
            if host_allowed(req.headers(), &allowed) {
                next.run(req).await
            } else {
                ApiError::new(403, format!("this node answers requests for Host {} only",
                                           allowed.join(", "))).into_response()
            }
        }
    }))
}

/// Time a client has to send each request's headers (and an idle keep-alive connection its next request): a
/// slowloris connection that trickles bytes is closed after this.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How many API connections may be open at once, given the open-file limit: room for the store, the trust file,
/// QUIC sockets and key files besides them, so idle connections cannot starve those.
pub fn max_connections(open_files: u64) -> usize {
    open_files.saturating_sub(128).clamp(16, 1024) as usize
}

/// An accepted connection, holding one of `serve`'s slots until it closes (an upgraded WebSocket included).
struct Slot {
    tcp: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl tokio::io::AsyncRead for Slot {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>)
        -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Slot {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8])
        -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.tcp).poll_write(cx, buf)
    }
    fn poll_write_vectored(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, bufs: &[std::io::IoSlice<'_>])
        -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.tcp).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.tcp.is_write_vectored()
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

/// Serves the API: at most `cap` connections at once (a slot is taken before accept, so more wait in the listen
/// backlog and hold no file descriptor here), each request's headers within HEADER_READ_TIMEOUT. Streams, uploads
/// and WebSockets run as long as they need. Returns when `shutdown` resolves.
pub async fn serve(listener: tokio::net::TcpListener, app: Router, cap: usize, shutdown: impl std::future::Future<Output = ()>) {
    let slots = Arc::new(tokio::sync::Semaphore::new(cap));
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            p = slots.clone().acquire_owned() => p.expect("the semaphore is never closed"),
            _ = &mut shutdown => return,
        };
        let tcp = tokio::select! {
            r = listener.accept() => match r {
                Ok((tcp, _)) => tcp,
                Err(e) => {
                    // EMFILE and the like: back off instead of spinning.
                    tracing::warn!("API accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = &mut shutdown => return,
        };
        let _ = tcp.set_nodelay(true);
        let io = hyper_util::rt::TokioIo::new(Slot { tcp, _permit: permit });
        let svc = hyper_util::service::TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
            if let Err(e) = b.serve_connection(io, svc).with_upgrades().await {
                tracing::debug!("API connection: {e}");
            }
        });
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let t = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")).unwrap_or(v);
    Some(t.trim().to_string())
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = bearer(&parts.headers).ok_or_else(|| ApiError::new(401, "sign in first"))?;
        state.node.verify(&token)
    }
}

pub fn params(raw: &Option<String>) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(q) = raw {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            m.entry(k.into_owned()).or_insert_with(|| v.into_owned());
        }
    }
    m
}

fn int_param(p: &HashMap<String, String>, name: &str) -> Result<Option<i64>, ApiError> {
    let Some(v) = p.get(name) else { return Ok(None) };
    let v = v.trim();
    if v.is_empty() {
        return Ok(Some(0));
    }
    match v.parse::<f64>() {
        Ok(f) if f >= 0.0 && f.fract() == 0.0 && f <= 9_007_199_254_740_991.0 => Ok(Some(f as i64)),
        _ => Err(ApiError::new(400, format!("{name} must be a whole number"))),
    }
}

pub fn query_from(p: &HashMap<String, String>) -> Result<Query, ApiError> {
    let to_me = match p.get("to_me").map(String::as_str) {
        None | Some("0") => false,
        Some("1") => true,
        _ => return Err(ApiError::new(400, "to_me must be 0 or 1")),
    };
    Ok(Query {
        to_me,
        after: int_param(p, "after")?,
        before: int_param(p, "before")?,
        latest: int_param(p, "latest")?,
        limit: int_param(p, "limit")?,
        thread: p.get("thread").cloned(),
        from: p.get("from").cloned(),
        to: p.get("to").cloned(),
        q: p.get("q").cloned(),
    })
}

/// Public facts a client needs before it can sign in: the node key (an agent token's aud) and which tokens it takes.
/// With `?nonce=` (16-128 base64url characters) the node also proves it holds that key: `proof` is its signature over
/// `islandmail-node-proof|v1|NONCE|TS`, so a process that took the port while the node was down cannot pass for it.
async fn node_info(State(s): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let proof = params(&raw).get("nonce").map(|n| {
        if !(16..=128).contains(&n.len()) || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(());
        }
        let ts = islandmail_core::now_ts();
        let sig = s.node.seed.sign(node_proof_statement(n, &ts).as_bytes());
        Ok(json!({ "ts": ts, "sig": islandmail_core::b64u(&sig) }))
    });
    let proof = match proof {
        Some(Err(())) => return ApiError::new(400, "nonce must be 16-128 base64url characters").into_response(),
        Some(Ok(p)) => Some(p),
        None => None,
    };
    let members = s.node.members.read().unwrap();
    let mut info = json!({ "node": islandmail_core::keys::fmt_key(&s.node.seed.public()), "network": members.network, "network_id": islandmail_core::b64u(&members.topic()),
                "envelope_version": islandmail_core::envelope::VERSION,
                "versions": islandmail_core::versions::report(), "build": env!("CARGO_PKG_VERSION"),
                "encryption_key": s.node.current_encryption_key(),
                "members_seq": members.seq, "auth": ["agent-token"],
                "names": members.node_by_key(&s.node.seed.public()).map(|n| n.names.clone()).unwrap_or_default(),
                "agent_token": { "format": "PASETO v4.public", "implicit_assertion": "islandmail-auth-v1",
                                 "max_lifetime_s": islandmail_core::agent_token::MAX_LIFETIME_S } });
    if let Some(p) = proof {
        info["proof"] = p;
    }
    json_resp(info, 200)
}

/// What a node signs to show a client it holds its key (GET /api/node?nonce=).
pub fn node_proof_statement(nonce: &str, ts: &str) -> String {
    format!("islandmail-node-proof|v1|{nonce}|{ts}")
}

/// Return the exact key set the local node would use. A trust-file change before posting invalidates the signature.
async fn recipients(State(s): State<AppState>, who: Caller, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    if let Some(room) = p.get("room") {
        // A room post: the node says where it goes (to, mode) and the exact keys, given the optional event.
        let event = match p.get("event") {
            Some(e) => Some(serde_json::from_str::<islandmail_core::room::Event>(e)
                .map_err(|e| ApiError::new(400, format!("invalid event: {e}")))?),
            None => None,
        };
        let members = s.node.members.read().unwrap().clone();
        let agents = s.node.agents();
        let plan = s.node.room_plan(room, &who.name, event.as_ref(), &members, &agents)?;
        let node_keys = s.node.recipient_node_keys(&members, &plan.keys)?;
        return Ok(json_resp(json!({ "keys": plan.keys.iter().map(|k| islandmail_core::b64u(k)).collect::<Vec<_>>(),
            "node_encryption_keys": node_keys, "to": plan.to, "mode": plan.mode.as_str(), "names": plan.names }), 200));
    }
    let to = p.get("to").ok_or_else(|| ApiError::new(400, "missing to"))?;
    let mode = match p.get("mode").map(String::as_str) {
        Some("private") => islandmail_core::Mode::Private,
        Some("members") => islandmail_core::Mode::Members,
        _ => return Err(ApiError::new(400, "specify members or private mode")),
    };
    let members = s.node.members.read().unwrap().clone();
    let keys = Node::recipients(&members, &s.node.agents(), to, &who.name, mode)?;
    let node_keys = s.node.recipient_node_keys(&members, &keys)?;
    Ok(json_resp(json!({ "keys": keys.iter().map(|k| islandmail_core::b64u(k)).collect::<Vec<_>>(), "node_encryption_keys": node_keys }), 200))
}

pub async fn blocking<T: Send + 'static>(node: &Arc<Node>, f: impl FnOnce(&Node) -> Result<T, ApiError> + Send + 'static)
                                        -> Result<T, ApiError> {
    let node = node.clone();
    tokio::task::spawn_blocking(move || f(&node)).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?
}

pub fn parse_json(body: &[u8]) -> Result<Value, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::new(400, "body is not valid JSON"))
}

/// A JSON object body of at most `max` bytes, sent as JSON (no simple cross-site form posts).
fn json_object(headers: &HeaderMap, body: &[u8], max: usize) -> Result<Value, ApiError> {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    if !ct.starts_with("application/json") {
        return Err(ApiError::new(415, "send Content-Type: application/json"));
    }
    if body.len() > max {
        return Err(ApiError::new(413, format!("body is over {max} bytes")));
    }
    Some(parse_json(body)?).filter(|v| v.is_object()).ok_or_else(|| ApiError::new(400, "body must be a JSON object"))
}

/// The unauthenticated POSTs also take a loopback Host only (no DNS rebinding).
fn local_json(headers: &HeaderMap, body: &Bytes) -> Result<Value, ApiError> {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let bare = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h);
    if !["127.0.0.1", "localhost", "[::1]"].contains(&bare) {
        return Err(ApiError::new(403, "this endpoint answers loopback requests only"));
    }
    json_object(headers, body, 16 * 1024)
}

/// POST /api/agents {name, key, ts, sig}: certify an agent of this host (proof of key; no token, since the agent
/// has no certificate yet). 201 new, 200 already certified with this key.
async fn certify(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let v = local_json(&headers, &body)?;
    let (status, out) = blocking(&s.node, move |n| n.certify(&v)).await?;
    Ok(json_resp(out, status))
}

/// GET /api/agents: every agent this host accepts now, with its homes.
async fn agents(State(s): State<AppState>, _: Caller) -> Result<Response, ApiError> {
    let list = s.node.members.read().unwrap().clone();
    let out: Vec<Value> = s.node.agents().iter().map(|a| json!({
        "name": a.name, "sub": a.sub, "key": islandmail_core::keys::fmt_key(&a.key), "pinned": a.pinned,
        "homes": a.homes.iter().map(|h| list.node_by_key(h).map_or_else(|| islandmail_core::keys::fmt_key(h), |n| n.name.clone()))
            .collect::<Vec<_>>(),
    })).collect();
    Ok(json_resp(json!({ "agents": out }), 200))
}

/// POST /api/revocations {name, ts, sig}, signed with the node key (`islandmail-node revoke`).
async fn revoke(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let v = local_json(&headers, &body)?;
    let revoked = blocking(&s.node, move |n| n.revoke(&v)).await?;
    Ok(json_resp(json!({ "revoked": revoked }), 200))
}

/// POST /api/invites, /api/joins, /api/accepts: host-owner steps signed with the node key (see invite.rs).
async fn owner_step(State(s): State<AppState>, headers: HeaderMap, body: Bytes,
                    step: fn(&Node, &Value) -> Result<Value, ApiError>) -> Result<Response, ApiError> {
    let v = local_json(&headers, &body)?;
    Ok(json_resp(blocking(&s.node, move |n| step(n, &v)).await?, 200))
}

/// POST /api/joins {invite, ts, sig, wait_s?}: check the invite, present this node to the inviting node (up to wait_s,
/// default 60), and trust it unless it refused. Unreachable: the answer carries the reply for `accept` instead.
async fn join(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let v = local_json(&headers, &body)?;
    let wait = Duration::from_secs(v.get("wait_s").and_then(|x| x.as_u64()).unwrap_or(60).clamp(1, 120));
    let plan = blocking(&s.node, move |n| crate::invite::join_prepare(n, &v)).await?;
    let outcome = crate::net::dial_join(&s.node, &plan.inv.node, &plan.reply, wait).await;
    Ok(json_resp(blocking(&s.node, move |n| crate::invite::join_finish(n, plan, outcome)).await?, 200))
}

async fn joined(State(s): State<AppState>, who: Caller) -> Result<Response, ApiError> {
    Ok(json_resp(crate::invite::joined_for(&s.node, &who.name)?, 200))
}

async fn joined_seen(State(s): State<AppState>, who: Caller, body: Bytes) -> Result<Response, ApiError> {
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiError::new(400, "body must be JSON {nonce}"))?;
    Ok(json_resp(crate::invite::joined_seen(&s.node, &who.name, v["nonce"].as_str().unwrap_or(""))?, 200))
}

async fn me(State(s): State<AppState>, who: Caller) -> Result<Response, ApiError> {
    let (island, seq) = { let m = s.node.members.read().unwrap(); (m.network.clone(), m.seq) };
    Ok(json_resp(json!({ "name": who.name, "sub": who.sub, "island": island, "last_seq": s.node.store.last_id()?,
                         "node": islandmail_core::keys::fmt_key(&s.node.seed.public()), "members_seq": seq }), 200))
}

async fn list(State(s): State<AppState>, who: Caller, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    let q = query_from(&p)?;
    // Extension: order=causal gives one thread in the order every node agrees on (parents first, then (ts, id)).
    if p.get("order").map(|s| s.as_str()) == Some("causal") {
        let thread = q.thread.clone().ok_or_else(|| ApiError::new(400, "order=causal needs thread"))?;
        if q.to_me || q.q.is_some() || q.from.is_some() || q.to.is_some() {
            return Err(ApiError::new(400, "causal order supports thread, after, before, limit and latest"));
        }
        let (rows, more) = s.node.store.thread_causal(&thread, &who, &q, MAX_TEXT)?;
        let msgs = messages_json(&s.node, &rows, &who);
        return Ok(json_resp(json!({ "messages": msgs, "more": more, "last_seq": s.node.store.last_id()? }), 200));
    }
    let (rows, more) = s.node.store.query(&q, &who, MAX_TEXT)?;
    let msgs = messages_json(&s.node, &rows, &who);
    Ok(json_resp(json!({ "messages": msgs, "more": more, "last_seq": s.node.store.last_id()? }), 200))
}

async fn post(State(s): State<AppState>, who: Caller, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let v = json_object(&headers, &body, 1024 * 1024)?;
    let p = blocking(&s.node, move |n| n.post(&who, &v)).await?;
    let mut out = json!({ "message": p.row.to_message(), "reaches": p.reaches });
    if p.repeated {
        out["repeated"] = json!(true);
    }
    Ok(json_resp(out, if p.repeated { 200 } else { 201 }))
}

/// Messages as clients see them; a reply carries a short quote of the message it answers, when the viewer can see it.
pub fn messages_json(node: &Node, rows: &[crate::store::Row], who: &Caller) -> Vec<Value> {
    rows.iter().map(|r| {
        let mut m = r.to_message();
        // The node that wrote and signed the envelope, by this host's name for it.
        m["host"] = json!(node.host_name(&r.writer));
        m["node"] = json!(r.writer);
        if let Some(q) = r.reply_to.as_deref().and_then(|e| node.store.by_env(e, who).ok().flatten()) {
            let text: String = q.text.unwrap_or_default().chars().take(280).collect();
            m["quote"] = json!({ "id": islandmail_core::short_id(&q.env_id), "seq": q.id, "from": q.sender, "ts": q.ts, "text": text });
        }
        m
    }).collect()
}

/// GET /api/messages/ID: ID is any unique prefix of a message's shared id (or its envelope hash).
async fn one(State(s): State<AppState>, who: Caller, axum::extract::Path(id): axum::extract::Path<String>) -> Result<Response, ApiError> {
    let row = resolve(&s.node, &id, &who)?;
    Ok(json_resp(json!({ "message": messages_json(&s.node, &[row], &who).pop() }), 200))
}

/// The one message the viewer can see whose id starts with `id`: 404 for none, 409 when the prefix is ambiguous.
pub fn resolve(node: &Node, id: &str, who: &Caller) -> Result<crate::store::Row, ApiError> {
    let shown: String = id.chars().take(64).filter(|c| c.is_ascii_alphanumeric()).collect();
    let mut rows = node.store.by_prefix(id, who, 2)?;
    match rows.len() {
        0 => Err(ApiError::new(404, format!("no message {shown}"))),
        1 => Ok(rows.pop().unwrap()),
        _ => Err(ApiError::new(409, format!("{shown} names more than one message; use more of its id"))),
    }
}

async fn rooms(State(s): State<AppState>, who: Caller) -> Result<Response, ApiError> {
    let rooms = blocking(&s.node, move |n| n.rooms(&who)).await?;
    Ok(json_resp(json!({ "rooms": rooms }), 200))
}

async fn room(State(s): State<AppState>, who: Caller, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    let id = p.get("id").ok_or_else(|| ApiError::new(400, "missing id"))?;
    Ok(json_resp(json!({ "room": s.node.room_view(&who, id)? }), 200))
}

async fn room_keys(State(s): State<AppState>, who: Caller, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    let id = p.get("room").ok_or_else(|| ApiError::new(400, "missing room"))?.clone();
    let keys = blocking(&s.node, move |n| n.room_keys(&who, &id)).await?;
    Ok(json_resp(json!({ "keys": keys }), 200))
}

/// GET /api/room-vouch?room=: what the room's creator vouches for now (its current members' keys and home nodes),
/// for the creator's client to sign and post as a vouch event.
async fn room_vouch(State(s): State<AppState>, who: Caller, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    let id = p.get("room").ok_or_else(|| ApiError::new(400, "missing room"))?.clone();
    if !islandmail_core::room::creator_of(&id).is_some_and(|c| islandmail_core::addr::same(c, &who.name)) {
        return Err(ApiError::new(403, "only the room's creator vouches for its members"));
    }
    let members = blocking(&s.node, move |n| n.vouch_entries(&id)).await?;
    Ok(json_resp(json!({ "members": members }), 200))
}

/// POST /api/room-read {room, seq}: the caller has read the room up to local seq `seq`.
async fn room_read(State(s): State<AppState>, who: Caller, body: Bytes) -> Result<Response, ApiError> {
    let v = parse_json(&body)?;
    let room = v["room"].as_str().ok_or_else(|| ApiError::new(400, "room is required"))?;
    let id = v["seq"].as_i64().filter(|&i| i >= 0).ok_or_else(|| ApiError::new(400, "seq is required"))?;
    s.node.store.mark_read(&who, room, id)?;
    Ok(json_resp(json!({ "ok": true }), 200))
}

/// POST /api/ui-sessions: a key for the /ui page, bound to the caller, for at most 12 hours. Read-only by default;
/// `{"post": true, "seed": HEX}` lends the node the caller's agent key so the page can post as the caller: it lives only
/// in `Node::lent` (memory, never written to disk or logged; `Seed` does not print) until the view key expires.
async fn ui_session(State(s): State<AppState>, who: Caller, body: Bytes) -> Result<Response, ApiError> {
    let v = if body.is_empty() { json!({}) } else { parse_json(&body)? };
    let post = v["post"] == json!(true);
    let seed = if post {
        let hex = v["seed"].as_str().ok_or_else(|| ApiError::new(400, "a posting key needs the agent's seed"))?;
        Some(islandmail_core::keys::Seed::from_hex(hex).map_err(|_| ApiError::new(400, "seed must be 64 hex digits"))?)
    } else {
        None
    };
    let (key, exp) = s.ui.open(who.clone(), post);
    if let Some(seed) = seed {
        s.node.lend_key(&who, seed, exp)?;
    }
    Ok(json_resp(json!({ "key": key, "expires": islandmail_core::ts_from_millis(exp), "path": format!("/ui#k={key}") }), 201))
}

async fn names(State(s): State<AppState>, _: Caller, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    Ok(json_resp(json!({ "names": s.node.names_list(p.get("prefix").map(|s| s.as_str()).unwrap_or(""))? }), 200))
}

async fn upload(
    State(s): State<AppState>,
    who: Caller,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Result<Response, ApiError> {
    let p = params(&raw);
    let name = crate::node::file_name(p.get("name").map(|s| s.as_str()));
    let ty = crate::node::mime_type(headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()));
    let f = blocking(&s.node, move |n| n.upload(&who, &name, &ty, &body)).await?;
    Ok(json_resp(json!({ "file": f }), 201))
}

const INLINE_TYPES: [&str; 5] = ["image/png", "image/jpeg", "image/gif", "image/webp", "text/plain"];

async fn download(
    State(s): State<AppState>,
    who: Caller,
    axum::extract::Path(id): axum::extract::Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    if !islandmail_core::envelope::is_id(&id) {
        return Err(ApiError::new(404, "no such file"));
    }
    let (f, bytes) = blocking(&s.node, move |n| n.download(&id, &who)).await?;
    let ty = f["type"].as_str().unwrap_or("application/octet-stream").to_string();
    let name = f["name"].as_str().unwrap_or("file").to_string();
    let inline = INLINE_TYPES.contains(&ty.as_str()) && params(&raw).get("download").map(|s| s.as_str()) != Some("1");
    let ct = if !inline {
        "application/octet-stream".to_string()
    } else if ty == "text/plain" {
        "text/plain; charset=utf-8".to_string()
    } else {
        ty
    };
    let enc: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>().replace('+', "%20");
    let mut r = Response::new(Body::from(bytes));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&ct).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    if let Ok(v) = HeaderValue::from_str(&format!("{}; filename*=UTF-8''{enc}", if inline { "inline" } else { "attachment" })) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}

fn sse_event(m: &Value) -> String {
    format!("id: {}\ndata: {}\n\n", m["seq"], m)
}

struct StreamSlot {
    streams: Arc<Mutex<HashMap<String, usize>>>,
    sub: String,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut m = self.streams.lock().unwrap();
        if let Some(n) = m.get_mut(&self.sub) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.sub);
            }
        }
    }
}

/// SSE: the backlog after Last-Event-ID / ?after= (default: only new mail), then each new message as it is stored
/// (written here or replicated in), until the token expires. A long backlog is sent a page at a time: the stream ends
/// and the client reconnects with Last-Event-ID.
async fn stream(
    State(s): State<AppState>,
    who: Caller,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let slot = {
        let mut m = s.streams.lock().unwrap();
        if m.get(&who.sub).copied().unwrap_or(0) >= MAX_STREAMS_PER_SUB {
            return Err(ApiError::new(429, format!("at most {MAX_STREAMS_PER_SUB} open streams per sender")));
        }
        if m.values().sum::<usize>() >= MAX_STREAMS {
            return Err(ApiError { status: 503, message: "too many open streams; try again soon".into(), retry_after: Some(30) });
        }
        *m.entry(who.sub.clone()).or_default() += 1;
        StreamSlot { streams: s.streams.clone(), sub: who.sub.clone() }
    };
    let p = params(&raw);
    let given = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| p.get("after").cloned());
    let after = match given.and_then(|g| g.trim().parse::<i64>().ok()) {
        Some(a) if a >= 0 => a,
        _ => s.node.store.last_id()?,
    };
    let mut rx = s.node.events.subscribe();
    let mut trust = s.node.trust.subscribe();
    let node = s.node.clone();
    let (tx, out) = mpsc::channel::<Result<Bytes, Infallible>>(1);
    tokio::spawn(async move {
        let _slot = slot;
        let mut after = after;
        let mut beat = tokio::time::interval(Duration::from_millis(HEARTBEAT_MS));
        beat.tick().await;
        let mut chunk = String::from("retry: 2000\n: connected\n\n");
        loop {
            if !node.active(&who) { break; }
            let Ok((rows, more)) = node.store.query(&Query { after: Some(after), ..Default::default() }, &who, MAX_TEXT) else { break };
            for (r, m) in rows.iter().zip(messages_json(&node, &rows, &who)) {
                chunk.push_str(&sse_event(&m));
                after = r.id;
            }
            if !chunk.is_empty() {
                let bytes = Bytes::from(std::mem::take(&mut chunk));
                if !matches!(tokio::time::timeout(Duration::from_secs(15), tx.send(Ok(bytes))).await, Ok(Ok(()))) { break; }
            }
            if more { break; }
            tokio::select! {
                // A notification is only a wakeup. SQLite supplies committed messages in cursor order.
                event = rx.recv() => if matches!(event, Err(tokio::sync::broadcast::error::RecvError::Closed)) { break; },
                _ = beat.tick() => chunk.push_str(": ping\n\n"),
                // A trust change (revocation, trust file edit): the loop re-checks the caller first.
                _ = trust.changed() => {}
                _ = tx.closed() => break,
            }
        }
    });
    let mut r = Response::new(Body::from_stream(ReceiverStream::new(out)));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, no-transform"));
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(h: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(header::HOST, HeaderValue::from_str(h).unwrap());
        m
    }

    #[test]
    fn only_loopback_hosts_with_the_api_port_pass() {
        let allowed = allowed_hosts("127.0.0.1:8787".parse().unwrap());
        for ok in ["127.0.0.1:8787", "localhost:8787", "LOCALHOST:8787", "[::1]:8787"] {
            assert!(host_allowed(&host(ok), &allowed), "{ok}");
        }
        // DNS rebinding sends the page's own name; another port is another service (or a page on it).
        for bad in ["rebind.example:8787", "rebind.example", "127.0.0.1", "localhost", "127.0.0.1:8788",
                    "localhost.:8787", "127.0.0.1:8787.evil", "evil.localhost:8787", ""] {
            assert!(!host_allowed(&host(bad), &allowed), "{bad}");
        }
        assert!(!host_allowed(&HeaderMap::new(), &allowed), "no Host at all");
        // Another loopback address as listened on.
        let allowed = allowed_hosts("127.0.0.2:9000".parse().unwrap());
        assert!(host_allowed(&host("127.0.0.2:9000"), &allowed) && !host_allowed(&host("127.0.0.1:8787"), &allowed));
    }

    #[test]
    fn connection_cap_leaves_room_for_other_files() {
        assert_eq!(max_connections(256), 128);
        assert_eq!(max_connections(100), 16);
        assert_eq!(max_connections(65536), 1024);
    }
}
