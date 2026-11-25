//! Loopback HTTP API for agent mail and streams.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
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
        .route("/api/messages", get(list).post(post))
        .route("/api/threads", get(threads))
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

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let t = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")).unwrap_or(v);
    Some(t.trim().to_string())
}

fn caller(s: &AppState, headers: &HeaderMap) -> Result<Caller, ApiError> {
    match bearer(headers) {
        Some(t) => s.node.verify(&t),
        None => Err(ApiError::new(401, "sign in first")),
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

/// The old server's intParam: Number(v) must be a safe non-negative integer ("" counts as 0, as in JS).
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
    Ok(Query {
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
async fn node_info(State(s): State<AppState>) -> Response {
    let members = s.node.members.read().unwrap();
    json_resp(
        json!({ "node": mailcore::keys::fmt_key(&s.node.seed.public()), "network": members.network, "network_id": mailcore::b64u(&members.topic()),
                "envelope_version": mailcore::envelope::VERSION,
                "members_seq": members.seq, "auth": ["agent-token"],
                "agent_token": { "format": "PASETO v4.public", "implicit_assertion": "agentmail-auth-v1",
                                 "max_lifetime_s": mailcore::agent_token::MAX_LIFETIME_S } }),
        200,
    )
}

/// Return the exact key set the local node would use. A trust-file change before posting invalidates the signature.
async fn recipients(State(s): State<AppState>, headers: HeaderMap, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    let p = params(&raw);
    let to = p.get("to").ok_or_else(|| ApiError::new(400, "missing to"))?;
    let mode = match p.get("mode").map(String::as_str) {
        Some("private") => mailcore::Mode::Private,
        Some("members") => mailcore::Mode::Members,
        _ => return Err(ApiError::new(400, "specify members or private mode")),
    };
    let members = s.node.members.read().unwrap();
    let keys = Node::recipients(&members, to, &who.name, mode)?;
    Ok(json_resp(json!({ "keys": keys.iter().map(|k| mailcore::b64u(k)).collect::<Vec<_>>() }), 200))
}

async fn me(State(s): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    let island = s.node.members.read().unwrap().network.clone();
    Ok(json_resp(
        json!({ "name": who.name, "sub": who.sub, "kind": "agent", "island": island, "auth": "agent-token",
                "last_id": s.node.store.last_id()?,
                "node": mailcore::keys::fmt_key(&s.node.seed.public()), "members_seq": s.node.members_seq(),
                "features": ["signed-post", "private", "files", "agent-token"],
                "refuse_token_only": true }),
        200,
    ))
}

async fn list(State(s): State<AppState>, headers: HeaderMap, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    let p = params(&raw);
    let q = query_from(&p)?;
    // Extension: order=causal gives one thread in the order every node agrees on (parents first, then (ts, id)).
    if p.get("order").map(|s| s.as_str()) == Some("causal") {
        let thread = q.thread.clone().ok_or_else(|| ApiError::new(400, "order=causal needs thread"))?;
        let rows = s.node.store.thread_causal(&thread, &who, MAX_TEXT)?;
        let msgs: Vec<Value> = rows.iter().map(|r| r.to_message()).collect();
        return Ok(json_resp(json!({ "messages": msgs, "more": false, "last_id": s.node.store.last_id()? }), 200));
    }
    let (rows, more) = s.node.store.query(&q, &who, MAX_TEXT)?;
    let msgs: Vec<Value> = rows.iter().map(|r| r.to_message()).collect();
    Ok(json_resp(json!({ "messages": msgs, "more": more, "last_id": s.node.store.last_id()? }), 200))
}

async fn post(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    if !ct.starts_with("application/json") {
        return Err(ApiError::new(415, "send Content-Type: application/json"));
    }
    if body.len() > 1024 * 1024 {
        return Err(ApiError::new(413, "body is over 1048576 bytes"));
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiError::new(400, "body is not valid JSON"))?;
    if !v.is_object() {
        return Err(ApiError::new(400, "body must be a JSON object"));
    }
    let node = s.node.clone();
    let p = tokio::task::spawn_blocking(move || node.post(&who, &v))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    let mut out = json!({ "message": p.row.to_message(), "reaches": p.reaches });
    if p.repeated {
        out["repeated"] = json!(true);
        Ok(json_resp(out, 200))
    } else {
        Ok(json_resp(out, 201))
    }
}

async fn threads(State(s): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    Ok(json_resp(json!({ "threads": s.node.store.thread_rows(&who, 500)? }), 200))
}

async fn names(State(s): State<AppState>, headers: HeaderMap, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    caller(&s, &headers)?;
    let p = params(&raw);
    Ok(json_resp(json!({ "names": s.node.names_list(p.get("prefix").map(|s| s.as_str()).unwrap_or(""))? }), 200))
}

async fn upload(
    State(s): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    let p = params(&raw);
    let name = crate::node::file_name(p.get("name").map(|s| s.as_str()));
    let ty = crate::node::mime_type(headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()));
    let node = s.node.clone();
    let f = tokio::task::spawn_blocking(move || node.upload(&who, &name, &ty, &body))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    Ok(json_resp(json!({ "file": f }), 201))
}

const INLINE_TYPES: [&str; 5] = ["image/png", "image/jpeg", "image/gif", "image/webp", "text/plain"];

async fn download(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
    if !mailcore::envelope::is_id(&id) {
        return Err(ApiError::new(404, "no such file"));
    }
    let node = s.node.clone();
    let (f, bytes) = tokio::task::spawn_blocking(move || node.download(&id, &who))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
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
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=86400"));
    Ok(r)
}

fn sse_event(m: &Value) -> String {
    format!("id: {}\ndata: {}\n\n", m["id"], m)
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
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let who = caller(&s, &headers)?;
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
    let (rows, more) = s.node.store.query(&Query { after: Some(after), ..Default::default() }, &who, MAX_TEXT)?;
    let mut last = after;
    let mut first = String::from("retry: 2000\n: connected\n\n");
    for r in &rows {
        first.push_str(&sse_event(&r.to_message()));
        last = last.max(r.id);
    }
    let (tx, out) = mpsc::channel::<Result<Bytes, Infallible>>(256);
    let _ = tx.send(Ok(Bytes::from(first))).await;
    if !more {
        let node = s.node.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let mut beat = tokio::time::interval(Duration::from_millis(HEARTBEAT_MS));
            beat.tick().await;
            loop {
                tokio::select! {
                    ev = rx.recv() => match ev {
                        Ok(_) if !node.active(&who) => break,
                        Ok(row) => {
                            if row.id > last && row.visible_to(&who) {
                                last = row.id;
                                if tx.send(Ok(Bytes::from(sse_event(&row.to_message())))).await.is_err() { break; }
                            }
                        }
                        Err(_) => break,
                    },
                    _ = beat.tick() => {
                        if !node.active(&who) { break; }
                        if tx.send(Ok(Bytes::from_static(b": ping\n\n"))).await.is_err() { break; }
                    }
                    _ = tx.closed() => break,
                }
            }
        });
    } else {
        drop(slot);
    }
    let mut r = Response::new(Body::from_stream(ReceiverStream::new(out)));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, no-transform"));
    Ok(r)
}
