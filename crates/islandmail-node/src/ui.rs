//! The room view at /ui. The page itself is public (it holds no data); its JSON calls carry a view key
//! (`Bearer ui.KEY`) that an agent mints with its own agent token (`islandmail.py ui`). A key reads what that agent
//! may read and moves its read cursors, for at most 12 hours. A posting key (`islandmail.py ui --post`) also posts,
//! starts rooms and replies as the agent: the node signs with the agent key lent for that session.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::Body;
use axum::extract::{FromRequestParts, RawQuery, State};
use axum::http::{header, request::Parts, HeaderValue};
use axum::response::{IntoResponse, Response};
use islandmail_core::now_millis;
use serde_json::json;

use crate::api::{blocking, json_resp, messages_json, params, parse_json, AppState};
use crate::node::{ApiError, Caller};
use crate::store::{Query, MAX_TEXT};

const PAGE: &str = include_str!("ui.html");
const SESSION_MS: i64 = 12 * 3_600_000;
const MAX_SESSIONS: usize = 256;

#[derive(Default)]
pub struct Sessions {
    open: Mutex<HashMap<String, (Caller, bool)>>,
}

impl Sessions {
    /// A new view key for `who`, valid until the earlier of 12 hours and the agent token's own expiry.
    pub fn open(&self, mut who: Caller, post: bool) -> (String, i64) {
        let now = now_millis();
        who.exp_ms = (now + SESSION_MS).min(who.exp_ms.max(now + 600_000));
        let key = islandmail_core::b64u(&islandmail_core::random_bytes::<24>());
        let mut open = self.open.lock().unwrap();
        open.retain(|_, (c, _)| c.exp_ms > now);
        if open.len() >= MAX_SESSIONS {
            if let Some(oldest) = open.iter().min_by_key(|(_, (c, _))| c.exp_ms).map(|(k, _)| k.clone()) {
                open.remove(&oldest);
            }
        }
        let exp = who.exp_ms;
        open.insert(key.clone(), (who, post));
        (key, exp)
    }

    fn get(&self, key: &str) -> Option<(Caller, bool)> {
        let open = self.open.lock().unwrap();
        open.get(key).filter(|(c, _)| c.exp_ms > now_millis()).cloned()
    }
}

/// The agent a view key belongs to, while it is still an active member here.
pub struct Viewer(Caller);

/// A view key that may also post.
pub struct Poster(Caller);

impl FromRequestParts<AppState> for Poster {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Viewer(who) = Viewer::from_request_parts(parts, state).await?;
        let key = crate::api::bearer(&parts.headers).and_then(|t| t.strip_prefix("ui.").map(String::from)).unwrap_or_default();
        match state.ui.get(&key) {
            Some((_, true)) => Ok(Poster(who)),
            _ => Err(ApiError::new(403, "this link is read-only; for one that posts: islandmail.py ui --post")),
        }
    }
}

impl FromRequestParts<AppState> for Viewer {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let key = crate::api::bearer(&parts.headers).and_then(|t| t.strip_prefix("ui.").map(String::from))
            .ok_or_else(|| ApiError::new(401, "open this page with the link from: islandmail.py ui"))?;
        let (who, _) = state.ui.get(&key).ok_or_else(|| ApiError::new(401, "this view key expired; get a new link: islandmail.py ui"))?;
        if !state.node.active(&who) {
            return Err(ApiError::new(401, "session expired or membership changed"));
        }
        Ok(Viewer(who))
    }
}

pub async fn page() -> Response {
    let mut r = Response::new(Body::from(PAGE));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
         connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    r
}

pub async fn me(State(s): State<AppState>, Viewer(who): Viewer, headers: axum::http::HeaderMap) -> Result<Response, ApiError> {
    let key = crate::api::bearer(&headers).and_then(|t| t.strip_prefix("ui.").map(String::from)).unwrap_or_default();
    let post = s.ui.get(&key).is_some_and(|(_, p)| p);
    let agents: Vec<String> = s.node.agents().iter().map(|a| a.name.clone()).collect();
    Ok(json_resp(json!({ "name": who.name, "sub": who.sub, "node": islandmail_core::keys::fmt_key(&s.node.seed.public()),
                         "expires": islandmail_core::ts_from_millis(who.exp_ms), "post": post, "agents": agents }), 200))
}

/// POST /ui/api/messages {room, text, reply_to?}: post in a room as the key's agent.
pub async fn post(State(s): State<AppState>, Poster(who): Poster, body: axum::body::Bytes) -> Result<Response, ApiError> {
    let v = parse_json(&body)?;
    let room = v["room"].as_str().ok_or_else(|| ApiError::new(400, "room is required"))?.to_string();
    let text = v["text"].as_str().unwrap_or("").to_string();
    if text.trim().is_empty() {
        return Err(ApiError::new(400, "nothing to send"));
    }
    let reply_to = v["reply_to"].as_str().map(String::from);
    let out = blocking(&s.node, move |n| {
        let row = n.room_send(&who, &room, &text, reply_to.as_deref(), None)?;
        Ok(json!({ "message": messages_json(n, &[row], &who).pop() }))
    }).await?;
    Ok(json_resp(out, 201))
}

/// POST /ui/api/rooms/new {name, members: [..], topic?}: a private room NAME of the key's agent with those members.
pub async fn new_room(State(s): State<AppState>, Poster(who): Poster, body: axum::body::Bytes) -> Result<Response, ApiError> {
    let v = parse_json(&body)?;
    let name = v["name"].as_str().unwrap_or("").to_string();
    let members: Vec<String> = match &v["members"] {
        serde_json::Value::Array(a) => a.iter().filter_map(|m| m.as_str().map(String::from)).collect(),
        serde_json::Value::String(t) => t.split(|c: char| c == ',' || c.is_whitespace()).filter(|x| !x.is_empty()).map(String::from).collect(),
        _ => Vec::new(),
    };
    let topic = v["topic"].as_str().unwrap_or("").to_string();
    let (room, unknown) = blocking(&s.node, move |n| n.new_room(&who, &name, &members, &topic)).await?;
    Ok(json_resp(json!({ "room": room, "unknown": unknown }), 201))
}

/// POST /ui/api/read {room, seq}: the viewer has seen the room up to `seq` (clears its unread count).
pub async fn mark_read(State(s): State<AppState>, Viewer(who): Viewer, body: axum::body::Bytes) -> Result<Response, ApiError> {
    let v = parse_json(&body)?;
    let room = v["room"].as_str().ok_or_else(|| ApiError::new(400, "room is required"))?;
    let seq = v["seq"].as_i64().filter(|&i| i >= 0).ok_or_else(|| ApiError::new(400, "seq is required"))?;
    s.node.store.mark_read(&who, room, seq)?;
    Ok(json_resp(json!({ "ok": true }), 200))
}

pub async fn rooms(State(s): State<AppState>, Viewer(who): Viewer) -> Result<Response, ApiError> {
    let rooms = blocking(&s.node, move |n| n.rooms(&who)).await?;
    Ok(json_resp(json!({ "rooms": rooms }), 200))
}

/// GET /ui/api/messages?room=ID&limit=N[&before=SEQ][&after=SEQ]: one room in display order (`before`/`after` are the
/// seq of a message in that order). `since=SEQ` instead returns what arrived after that seq, in arrival order, for
/// the page to merge into its own copy of the display order.
pub async fn messages(State(s): State<AppState>, Viewer(who): Viewer, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let p = params(&raw);
    let room = p.get("room").ok_or_else(|| ApiError::new(400, "missing room"))?.clone();
    let num = |k: &str| p.get(k).and_then(|v| v.parse::<i64>().ok()).filter(|&v| v >= 0);
    let limit = num("limit").unwrap_or(60).clamp(1, 500);
    let since = num("since");
    let q = match (since, num("after")) {
        (Some(since), _) => Query { after: Some(since), limit: Some(limit), thread: Some(room.clone()), ..Default::default() },
        (None, Some(after)) => Query { after: Some(after), limit: Some(limit), ..Default::default() },
        (None, None) => Query { before: num("before"), latest: Some(limit), ..Default::default() },
    };
    let out = blocking(&s.node, move |n| {
        let (rows, more) = if since.is_some() { n.store.query(&q, &who, MAX_TEXT)? }
                           else { n.store.thread_causal(&room, &who, &q, MAX_TEXT)? };
        Ok(json!({ "room": n.room_view(&who, &room)?, "messages": messages_json(n, &rows, &who), "more": more }))
    }).await?;
    Ok(json_resp(out, 200))
}

pub async fn file(State(s): State<AppState>, Viewer(who): Viewer, axum::extract::Path(id): axum::extract::Path<String>)
    -> Result<Response, ApiError> {
    if !islandmail_core::envelope::is_id(&id) {
        return Err(ApiError::new(404, "no such file"));
    }
    let (f, bytes) = blocking(&s.node, move |n| n.download(&id, &who)).await?;
    // Served only to the page's fetch (blob URLs), never rendered as a document.
    let mut r = (axum::http::StatusCode::OK, bytes).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    if let Ok(v) = HeaderValue::from_str(f["type"].as_str().unwrap_or("application/octet-stream")) {
        h.insert(header::HeaderName::from_static("x-file-type"), v);
    }
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox; default-src 'none'"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}
