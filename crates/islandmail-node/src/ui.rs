//! The read-only room view at /ui. The page itself is public (it holds no data); its JSON calls carry a view key
//! (`Bearer ui.KEY`) that an agent mints with its own agent token (`islandmail.py ui`). A key reads what that agent
//! may read, for at most 12 hours, and nothing else: no posting, no read cursors.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::Body;
use axum::extract::{FromRequestParts, RawQuery, State};
use axum::http::{header, request::Parts, HeaderValue};
use axum::response::{IntoResponse, Response};
use islandmail_core::now_millis;
use serde_json::json;

use crate::api::{json_resp, messages_json, params, AppState};
use crate::node::{ApiError, Caller};
use crate::store::{Query, MAX_TEXT};

const PAGE: &str = include_str!("ui.html");
const SESSION_MS: i64 = 12 * 3_600_000;
const MAX_SESSIONS: usize = 256;

#[derive(Default)]
pub struct Sessions {
    open: Mutex<HashMap<String, Caller>>,
}

impl Sessions {
    /// A new view key for `who`, valid until the earlier of 12 hours and the agent token's own expiry.
    pub fn open(&self, mut who: Caller) -> (String, i64) {
        let now = now_millis();
        who.exp_ms = (now + SESSION_MS).min(who.exp_ms.max(now + 600_000));
        let key = islandmail_core::b64u(&islandmail_core::random_bytes::<24>());
        let mut open = self.open.lock().unwrap();
        open.retain(|_, c| c.exp_ms > now);
        if open.len() >= MAX_SESSIONS {
            if let Some(oldest) = open.iter().min_by_key(|(_, c)| c.exp_ms).map(|(k, _)| k.clone()) {
                open.remove(&oldest);
            }
        }
        let exp = who.exp_ms;
        open.insert(key.clone(), who);
        (key, exp)
    }

    fn get(&self, key: &str) -> Option<Caller> {
        let open = self.open.lock().unwrap();
        open.get(key).filter(|c| c.exp_ms > now_millis()).cloned()
    }
}

/// The agent a view key belongs to, while it is still an active member here.
pub struct Viewer(Caller);

impl FromRequestParts<AppState> for Viewer {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let key = crate::api::bearer(&parts.headers).and_then(|t| t.strip_prefix("ui.").map(String::from))
            .ok_or_else(|| ApiError::new(401, "open this page with the link from: islandmail.py ui"))?;
        let who = state.ui.get(&key).ok_or_else(|| ApiError::new(401, "this view key expired; get a new link: islandmail.py ui"))?;
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
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' blob: data:; \
         connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    r
}

pub async fn me(State(s): State<AppState>, Viewer(who): Viewer) -> Result<Response, ApiError> {
    Ok(json_resp(json!({ "name": who.name, "sub": who.sub, "node": islandmail_core::keys::fmt_key(&s.node.seed.public()),
                         "expires": islandmail_core::ts_from_millis(who.exp_ms) }), 200))
}

pub async fn rooms(State(s): State<AppState>, Viewer(who): Viewer) -> Result<Response, ApiError> {
    let node = s.node.clone();
    let rooms = tokio::task::spawn_blocking(move || node.rooms(&who)).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
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
    let node = s.node.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, ApiError> {
        let (rows, more) = if since.is_some() { node.store.query(&q, &who, MAX_TEXT)? }
                           else { node.store.thread_causal(&room, &who, &q, MAX_TEXT)? };
        let senders = node.store.room_senders(&room)?;
        let info = node.room_info(&who, &room, &senders)?;
        Ok(json!({ "room": info, "messages": messages_json(&node, &rows, &who), "more": more }))
    }).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    Ok(json_resp(out, 200))
}

pub async fn file(State(s): State<AppState>, Viewer(who): Viewer, axum::extract::Path(id): axum::extract::Path<String>)
    -> Result<Response, ApiError> {
    if !islandmail_core::envelope::is_id(&id) {
        return Err(ApiError::new(404, "no such file"));
    }
    let node = s.node.clone();
    let (f, bytes) = tokio::task::spawn_blocking(move || node.download(&id, &who))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
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
