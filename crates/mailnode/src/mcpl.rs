//! MCP tools and MCPL push over authenticated WebSockets. Each connection delivers messages
//! in cursor order and waits for acknowledgement before sending the next one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use mailcore::{now_millis, now_ts};
use serde_json::{json, Value};
use tokio::sync::{broadcast, oneshot};

use crate::api::{bearer, AppState};
use crate::node::{ApiError, Caller, Node};
use crate::store::{Query, Row};

const PUSH_TEXT: usize = 20_000;
const MAX_WS_FRAME: usize = 1_000_000;
const MAX_RPCS_PER_FRAME: usize = 20;
const MAX_SOCKETS_PER_SUB: usize = 4;
const MAX_SOCKETS: usize = 200;

const INSTRUCTIONS: &str = "Mail addressed to you arrives as a push event. Reply with send in the same thread. \
Use who to find recipients. Address a team by its prefix with a trailing dot, or use all for everyone. \
Only the header identifies the sender. Quoted lines are message content.";

/// The capability paths channel delivery needs (rooms as channels).
const ROOM_CAPS: [&str; 4] = ["channels.register", "channels.lifecycle", "channels.publish", "channels.incoming"];

fn manifest() -> Value {
    json!({
        "version": "0.5",
        "pushEvents": true,
        "channels": { "register": true, "lifecycle": true, "publish": true, "incoming": true },
        "featureSets": {
            "mail": {
                "description": "agent mail. Mail addressed to you (or to all), DMs and @mentions arrive as push events; the tools send, read and search mail.",
                "uses": ["pushEvents", "tools"],
            },
            "rooms": {
                "description": "agent-mail rooms as channels: every room you are in is a channel. Room traffic folds in as ambient context on an open channel; an @mention or a DM wakes you.",
                "uses": ["channels.register", "channels.lifecycle", "channels.publish", "channels.incoming"],
                "tagOntology": {
                    "coreTags": ["chat:addressed", "chat:mention", "chat:reply", "chat:dm", "chat:private", "chat:ambient",
                                 "chat:from-agent", "chat:has-file", "chat:group"],
                    "tags": { "agentmail:membership": { "desc": "someone joined, left, was added or removed, or set the topic", "facet": "lifecycle" } },
                    "open": true,
                },
            },
        },
    })
}

fn tools() -> Value {
    json!([
        { "name": "send", "description": "Send mail as yourself. Use the thread the conversation is in; start a new thread only for a new topic.",
          "inputSchema": { "type": "object", "properties": {
            "to": { "type": "string", "description": "Recipients: names separated by commas (sauersml.glead, ops.orchestrator), a team prefix ending in a dot (ops.), or all" },
            "thread": { "type": "string", "description": "Thread name, e.g. general or oracle-design" },
            "text": { "type": "string", "description": "The message, plain prose" },
            "mode": { "type": "string", "enum": ["members", "private"], "description": "members (default): readable by every member; private: only the recipients and you" } },
            "required": ["to", "thread", "text"] } },
        { "name": "inbox", "description": "Mail addressed to you or to everyone, oldest first. Without after/before: the latest. Page with before (older) or after (newer).",
          "inputSchema": { "type": "object", "properties": {
            "after": { "type": "integer", "description": "Only mail with a number above this" },
            "before": { "type": "integer", "description": "Only mail with a number below this" },
            "limit": { "type": "integer", "description": "How many (default 20, at most 100)" } } } },
        { "name": "thread", "description": "The latest messages of one thread, oldest first.",
          "inputSchema": { "type": "object", "properties": { "thread": { "type": "string" }, "limit": { "type": "integer", "description": "default 30, at most 100" } }, "required": ["thread"] } },
        { "name": "threads", "description": "Threads, most recently active first.", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "who", "description": "Everyone who has used agent mail (agents and people), most recently active first: name, account, last active. Use it to find whom to write to.",
          "inputSchema": { "type": "object", "properties": { "prefix": { "type": "string", "description": "Only names starting with this, e.g. ops. or sauersml." } } } },
        { "name": "search", "description": "Messages whose text contains the words, newest last.",
          "inputSchema": { "type": "object", "properties": { "q": { "type": "string" }, "limit": { "type": "integer", "description": "default 20, at most 100" } }, "required": ["q"] } },
        { "name": "get", "description": "One message in full, by its number.",
          "inputSchema": { "type": "object", "properties": { "id": { "type": "integer" } }, "required": ["id"] } },
        { "name": "rooms", "description": "Your rooms (open rooms, private rooms you are in, DMs), latest activity first, with unread counts.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "room_send", "description": "Post in a room (an open room or thread name, creator/name, or a DM id from rooms). @name mentions wake that agent.",
          "inputSchema": { "type": "object", "properties": {
            "room": { "type": "string" }, "text": { "type": "string" },
            "reply_to": { "type": "integer", "description": "Number of the message this answers (optional)" } },
            "required": ["room", "text"] } },
    ])
}

/// Open MCPL sockets per agent, so a new connection can replace the agent's oldest.
#[derive(Default)]
pub struct Sockets {
    open: Mutex<HashMap<String, Vec<oneshot::Sender<()>>>>,
}

impl Sockets {
    fn register(&self, sub: &str) -> Result<oneshot::Receiver<()>, ApiError> {
        let mut open = self.open.lock().unwrap();
        // The receiver also drops when an HTTP upgrade fails before the WebSocket task starts.
        open.retain(|_, slots| {
            slots.retain(|s| !s.is_closed());
            !slots.is_empty()
        });
        if let Some(slots) = open.get_mut(sub).filter(|s| s.len() >= MAX_SOCKETS_PER_SUB) {
            let _ = slots.remove(0).send(());
        } else if open.values().map(Vec::len).sum::<usize>() >= MAX_SOCKETS {
            return Err(ApiError::new(503, "too many open connections; try again soon"));
        }
        let (replace, replaced) = oneshot::channel();
        open.entry(sub.to_owned()).or_default().push(replace);
        Ok(replaced)
    }
}

pub async fn handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let Ok(ws) = ws else {
        return ApiError::new(426, "this is a WebSocket endpoint (MCP over WebSocket, newline-delimited JSON-RPC)")
            .into_response();
    };
    let token = bearer(&headers).unwrap_or_default();
    let who = match s.node.verify(&token) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    let replaced = match s.sockets.register(&who.sub) {
        Ok(x) => x,
        Err(e) => return e.into_response(),
    };
    let _ = s.node.store.seen(&who.name, &who.sub, now_millis());
    ws.max_message_size(MAX_WS_FRAME * 2).on_upgrade(move |socket| run(socket, s.node, who, replaced))
}

struct Conn {
    node: Arc<Node>,
    who: Caller,
    out: Vec<Message>,
    mcpl: bool,
    version: Option<String>,
    grant: Option<Vec<String>>,
    ready: bool,
    pending: Option<(String, i64, std::time::Instant)>,
    closed: bool,
    /// Rooms as channels: the room ids registered with the host, the ones it has open, and the register request.
    channels: std::collections::BTreeMap<String, Value>,
    open: std::collections::HashSet<String>,
    registering: Option<String>,
    registered: bool,
}

async fn run(socket: WebSocket, node: Arc<Node>, who: Caller, mut replaced: oneshot::Receiver<()>) {
    let (mut sink, mut stream) = socket.split();
    let mut events = node.events.subscribe();
    let mut trust = node.trust.subscribe();
    let mut c = Conn {
        node,
        who,
        out: Vec::new(),
        mcpl: false,
        version: None,
        grant: None,
        ready: false,
        pending: None,
        closed: false,
        channels: Default::default(),
        open: Default::default(),
        registering: None,
        registered: false,
    };
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    while !c.closed {
        tokio::select! {
            m = stream.next() => match m {
                _ if !c.node.active(&c.who) => c.close(4001, "session expired or membership changed"),
                Some(Ok(Message::Text(t))) => c.frame(t.as_str()),
                Some(Ok(Message::Binary(b))) => c.frame(&String::from_utf8_lossy(&b)),
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            ev = events.recv() => match ev {
                _ if !c.node.active(&c.who) => c.close(4001, "session expired or membership changed"),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => { c.sync_channels(); c.flush_backlog() }
                Err(_) => break,
            },
            _ = trust.changed() => if !c.node.active(&c.who) { c.close(4001, "session expired or membership changed") },
            r = &mut replaced => match r {
                Ok(()) => c.close(4000, "replaced by a newer connection from the same agent"),
                Err(_) => break,
            },
            _ = tick.tick() => {
                if !c.node.active(&c.who) { c.close(4001, "session expired or membership changed"); }
                else if c.pending.as_ref().is_some_and(|(_, _, since)| since.elapsed() >= Duration::from_secs(60)) {
                    c.close(4008, "push acknowledgement timed out");
                }
            },
        }
        for frame in c.out.drain(..) {
            if !matches!(frame, Message::Close(_)) && !c.node.active(&c.who) {
                return;
            }
            if !matches!(tokio::time::timeout(Duration::from_secs(15), sink.send(frame)).await, Ok(Ok(()))) {
                return;
            }
        }
    }
}

impl Conn {
    fn send(&mut self, v: Value) {
        self.out.push(Message::Text(v.to_string().into()));
    }

    fn close(&mut self, code: u16, reason: &str) {
        self.out.push(Message::Close(Some(CloseFrame { code, reason: reason.to_string().into() })));
        self.closed = true;
    }

    fn frame(&mut self, text: &str) {
        if text.len() > MAX_WS_FRAME {
            return self.close(1009, "frame too large");
        }
        let lines: Vec<&str> = text.split('\n').filter(|l| !l.trim().is_empty()).collect();
        if lines.len() > MAX_RPCS_PER_FRAME {
            return self.send(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600,
                "message": format!("at most {MAX_RPCS_PER_FRAME} messages per frame") } }));
        }
        for line in lines {
            let msg: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => {
                    self.send(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } }));
                    continue;
                }
            };
            if !msg.is_object() {
                self.send(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "invalid request" } }));
                continue;
            }
            self.rpc(&msg);
            if self.closed {
                return;
            }
        }
    }

    fn rpc(&mut self, msg: &Value) {
        let id = match &msg["id"] {
            v @ (Value::String(_) | Value::Number(_)) => Some(v.clone()),
            _ => None,
        };
        let Some(method) = msg["method"].as_str() else {
            // A response to one of our push/event requests: the cursor moves only on an accepted push.
            let Some(id) = id else { return };
            let key = id.as_str().map(|s| s.to_string()).unwrap_or_else(|| id.to_string());
            if self.registering.as_deref() == Some(key.as_str()) {
                self.registering = None;
                self.registered = msg.get("error").is_none();
                tracing::info!("mcpl {}: channels/register {}", self.who.name, if self.registered { "accepted" } else { "refused" });
                if self.registered {
                    for (room, d) in &self.channels {
                        if d["initiallyOpen"] == json!(true) {
                            self.open.insert(room.clone());
                        }
                    }
                    self.flush_backlog();
                }
                return;
            }
            let Some((rpc, m, _)) = self.pending.as_ref() else { return };
            if rpc != &key { return; }
            let m = *m;
            let r = &msg["result"];
            let incoming = rpc.starts_with("incoming-");
            if incoming {
                if msg.get("error").is_some() {
                    return self.close(4008, "channel message declined; reconnect to retry");
                }
            } else if r["accepted"] != json!(true) && r["reason"] != json!("duplicate") {
                return self.close(4008, "push declined; reconnect to retry");
            }
            if self.node.store.advance_cursor(&self.who.key, m).is_err() {
                return self.close(1011, "cannot save delivery cursor");
            }
            self.pending = None;
            tracing::info!("mcpl {}: push of #{m} accepted", self.who.name);
            self.flush_backlog();
            return;
        };
        let reply = |c: &mut Conn, result: Value| {
            if let Some(id) = &id {
                c.send(json!({ "jsonrpc": "2.0", "id": id, "result": result }));
            }
        };
        let fail = |c: &mut Conn, code: i64, message: String| {
            if let Some(id) = &id {
                c.send(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }));
            }
        };
        let empty = json!({});
        let params = if msg["params"].is_object() { &msg["params"] } else { &empty };
        match method {
            "initialize" => {
                let host = &params["capabilities"]["experimental"]["mcpl"];
                self.mcpl = !host.is_null();
                self.version = host["version"].as_str().map(|s| s.chars().take(16).collect());
                tracing::info!("mcpl {}: initialize (mcpl {}, version {:?})", self.who.name, self.mcpl, self.version);
                let pv = params["protocolVersion"].as_str().map(|s| s.chars().take(32).collect::<String>());
                let mut caps = json!({ "tools": {} });
                if self.mcpl {
                    caps["experimental"] = json!({ "mcpl": manifest() });
                }
                reply(self, json!({
                    "protocolVersion": pv.unwrap_or_else(|| "2024-11-05".into()),
                    "capabilities": caps,
                    "serverInfo": { "name": "agentmail", "version": concat!("mailnode-", env!("CARGO_PKG_VERSION")) },
                    "instructions": format!("{INSTRUCTIONS} You are {} ({}).", self.who.name, self.who.sub),
                }));
            }
            "notifications/initialized" => {
                self.ready = true;
                if self.push_allowed() {
                    self.flush_backlog();
                }
            }
            "featureSets/update" => {
                let eff: Option<Vec<String>> = params["effectiveCapabilities"]
                    .as_array()
                    .map(|a| a.iter().take(64).map(|c| c.as_str().map(|s| s.to_string()).unwrap_or_else(|| c.to_string())).collect());
                let denied: Vec<String> = params["deniedCapabilities"]
                    .as_array()
                    .map(|a| a.iter().take(64).map(|c| c.as_str().map(|s| s.to_string()).unwrap_or_else(|| c.to_string())).collect())
                    .unwrap_or_default();
                if let Some(e) = &eff {
                    if e.iter().any(|c| denied.contains(c)) {
                        return fail(self, -32602, "a capability is in both effectiveCapabilities and deniedCapabilities".into());
                    }
                    self.grant = Some(e.iter().map(|c| c.chars().take(64).collect()).collect());
                }
                let missing: Vec<&str> = match &self.grant {
                    Some(g) => ["pushEvents", "tools"].into_iter().filter(|u| !capability_in(g, u)).collect(),
                    None => vec![],
                };
                let mut r = json!({ "accepted": true, "mode": if missing.is_empty() { "full" } else { "degraded" }, "notes": [] });
                if !missing.is_empty() {
                    r["unavailableFeatures"] =
                        json!([{ "featureSet": "mail", "missingCapabilities": missing, "effect": "degraded" }]);
                }
                tracing::info!("mcpl {}: featureSets/update grant {:?} -> {}", self.who.name, self.grant, r["mode"]);
                reply(self, r);
                if self.ready && self.push_allowed() {
                    self.flush_backlog();
                }
                if self.ready {
                    self.sync_channels();
                }
            }
            "channels/list" => {
                let list: Vec<Value> = self.channels.values().cloned().collect();
                reply(self, json!({ "channels": list }))
            }
            "channels/open" => {
                if !self.channels_allowed() {
                    return fail(self, -32017, "channels are not granted".into());
                }
                let cid = params["channelId"].as_str().map(String::from)
                    .or_else(|| params["address"]["room"].as_str().map(|r| format!("room:{r}")));
                let Some(room) = cid.as_deref().and_then(|c| c.strip_prefix("room:")).map(String::from) else {
                    return fail(self, -32023, "unknown channel".into());
                };
                let Some(d) = self.channels.get(&room).cloned() else { return fail(self, -32023, "unknown channel".into()) };
                self.open.insert(room.clone());
                let mut r = json!({ "channel": d });
                let limit = params["history"]["limit"].as_i64().unwrap_or(0).clamp(0, 100);
                if limit > 0 {
                    let q = Query { latest: Some(limit), ..Default::default() };
                    if let Ok((rows, more)) = self.node.store.thread_causal(&room, &self.who, &q, PUSH_TEXT as i64) {
                        r["history"] = json!(rows.iter().map(|row| self.incoming_message(row)).collect::<Vec<_>>());
                        r["historyTruncated"] = json!(more);
                    }
                }
                tracing::info!("mcpl {}: channels/open {room}", self.who.name);
                reply(self, r);
                self.flush_backlog();
            }
            "channels/close" => {
                let room = params["channelId"].as_str().and_then(|c| c.strip_prefix("room:")).unwrap_or("").to_string();
                let closed = self.open.remove(&room);
                reply(self, json!({ "closed": closed }))
            }
            "channels/publish" => {
                if !self.channels_allowed() {
                    return fail(self, -32017, "channels are not granted".into());
                }
                let room = params["channelId"].as_str().and_then(|c| c.strip_prefix("room:")).unwrap_or("").to_string();
                let text: Vec<&str> = params["content"].as_array().map(|a| a.iter().filter_map(|b| b["text"].as_str()).collect())
                    .unwrap_or_default();
                match self.room_send(&room, &text.join("\n"), None) {
                    Ok(row) => reply(self, json!({ "delivered": true, "messageId": row.id.to_string() })),
                    Err(e) => fail(self, -32603, e.message),
                }
            }
            "mcpl/manifest" => reply(self, manifest()),
            "ping" => reply(self, json!({})),
            "tools/list" => reply(self, json!({ "tools": tools() })),
            "tools/call" => {
                let name = params["name"].as_str().unwrap_or("").to_string();
                let args = if params["arguments"].is_object() { params["arguments"].clone() } else { json!({}) };
                match self.call_tool(&name, &args) {
                    Ok(text) => reply(self, json!({ "content": [{ "type": "text", "text": text }] })),
                    Err(e) => reply(self, json!({ "content": [{ "type": "text", "text": e.message }], "isError": true })),
                }
            }
            "resources/list" => reply(self, json!({ "resources": [] })),
            "prompts/list" => reply(self, json!({ "prompts": [] })),
            other => fail(self, -32601, format!("method not found: {}", other.chars().take(80).collect::<String>())),
        }
    }

    fn call_tool(&self, name: &str, args: &Value) -> Result<String, ApiError> {
        let cap = |v: &Value, d: i64| v.as_i64().unwrap_or(d).clamp(1, 100);
        let int = |v: &Value| v.as_i64().filter(|&x| x >= 0);
        let n = &self.node;
        let me = &self.who;
        match name {
            "send" => {
                let body = json!({ "to": args["to"], "thread": args["thread"], "text": args["text"], "mode": args.get("mode").cloned().unwrap_or(Value::Null) });
                let mut body = body;
                if body["mode"].is_null() {
                    body.as_object_mut().unwrap().remove("mode");
                }
                let p = n.post(&self.who, &body)?;
                let m = &p.row;
                if p.repeated {
                    return Ok(format!(
                        "Already sent as #{} to {} in thread \"{}\" at {}; this identical message wasn't sent again.",
                        m.id, m.recipient, m.thread, m.ts
                    ));
                }
                let reach = if p.reaches.is_empty() {
                    "no one who has used the mailbox matches that address yet".to_string()
                } else if p.reaches.len() > 12 {
                    format!("stored here for {} and {} more, copied to their nodes as they sync", p.reaches[..12].join(", "), p.reaches.len() - 12)
                } else {
                    format!("stored here for {}, copied to their nodes as they sync", p.reaches.join(", "))
                };
                Ok(format!("Sent #{} to {} in thread \"{}\"; {reach}.", m.id, m.recipient, m.thread))
            }
            "inbox" => {
                let limit = cap(&args["limit"], 20);
                let after = int(&args["after"]);
                let query = Query { to_me: true, after, before: int(&args["before"]), limit: Some(limit),
                    latest: after.is_none().then_some(limit), ..Default::default() };
                let (rows, _) = n.store.query(&query, me, 2000)?;
                if rows.is_empty() {
                    return Ok("No mail for you there.".into());
                }
                let older = rows[0].id;
                let text: Vec<String> = rows.iter().map(|r| self.node.fmt(r, 2000)).collect();
                Ok(format!("{}\n\n(older: inbox with before={older})", text.join("\n\n")))
            }
            "thread" => {
                let thread = args["thread"].as_str().map(|s| s.to_string()).unwrap_or_else(|| args["thread"].to_string());
                let page = Query { latest: Some(cap(&args["limit"], 30)), ..Default::default() };
                let (rows, _) = n.store.thread_causal(&thread, me, &page, 2000)?;
                if rows.is_empty() {
                    return Ok(format!("No thread named \"{}\".", thread.chars().take(80).collect::<String>()));
                }
                Ok(rows.iter().map(|r| self.node.fmt(r, 2000)).collect::<Vec<_>>().join("\n\n"))
            }
            "who" => {
                let rows = n.names_list(args["prefix"].as_str().unwrap_or(""))?;
                if rows.is_empty() {
                    return Ok("No one matches.".into());
                }
                Ok(rows
                    .iter()
                    .map(|r| {
                        let la = r["last_active"].as_str().unwrap_or("");
                        let la = if la == "1970-01-01T00:00:00.000Z" { "never".to_string() } else { format!("{}Z", &la[..la.len().min(16)]) };
                        format!("{} [{}] last active {la}", r["name"].as_str().unwrap_or(""), r["sub"].as_str().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
            "threads" => {
                let rows = n.store.thread_rows(me, 40)?;
                if rows.is_empty() {
                    return Ok("No threads yet.".into());
                }
                Ok(rows
                    .iter()
                    .map(|t| {
                        let ts = t["ts"].as_str().unwrap_or("");
                        format!("{} ({} messages; last #{} {}Z from {})", t["thread"].as_str().unwrap_or(""), t["n"], t["id"],
                            &ts[..ts.len().min(16)], t["sender"].as_str().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
            "search" => {
                let q: String = args["q"].as_str().unwrap_or("").trim().chars().take(200).collect();
                if q.is_empty() {
                    return Err(ApiError::new(400, "q is empty"));
                }
                let query = Query { q: Some(q), latest: Some(cap(&args["limit"], 20)), ..Default::default() };
                let (rows, _) = n.store.query(&query, me, 1000)?;
                if rows.is_empty() {
                    return Ok("Nothing matches.".into());
                }
                Ok(rows.iter().map(|r| self.node.fmt(r, 1000)).collect::<Vec<_>>().join("\n\n"))
            }
            "rooms" => {
                let rooms = n.rooms(me)?;
                if rooms.is_empty() {
                    return Ok("No rooms yet.".into());
                }
                Ok(rooms.iter().map(|r| {
                    let unread = r["unread"].as_i64().unwrap_or(0);
                    let mentions = r["unread_mentions"].as_i64().unwrap_or(0);
                    let topic = r["topic"].as_str().filter(|t| !t.is_empty()).map(|t| format!(" — {t}")).unwrap_or_default();
                    format!("{} [{}] {} unread{}; members: {}{topic}", r["id"].as_str().unwrap_or(""), r["kind"].as_str().unwrap_or(""),
                        unread, if mentions > 0 { format!(" ({mentions} mention you)") } else { String::new() },
                        r["members"].as_array().map(|m| m.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default())
                }).collect::<Vec<_>>().join("\n"))
            }
            "room_send" => {
                let room = args["room"].as_str().unwrap_or("").to_string();
                let reply_to = args["reply_to"].as_i64();
                let row = self.room_send(&room, args["text"].as_str().unwrap_or(""), reply_to)?;
                Ok(format!("Posted #{} in room {}.", row.id, room))
            }
            "get" => {
                let id = args["id"].as_i64().unwrap_or(-1);
                match n.store.get(id, me)? {
                    Some(r) => Ok(self.node.fmt(&r, 100_000)),
                    None => Err(ApiError::new(404, format!("no message #{}", args["id"].to_string().chars().take(20).collect::<String>()))),
                }
            }
            other => Err(ApiError::new(400, format!("no tool named {}", other.chars().take(80).collect::<String>()))),
        }
    }

    fn push_allowed(&self) -> bool {
        if !self.mcpl {
            return false; // plain MCP: tools only, never an MCPL frame
        }
        if let Some(g) = &self.grant {
            return capability_in(g, "pushEvents");
        }
        // MCPL 0.5: nothing capability-dependent until the host's featureSets/update arrives; older hosts keep the
        // older meaning.
        let v = self.version.clone().unwrap_or_else(|| "0.0".into());
        let mut it = v.split('.').map(|x| x.parse::<i64>().unwrap_or(0));
        let (major, minor) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
        !(major > 0 || minor >= 5)
    }

    fn channels_allowed(&self) -> bool {
        self.mcpl && self.grant.as_ref().is_some_and(|g| ROOM_CAPS.iter().all(|c| capability_in(g, c)))
    }

    /// Post as the connected agent in a room (the node signs: the agent's identity file is in identities_dir).
    fn room_send(&self, room: &str, text: &str, reply_to: Option<i64>) -> Result<Row, ApiError> {
        let members = self.node.members.read().unwrap().clone();
        let plan = self.node.room_plan(room, &self.who.name, None, &members, &self.node.agents())?;
        let mut body = json!({ "to": plan.to, "thread": room, "text": text, "mode": plan.mode.as_str(), "room": true });
        if let Some(id) = reply_to {
            let q = self.node.store.get(id, &self.who)?.ok_or_else(|| ApiError::new(404, format!("no message #{id}")))?;
            body["reply_to"] = json!(q.env_id);
        }
        Ok(self.node.post(&self.who, &body)?.row)
    }

    /// The channel descriptor of a room (from `Node::rooms`).
    fn descriptor(r: &Value) -> Value {
        let id = r["id"].as_str().unwrap_or("");
        let kind = r["kind"].as_str().unwrap_or("open");
        let label = match kind {
            "dm" => format!("@{} (dm)", r["label"].as_str().unwrap_or(id)),
            _ => format!("#{id}"),
        };
        json!({ "id": format!("room:{id}"), "type": "agentmail.room", "label": label, "direction": "bidirectional",
                "address": { "room": id },
                "metadata": { "kind": kind, "topic": r["topic"], "members": r["members"], "history": r["history"] },
                "initiallyOpen": r["member"] == json!(true),
                "capabilities": { "history": { "maxMessages": 100, "supportsBeforeMessage": false } } })
    }

    /// Register the agent's rooms as channels once the host grants channels; afterwards announce new ones.
    fn sync_channels(&mut self) {
        if !self.ready || !self.channels_allowed() || self.registering.is_some() {
            return;
        }
        let Ok(rooms) = self.node.rooms(&self.who) else { return };
        let now: std::collections::BTreeMap<String, Value> = rooms.iter()
            .map(|r| (r["id"].as_str().unwrap_or("").to_string(), Self::descriptor(r))).collect();
        if !self.registered {
            let rpc = format!("chreg-{}", mailcore::b64u(&mailcore::random_bytes::<6>()));
            self.channels = now;
            let list: Vec<Value> = self.channels.values().cloned().collect();
            self.send(json!({ "jsonrpc": "2.0", "id": rpc, "method": "channels/register", "params": { "channels": list } }));
            self.registering = Some(rpc);
            return;
        }
        let added: Vec<Value> = now.iter().filter(|(k, _)| !self.channels.contains_key(*k)).map(|(_, d)| d.clone()).collect();
        let updated: Vec<Value> = now.iter()
            .filter(|(k, d)| self.channels.get(*k).is_some_and(|old| old["metadata"] != d["metadata"])).map(|(_, d)| d.clone()).collect();
        if added.is_empty() && updated.is_empty() {
            return;
        }
        for d in &added {
            if d["initiallyOpen"] == json!(true) {
                if let Some(room) = d["address"]["room"].as_str() {
                    self.open.insert(room.to_string());
                }
            }
        }
        self.channels = now;
        let mut p = json!({});
        if !added.is_empty() { p["added"] = json!(added); }
        if !updated.is_empty() { p["updated"] = json!(updated); }
        self.send(json!({ "jsonrpc": "2.0", "method": "channels/changed", "params": p }));
    }

    /// How a row reaches this agent: (addressed by `to`, mentions it, a DM, a reply to its own message).
    fn address(&self, r: &Row) -> (bool, bool, bool, bool) {
        let addressed = mailcore::addr::addressed_to(&r.recipient, &[&self.who.name]);
        let mention = r.mentions_name(&self.who.name);
        let dm = mailcore::room::dm_pair(&r.thread).is_some();
        let reply = r.reply_to.as_deref().and_then(|e| self.node.store.by_env(e, &self.who).ok().flatten())
            .is_some_and(|q| q.sender_sub == self.who.sub);
        (addressed, mention, dm, reply)
    }

    /// MCPL RFC-001 tags and discord-parity wake flags.
    fn tags(&self, r: &Row) -> (Vec<&'static str>, Value) {
        let (addressed, mention, dm, reply) = self.address(r);
        let mut t = vec!["mail"];
        if mention { t.push("chat:mention"); }
        if reply { t.push("chat:reply"); }
        if dm { t.extend(["chat:dm", "chat:private"]); }
        if addressed || mention || dm || reply { t.push("chat:addressed"); } else { t.push("chat:ambient"); }
        if !dm && mailcore::room::dm_pair(&r.thread).is_none() { t.push("chat:group"); }
        t.push("chat:from-agent");
        if r.files != "[]" { t.push("chat:has-file"); }
        if r.kind == "event" { t.push("agentmail:membership"); }
        let meta = json!({ "addressed": addressed || mention || dm || reply, "isMention": mention || reply,
                           "isExplicitMention": mention, "isReplyToBot": reply, "isDM": dm, "isBot": false,
                           "room": r.thread, "kind": r.kind });
        (t, meta)
    }

    fn incoming_message(&self, r: &Row) -> Value {
        let (tags, meta) = self.tags(r);
        json!({ "channelId": format!("room:{}", r.thread), "messageId": r.id.to_string(),
                "author": { "id": r.sender_sub, "name": r.sender }, "timestamp": r.ts,
                "content": [{ "type": "text", "text": self.node.fmt(r, PUSH_TEXT) }], "metadata": meta, "tags": tags })
    }

    /// Deliver the next message after the cursor: on a channel the host has open, every room message (ambient
    /// context; mentions and DMs flagged so the host can wake); otherwise only mail addressed to the agent, an
    /// @mention, a DM or a reply to it, as push/event. Messages for neither are passed over.
    fn flush_backlog(&mut self) {
        if !self.ready || self.pending.is_some() { return; }
        let pushing = self.push_allowed();
        let incoming = self.registered && self.channels_allowed();
        if !pushing && !incoming { return; }
        loop {
            let rows = self.node.store.cursor(&self.who.key).and_then(|cursor| {
                let q = Query { after: Some(cursor), limit: Some(50), ..Default::default() };
                self.node.store.query(&q, &self.who, PUSH_TEXT as i64).map(|r| (cursor, r))
            });
            let (_, (rows, more)) = match rows {
                Ok(x) => x,
                Err(_) => return self.close(1011, "cannot read delivery cursor"),
            };
            for row in &rows {
                let own = row.sender_sub == self.who.sub;
                let (addressed, mention, dm, reply) = self.address(row);
                if !own && incoming && self.open.contains(&row.thread) {
                    return self.push_incoming(row);
                }
                if !own && pushing && (addressed || mention || dm || reply) {
                    return self.push(row);
                }
                if self.node.store.advance_cursor(&self.who.key, row.id).is_err() {
                    return self.close(1011, "cannot save delivery cursor");
                }
            }
            if !more { return; }
        }
    }

    fn push_incoming(&mut self, r: &Row) {
        let rpc = format!("incoming-{}-{}", r.id, mailcore::b64u(&mailcore::random_bytes::<6>()));
        self.send(json!({ "jsonrpc": "2.0", "id": rpc, "method": "channels/incoming",
                          "params": { "messages": [self.incoming_message(r)] } }));
        tracing::info!("mcpl {}: channels/incoming #{} in {}", self.who.name, r.id, r.thread);
        self.pending = Some((rpc, r.id, std::time::Instant::now()));
    }

    fn push(&mut self, r: &Row) {
        let event_id = format!("mail-{}", r.id);
        let rpc = format!("push-{event_id}-{}", mailcore::b64u(&mailcore::random_bytes::<6>()));
        let text = self.node.fmt(r, PUSH_TEXT);
        let (tags, meta) = self.tags(r);
        let mut o = json!({ "server": "agentmail", "messageId": r.id, "thread": r.thread, "from": r.sender,
                            "to": r.recipient, "verified": true, "attest": "agent",
                            "channelId": format!("room:{}", r.thread), "mcplChannelId": format!("room:{}", r.thread),
                            "authorId": r.sender_sub, "authorName": r.sender });
        if let (Some(o), Some(m)) = (o.as_object_mut(), meta.as_object()) {
            o.extend(m.clone());
        }
        self.send(json!({
            "jsonrpc": "2.0", "id": rpc, "method": "push/event",
            "params": { "featureSet": "mail", "eventId": event_id, "timestamp": now_ts(), "origin": o,
                        "tags": tags, "payload": { "content": [{ "type": "text", "text": text }] } },
        }));
        tracing::info!("mcpl {}: push/event {event_id}", self.who.name);
        self.pending = Some((rpc, r.id, std::time::Instant::now()));
    }
}

/// MCPL capability paths: a grant of "channels" covers "channels.incoming".
fn capability_in(grant: &[String], cap: &str) -> bool {
    grant.iter().any(|g| g == cap || cap.starts_with(&format!("{g}.")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_limits_count_only_live_receivers() {
        let sockets = Sockets::default();
        let mut live: Vec<_> = (0..MAX_SOCKETS).map(|i| sockets.register(&i.to_string()).unwrap()).collect();
        assert!(sockets.register("next").is_err());
        live.pop();
        let _next = sockets.register("next").unwrap();
        drop(live);
        let mut same: Vec<_> = (0..=MAX_SOCKETS_PER_SUB).map(|_| sockets.register("same").unwrap()).collect();
        assert!(same[0].try_recv().is_ok());
        assert!(same[1..].iter_mut().all(|s| matches!(s.try_recv(), Err(oneshot::error::TryRecvError::Empty))));
    }
}
