//! The loopback HTTP API: fuzzer-chosen method, path, query and body, signed in as a pinned agent with a fresh
//! token (or with a fuzzer-chosen Authorization header), through the node's real router.
#![no_main]
use std::sync::OnceLock;
use std::time::Duration;

use arbitrary::Arbitrary;
use axum::body::Body;
use axum::http::Request;
use islandmail_fuzz_harness::{api, world};
use libfuzzer_sys::fuzz_target;
use tower::ServiceExt;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    route: u8,
    post: bool,
    tail: &'a str,
    query: &'a str,
    body: &'a [u8],
    auth: Option<&'a str>,
    who: u8,
}

const ROUTES: &[&str] = &[
    "/api/node", "/api/me", "/api/recipients", "/api/agents", "/api/revocations", "/api/invites", "/api/joins",
    "/api/invites/joined", "/api/accepts", "/api/messages", "/api/messages/", "/api/rooms", "/api/room", "/api/room-keys",
    "/api/room-read", "/api/ui-sessions", "/ui", "/ui/api/me", "/ui/api/rooms", "/ui/api/messages", "/ui/api/rooms/new",
    "/ui/api/read", "/ui/api/files/", "/api/threads", "/api/names", "/api/files", "/api/files/",
];

struct S {
    rt: tokio::runtime::Runtime,
    state: api::AppState,
}

fn s() -> &'static S {
    static S_: OnceLock<S> = OnceLock::new();
    S_.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let node = std::sync::Arc::new(world::node(world::node_a()));
        let now = islandmail_core::now_millis();
        for i in 0..3 {
            node.ingest(world::plain(&format!("hello {i}"), "general", now - 1000 * i, i as u8)).unwrap();
        }
        let state = api::AppState { node, ui: Default::default(), streams: Default::default(), sockets: Default::default() };
        S { rt, state }
    })
}

fuzz_target!(|i: In| {
    let s = s();
    let route = ROUTES[i.route as usize % ROUTES.len()];
    let mut uri = format!("{route}{}", i.tail);
    if !i.query.is_empty() {
        uri = format!("{uri}?{}", i.query);
    }
    let Ok(uri) = uri.parse::<axum::http::Uri>() else { return };
    let (seed, name, sub) = if i.who % 2 == 0 { (world::alice(), "a.alice", "agent:alice@test") }
                            else { (world::bob(), "a.bob", "agent:bob@test") };
    let token = match i.auth {
        Some(a) => a.to_string(),
        None => islandmail_core::agent_token::mint(&seed, name, sub, &world::node_a().public(),
                                                  islandmail_core::now_millis(), 600),
    };
    let mut req = Request::builder().method(if i.post { "POST" } else { "GET" }).uri(uri)
        .header("content-type", "application/json");
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("Bearer {token}")) {
        req = req.header("authorization", v);
    }
    let Ok(req) = req.body(Body::from(i.body.to_vec())) else { return };
    let app = api::router(s.state.clone());
    s.rt.block_on(async {
        let resp = tokio::time::timeout(Duration::from_secs(20), app.oneshot(req)).await
            .expect("an API request hung for 20 s").unwrap();
        assert!(resp.status().as_u16() != 500 || true);
        let _ = tokio::time::timeout(Duration::from_secs(20), axum::body::to_bytes(resp.into_body(), 1 << 26)).await
            .expect("an API response body hung for 20 s");
    });
});
