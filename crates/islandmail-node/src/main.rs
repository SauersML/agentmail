//! Each host runs a direct peer and exposes a loopback API to its agents.
//!
//!   islandmail-node run CONFIG.json
//!   islandmail-node keygen SEED_FILE                       (prints the public key; the seed stays in the file, mode 600)
//!   islandmail-node pubkey SEED_FILE
//!   islandmail-node network-id
//!   islandmail-node agent-token IDENTITY_FILE NODE_KEY [TTL_SECS]   (a single-use agent token from an islandmail.py identity)
//!   islandmail-node revoke CONFIG.json NAME                (the running node revokes its certificates for NAME)

mod api;
mod config;
mod encryption_keys;
mod homes;
mod invite;
mod mcpl;
mod net;
mod node;
mod private_fs;
mod store;
mod ui;

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use islandmail_core::keys::fmt_key;

const USAGE: &str = "usage:\n  islandmail-node run CONFIG.json\n  islandmail-node keygen SEED_FILE\n  islandmail-node pubkey SEED_FILE\n  \
     islandmail-node network-id\n  islandmail-node agent-token IDENTITY_FILE NODE_KEY [TTL_SECS]\n  islandmail-node revoke CONFIG.json NAME";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("run") if args.len() == 2 => run(Path::new(&args[1])).await,
        Some("keygen") if args.len() == 2 => {
            let s = islandmail_core::keys::Seed::generate();
            config::write_seed(Path::new(&args[1]), &s)?;
            println!("{}", fmt_key(&s.public()));
            Ok(())
        }
        Some("pubkey") if args.len() == 2 => {
            println!("{}", fmt_key(&config::read_seed(Path::new(&args[1]))?.public()));
            Ok(())
        }
        Some("network-id") if args.len() == 1 => {
            println!("{}", islandmail_core::b64u(&islandmail_core::random_bytes::<32>()));
            Ok(())
        }
        Some("agent-token") if args.len() == 3 || args.len() == 4 => {
            // An islandmail.py identity file ({name, sub, seed}); refused if other users could read it.
            let path = Path::new(&args[1]);
            let v: serde_json::Value = serde_json::from_str(&config::read_private(path)?).context("identity file is not JSON")?;
            let (Some(name), Some(sub), Some(seed)) = (v["name"].as_str(), v["sub"].as_str(), v["seed"].as_str()) else {
                bail!("identity file needs name, sub and seed");
            };
            let seed = islandmail_core::keys::Seed::from_hex(seed)?;
            let node = islandmail_core::keys::parse_key(&args[2]).context("NODE_KEY (GET /api/node gives it)")?;
            let ttl: i64 = match args.get(3) {
                Some(t) => t.parse().context("TTL_SECS")?,
                None => islandmail_core::agent_token::DEFAULT_LIFETIME_S,
            };
            if !(1..=islandmail_core::agent_token::MAX_LIFETIME_S).contains(&ttl) {
                bail!("TTL_SECS must be 1 to {}", islandmail_core::agent_token::MAX_LIFETIME_S);
            }
            println!("{}", islandmail_core::agent_token::mint(&seed, name, sub, &node, islandmail_core::now_millis(), ttl));
            Ok(())
        }
        Some("revoke") if args.len() == 3 => revoke(Path::new(&args[1]), &args[2]),
        Some("--help" | "-h" | "help") => {
            println!("islandmail-node {}: Islandmail node (see README.md)\n{USAGE}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => usage(),
    }
}

/// Asks the running node (whose key file this host owner can read) to revoke its certificates for `name`.
fn revoke(path: &Path, name: &str) -> Result<()> {
    use std::io::{Read, Write};
    let cfg = config::Config::load(path)?;
    let seed = config::read_seed(&cfg.node_key_file)?;
    let ts = islandmail_core::now_ts();
    let st = node::revoke_statement(name, &fmt_key(&seed.public()), &ts);
    let body = serde_json::json!({ "name": name, "ts": ts, "sig": islandmail_core::b64u(&seed.sign(st.as_bytes())) }).to_string();
    let addr = cfg.api_listen.replace("localhost:", "127.0.0.1:");
    let mut conn = std::net::TcpStream::connect(&addr).with_context(|| format!("connecting to the node at {addr} (is it running?)"))?;
    write!(conn, "POST /api/revocations HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
                  Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    let mut resp = String::new();
    conn.read_to_string(&mut resp)?;
    let (head, json) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    anyhow::ensure!(head.starts_with("HTTP/1.1 200"), "node refused: {}", json.trim());
    let v: serde_json::Value = serde_json::from_str(json.trim()).context("node answer is not JSON")?;
    let revoked = v["revoked"].as_array().cloned().unwrap_or_default();
    if revoked.is_empty() {
        println!("this node has no live certificate for {name}");
    }
    for r in revoked {
        println!("revoked {} {}", r["name"].as_str().unwrap_or(""), r["key"].as_str().unwrap_or(""));
    }
    Ok(())
}

async fn run(path: &Path) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "islandmail_node=info,iroh=warn,iroh_gossip=warn".into()),
        )
        .init();
    let cfg = config::Config::load(path)?;
    let listen: std::net::SocketAddr = match cfg.api_listen.strip_prefix("localhost:") {
        Some(port) => ([127, 0, 0, 1], port.parse::<u16>().context("invalid api_listen port")?).into(),
        None => cfg.api_listen.parse().context("api_listen needs a loopback socket address")?,
    };
    anyhow::ensure!(listen.ip().is_loopback(), "api_listen must be a loopback address");
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
    private_fs::create_dir(&cfg.data_dir)?;
    anyhow::ensure!(cfg.data_dir.symlink_metadata()?.is_dir(), "data_dir must be a directory");
    private_fs::restrict_dir(&cfg.data_dir)?;
    let seed = cfg.node_seed()?;
    let members = cfg.members()?;
    if !members.is_node(&seed.public()) {
        bail!("this node's key {} is not on the member list; add it to this host's trust file", fmt_key(&seed.public()));
    }
    let held_only = cfg.certify == config::Certify::IdentitiesDir;
    anyhow::ensure!(!held_only || cfg.identities_dir.is_some(), "\"certify\": \"identities_dir\" needs identities_dir");
    let identities = cfg.identities();
    tracing::info!(
        "node {} ; member list seq {} ({} members, {} nodes); {} local identities",
        fmt_key(&seed.public()),
        members.seq,
        members.members.len(),
        members.nodes.len(),
        identities.len()
    );
    let store = store::Store::open(&cfg.data_dir.join("mail.sqlite"))?;
    let (out_tx, out_rx) = tokio::sync::mpsc::channel(32);
    let opts = node::Opts {
        identities,
        held_only,
        public_url: cfg.public_url.clone().unwrap_or_else(|| format!("http://{}", cfg.api_listen)),
        members_file: Some(cfg.members_file.clone()),
        relay: cfg.relay.clone(),
    };
    store.bind_roster(&seed.public(), &members)?;
    let node = Arc::new(node::Node::new(store, members, seed, opts, out_tx));
    node.certify_identities();
    let net = net::start(&cfg, node.clone(), out_rx).await?;

    let state = api::AppState {
        node: node.clone(),
        ui: Arc::new(Default::default()),
        streams: Arc::new(Mutex::new(Default::default())),
        sockets: Arc::new(Default::default()),
    };
    tracing::info!("HTTP API on http://{} ({} envelopes stored)", cfg.api_listen, node.store.count()?);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    net.shutdown().await
}
