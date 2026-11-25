//! mailnode: one per host. Replicates every envelope with the other member nodes over iroh and serves the old mail
//! server's API on localhost, so islandmail.py and Connectome hosts only change their base URL.
//!
//!   mailnode run CONFIG.json
//!   mailnode keygen SEED_FILE                       (prints the public key; the seed stays in the file, mode 600)
//!   mailnode pubkey SEED_FILE
//!   mailnode sign-members OPERATOR_SEED_FILE IN.json OUT.json
//!   mailnode agent-token IDENTITY_FILE NODE_KEY [TTL_SECS]   (a single-use agent token from an islandmail.py identity)

mod api;
mod config;
mod mcpl;
mod net;
mod node;
mod store;

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use mailcore::keys::fmt_key;
use mailcore::MemberList;

const USAGE: &str = "usage:\n  mailnode run CONFIG.json\n  mailnode keygen SEED_FILE\n  mailnode pubkey SEED_FILE\n  \
     mailnode sign-members OPERATOR_SEED_FILE IN.json OUT.json\n  mailnode agent-token IDENTITY_FILE NODE_KEY [TTL_SECS]";

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
            let s = mailcore::keys::Seed::generate();
            config::write_seed(Path::new(&args[1]), &s)?;
            println!("{}", fmt_key(&s.public()));
            Ok(())
        }
        Some("pubkey") if args.len() == 2 => {
            println!("{}", fmt_key(&config::read_seed(Path::new(&args[1]))?.public()));
            Ok(())
        }
        Some("sign-members") if args.len() == 4 => {
            let op = config::read_seed(Path::new(&args[1]))?;
            let raw = std::fs::read_to_string(&args[2])?;
            let mut list: MemberList = serde_json::from_str(&raw).context("member list JSON")?;
            if list.issued.is_empty() {
                list.issued = mailcore::now_ts();
            }
            list.sign(&op);
            list.verify(&op.public())?;
            std::fs::write(&args[3], serde_json::to_string_pretty(&list)?)?;
            println!("signed member list seq {} by {}", list.seq, list.operator);
            Ok(())
        }
        Some("agent-token") if args.len() == 3 || args.len() == 4 => {
            // An islandmail.py identity file ({name, sub, seed}); refused if other users could read it.
            let path = Path::new(&args[1]);
            config::check_private(path)?;
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?).context("identity file is not JSON")?;
            let (Some(name), Some(sub), Some(seed)) = (v["name"].as_str(), v["sub"].as_str(), v["seed"].as_str()) else {
                bail!("identity file needs name, sub and seed");
            };
            let seed = mailcore::keys::Seed::from_hex(seed)?;
            let node = mailcore::keys::parse_key(&args[2]).context("NODE_KEY (GET /api/node gives it)")?;
            let ttl: i64 = match args.get(3) {
                Some(t) => t.parse().context("TTL_SECS")?,
                None => mailcore::agent_token::DEFAULT_LIFETIME_S,
            };
            if !(1..=mailcore::agent_token::MAX_LIFETIME_S).contains(&ttl) {
                bail!("TTL_SECS must be 1 to {}", mailcore::agent_token::MAX_LIFETIME_S);
            }
            println!("{}", mailcore::agent_token::mint(&seed, name, sub, &node, mailcore::now_millis(), ttl));
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            println!("mailnode {}: peer-to-peer agent mail node (see README.md)\n{USAGE}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => usage(),
    }
}

async fn run(path: &Path) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mailnode=info,iroh=warn,iroh_gossip=warn".into()),
        )
        .init();
    let cfg = config::Config::load(path)?;
    std::fs::create_dir_all(&cfg.data_dir)?;
    private_data(&cfg.data_dir)?;
    let seed = cfg.node_seed()?;
    let members = cfg.best_members()?;
    if !members.is_node(&seed.public()) {
        bail!("this node's key {} is not on the member list; add it and re-sign", fmt_key(&seed.public()));
    }
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
    private_data(&cfg.data_dir)?; // again, for a database the open just created
    // Every member is a known name from the start (who / reaches), even before it has written anything here.
    for m in &members.members {
        store.seen(&m.name, &m.sub, 0)?;
    }
    // ...and everyone who has written, including through the old server (reachable via the bridge).
    store.names_from_messages()?;
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
    let opts = node::Opts {
        identities,
        renamed: cfg.renamed.clone(),
        members_path: Some(cfg.adopted_members_path()),
        public_url: cfg.public_url.clone().unwrap_or_else(|| format!("http://{}", cfg.api_listen)),
    };
    let operator = mailcore::keys::parse_key(&cfg.operator_key)?;
    let node = Arc::new(node::Node::new(store, members, operator, seed, opts, out_tx));
    let _net = net::start(&cfg, node.clone(), out_rx).await?;

    let state = api::AppState {
        node: node.clone(),
        streams: Arc::new(Mutex::new(Default::default())),
        sockets: Arc::new(Default::default()),
    };
    // The API serves decrypted mail to any member's valid token: it is for this host's own processes only.
    let loopback = match cfg.api_listen.parse::<std::net::SocketAddr>() {
        Ok(a) => a.ip().is_loopback(),
        Err(_) => cfg.api_listen.starts_with("localhost:"),
    };
    if !loopback {
        bail!("api_listen {} is not a loopback address; the compat API must not be reachable from other hosts", cfg.api_listen);
    }
    let listener = tokio::net::TcpListener::bind(&cfg.api_listen).await.with_context(|| format!("binding {}", cfg.api_listen))?;
    tracing::info!("compat API on http://{} ({} envelopes stored)", cfg.api_listen, node.store.count()?);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// The store holds decrypted mail (members mode, and private mail for the identities this node holds): only this
/// user may read it. SQLite gives its -wal and -shm files the database file's mode.
fn private_data(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("making {} private", dir.display()))?;
    for f in ["mail.sqlite", "mail.sqlite-wal", "mail.sqlite-shm"] {
        let p = dir.join(f);
        if p.exists() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
