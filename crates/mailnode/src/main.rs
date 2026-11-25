//! Each host runs a direct peer and exposes a loopback API to its agents.
//!
//!   mailnode run CONFIG.json
//!   mailnode keygen SEED_FILE                       (prints the public key; the seed stays in the file, mode 600)
//!   mailnode pubkey SEED_FILE
//!   mailnode network-id
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

const USAGE: &str = "usage:\n  mailnode run CONFIG.json\n  mailnode keygen SEED_FILE\n  mailnode pubkey SEED_FILE\n  \
     mailnode network-id\n  mailnode agent-token IDENTITY_FILE NODE_KEY [TTL_SECS]";

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
        Some("network-id") if args.len() == 1 => {
            println!("{}", mailcore::b64u(&mailcore::random_bytes::<32>()));
            Ok(())
        }
        Some("agent-token") if args.len() == 3 || args.len() == 4 => {
            // An islandmail.py identity file ({name, sub, seed}); refused if other users could read it.
            let path = Path::new(&args[1]);
            let v: serde_json::Value = serde_json::from_str(&config::read_private(path)?).context("identity file is not JSON")?;
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
    let listen: std::net::SocketAddr = match cfg.api_listen.strip_prefix("localhost:") {
        Some(port) => ([127, 0, 0, 1], port.parse::<u16>().context("invalid api_listen port")?).into(),
        None => cfg.api_listen.parse().context("api_listen needs a loopback socket address")?,
    };
    anyhow::ensure!(listen.ip().is_loopback(), "api_listen must be a loopback address");
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&cfg.data_dir)?;
    anyhow::ensure!(cfg.data_dir.symlink_metadata()?.is_dir(), "data_dir must be a directory");
    std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o700))?;
    let seed = cfg.node_seed()?;
    let members = cfg.members()?;
    if !members.is_node(&seed.public()) {
        bail!("this node's key {} is not on the member list; add it to this host's trust file", fmt_key(&seed.public()));
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
    let (out_tx, out_rx) = tokio::sync::mpsc::channel(32);
    let opts = node::Opts {
        identities,
        public_url: cfg.public_url.clone().unwrap_or_else(|| format!("http://{}", cfg.api_listen)),
    };
    store.bind_roster(&seed.public(), &members)?;
    let node = Arc::new(node::Node::new(store, members, seed, opts, out_tx));
    let _net = net::start(&cfg, node.clone(), out_rx).await?;

    let state = api::AppState {
        node: node.clone(),
        streams: Arc::new(Mutex::new(Default::default())),
        sockets: Arc::new(Default::default()),
    };
    tracing::info!("compat API on http://{} ({} envelopes stored)", cfg.api_listen, node.store.count()?);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
