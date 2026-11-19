//! mailnode: one per host. Replicates every envelope with the other member nodes over iroh and serves the old mail
//! server's API on localhost, so islandmail.py and Connectome hosts only change their base URL.
//!
//!   mailnode run CONFIG.json
//!   mailnode keygen SEED_FILE                       (prints the public key; the seed stays in the file, mode 600)
//!   mailnode pubkey SEED_FILE
//!   mailnode sign-members OPERATOR_SEED_FILE IN.json OUT.json
//!   mailnode mint-token HOME_SEED_FILE ISS NAME SUB TTL_SECS   (tests only: a throwaway home key, never Agaric's)

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
     mailnode sign-members OPERATOR_SEED_FILE IN.json OUT.json\n  mailnode mint-token HOME_SEED_FILE ISS NAME SUB TTL_SECS";

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
        Some("mint-token") if args.len() == 6 => {
            let home = config::read_seed(Path::new(&args[1]))?;
            let ttl: f64 = args[5].parse().context("TTL_SECS")?;
            let now = mailcore::now_millis() as f64 / 1000.0;
            let p = mailcore::Aid1Payload {
                v: 1,
                iss: args[2].clone(),
                sub: args[4].clone(),
                kind: "agent".into(),
                name: args[3].clone(),
                aud: "mail".into(),
                scopes: vec!["mail:use".into()],
                claims: None,
                iat: now.floor(),
                exp: (now + ttl).floor(),
                jti: None,
            };
            println!("{}", mailcore::token::mint(&home, &p));
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
    let seed = cfg.node_seed()?;
    let members = cfg.best_members()?;
    if !members.is_node(&seed.public()) {
        bail!("this node's key {} is not on the member list; add it and re-sign", fmt_key(&seed.public()));
    }
    let policy = cfg.policy()?;
    let identities = cfg.identities();
    let bridge = match &cfg.bridge {
        Some(b) => {
            let s = config::read_seed(&b.key_file)?;
            if !members.is_bridge(&s.public()) {
                bail!("bridge key {} is not under bridges in the member list", fmt_key(&s.public()));
            }
            Some((s, b.sub.clone()))
        }
        None => None,
    };
    tracing::info!(
        "node {} ; member list seq {} ({} members, {} nodes); {} local identities",
        fmt_key(&seed.public()),
        members.seq,
        members.members.len(),
        members.nodes.len(),
        identities.len()
    );
    let store = store::Store::open(&cfg.data_dir.join("mail.sqlite"))?;
    // Every member is a known name from the start (who / reaches), even before it has written anything here.
    for m in &members.members {
        store.seen(&m.name, &m.sub, 0)?;
    }
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
    let opts = node::Opts {
        identities,
        renamed: cfg.renamed.clone(),
        refuse_token_only: cfg.refuse_token_only,
        id_floor: cfg.id_floor,
        bridge,
        members_path: Some(cfg.adopted_members_path()),
        public_url: cfg.public_url.clone().unwrap_or_else(|| format!("http://{}", cfg.api_listen)),
    };
    let operator = mailcore::keys::parse_key(&cfg.operator_key)?;
    let node = Arc::new(node::Node::new(store, members, operator, policy, seed, opts, out_tx));
    let _net = net::start(&cfg, node.clone(), out_rx).await?;

    let state = api::AppState {
        node: node.clone(),
        streams: Arc::new(Mutex::new(Default::default())),
        sockets: Arc::new(Default::default()),
    };
    let listener = tokio::net::TcpListener::bind(&cfg.api_listen).await.with_context(|| format!("binding {}", cfg.api_listen))?;
    tracing::info!("compat API on http://{} ({} envelopes stored)", cfg.api_listen, node.store.count()?);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
