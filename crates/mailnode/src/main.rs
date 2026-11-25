//! mailnode: one per host. Certifies this host's agents, replicates every envelope, certificate and revocation with
//! the other member nodes over iroh, and serves the mail API on localhost for islandmail.py and Connectome hosts.
//!
//!   mailnode run CONFIG
//!   mailnode keygen SEED_FILE                            (prints the public key; the seed stays in the file, mode 600)
//!   mailnode pubkey SEED_FILE
//!   mailnode sign-members OPERATOR_SEED IN OUT
//!   mailnode agent-token IDENTITY_FILE NODE_KEY [TTL]     (a single-use agent token from an identity file)
//!   mailnode revoke CONFIG NAME                           (revokes this node's certificates for NAME; node running)

mod api;
mod config;
mod mcpl;
mod net;
mod node;
mod store;
#[cfg(test)]
mod testutil;

use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use mailcore::keys::fmt_key;
use mailcore::{KnownCerts, MemberList, Revocation};

const USAGE: &str = "usage:
  mailnode run CONFIG                              run the node (CONFIG: JSON; only operator_key is required)
  mailnode keygen SEED_FILE                        make a key (seed file mode 600); prints the public key
  mailnode pubkey SEED_FILE                        print a seed file's public key
  mailnode sign-members OPERATOR_SEED IN OUT       sign the member list IN with the operator key, write OUT
  mailnode agent-token IDENTITY_FILE NODE_KEY [TTL]
                                                   print a single-use agent token for that node (TTL seconds,
                                                   default 3600); the identity file needs name and seed
  mailnode revoke CONFIG NAME                      revoke every certificate this node issued for NAME (the node
                                                   must be running; it stores and passes on the revocations)";

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
            let raw = std::fs::read_to_string(&args[2]).with_context(|| format!("reading {}", args[2]))?;
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
            // An identity file ({name, seed, …}); refused if other users could read it.
            let path = Path::new(&args[1]);
            config::check_private(path)?;
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path)?).context("identity file is not JSON")?;
            let (Some(name), Some(seed)) = (v["name"].as_str(), v["seed"].as_str()) else {
                bail!("identity file needs name and seed");
            };
            let seed = mailcore::keys::Seed::from_hex(seed)?;
            let node = mailcore::keys::parse_key(&args[2]).context("NODE_KEY (GET /api/node gives it)")?;
            let ttl: i64 = match args.get(3) {
                Some(t) => t.parse().context("TTL")?,
                None => mailcore::agent_token::DEFAULT_LIFETIME_S,
            };
            if !(1..=mailcore::agent_token::MAX_LIFETIME_S).contains(&ttl) {
                bail!("TTL must be 1 to {} seconds", mailcore::agent_token::MAX_LIFETIME_S);
            }
            println!("{}", mailcore::agent_token::mint(&seed, name, &node, mailcore::now_millis(), ttl));
            Ok(())
        }
        Some("revoke") if args.len() == 3 => revoke(Path::new(&args[1]), &args[2]),
        Some("--help" | "-h" | "help") => {
            println!("mailnode {}: peer-to-peer agent mail node\n{USAGE}", env!("CARGO_PKG_VERSION"));
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
    // The API serves decrypted mail to any agent this node certified: it is for this host's own processes only.
    let loopback = match cfg.api_listen.parse::<std::net::SocketAddr>() {
        Ok(a) => a.ip().is_loopback(),
        Err(_) => cfg.api_listen.starts_with("localhost:"),
    };
    if !loopback {
        bail!("api_listen {} is not a loopback address; the API must not be reachable from other hosts", cfg.api_listen);
    }
    std::fs::create_dir_all(&cfg.data_dir)?;
    private_data(&cfg.data_dir)?;
    let seed = cfg.node_seed()?;
    let members = cfg.best_members()?;
    let Some(me) = members.node_by_key(&seed.public()).cloned() else {
        bail!("this node's key {} is not on the member list; add it and re-sign", fmt_key(&seed.public()));
    };
    let identities = cfg.identities();
    tracing::info!(
        "node {} ({:?}, names {}); member list seq {} ({} nodes); {} identities held",
        fmt_key(&seed.public()),
        me.name,
        me.namespace().join(", "),
        members.seq,
        members.nodes.len(),
        identities.len()
    );
    let store = store::Store::open(&cfg.data_dir.join("mail.sqlite"))?;
    private_data(&cfg.data_dir)?; // again, for a database the open just created
    store.names_from_messages()?;
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
    let opts = node::Opts {
        identities,
        members_path: Some(cfg.adopted_members_path()),
        public_url: cfg.public_url.clone().unwrap_or_else(|| format!("http://{}", cfg.api_listen)),
    };
    let operator = mailcore::keys::parse_key(&cfg.operator_key).context("operator_key")?;
    let node = Arc::new(node::Node::new(store, members, operator, seed, opts, out_tx));
    let issued = node.certify_held();
    if !issued.is_empty() {
        tracing::info!("certified {} held identities", issued.len());
    }
    let _net = net::start(&cfg, node.clone(), out_rx).await?;

    let state = api::AppState {
        node: node.clone(),
        streams: Arc::new(Mutex::new(Default::default())),
        sockets: Arc::new(Default::default()),
    };
    let listener =
        tokio::net::TcpListener::bind(&cfg.api_listen).await.with_context(|| format!("binding {}", cfg.api_listen))?;
    tracing::info!("API on http://{} ({} envelopes stored)", cfg.api_listen, node.store.count()?);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// `mailnode revoke CONFIG NAME`: one revocation per unrevoked certificate this node issued for NAME, each handed to
/// the running node (POST /api/revocations), which stores it and passes it on.
fn revoke(path: &Path, name: &str) -> Result<()> {
    let cfg = config::Config::load(path)?;
    let seed = config::read_seed(&cfg.node_key_file)?;
    let me = fmt_key(&seed.public());
    let db = cfg.data_dir.join("mail.sqlite");
    let store = store::Store::open_read_only(&db)?;
    let certs: Vec<_> =
        store.certs_for(name).into_iter().filter(|c| c.node == me && !store.revoked(c)).collect();
    drop(store);
    if certs.is_empty() {
        bail!("{name} has no unrevoked certificate from this node");
    }
    for c in certs {
        let r = Revocation::sign(&seed, &c.name, &c.agent_key()?, &mailcore::now_ts());
        let (status, body) = post_json(&cfg.api_listen, "/api/revocations", &serde_json::to_string(&r)?)
            .with_context(|| format!("handing the revocation to the node at http://{} (is it running?)", cfg.api_listen))?;
        if status != 200 {
            bail!("the node refused the revocation of {} (key {}): {status} {body}", c.name, c.key);
        }
        println!("revoked {} (key {}, certified {})", c.name, c.key, c.issued);
    }
    Ok(())
}

/// A minimal HTTP/1.1 POST of JSON to this host's own node (`addr` is api_listen, a loopback address).
fn post_json(addr: &str, path: &str, body: &str) -> Result<(u16, String)> {
    let mut s = std::net::TcpStream::connect(addr).with_context(|| format!("connecting to {addr}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .context("the node's answer is not HTTP")?;
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.trim().to_string()).unwrap_or_default();
    Ok((status, body))
}

/// The store holds decrypted mail (members mode, and private mail addressed to this host's agents): only this
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
