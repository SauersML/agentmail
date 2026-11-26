//! Every format version in one table. From v0.1.0 on these are a compatibility promise: a new build reads what an
//! older one wrote (stores, trust files and configs are migrated forward at start, see the node's `migrate`
//! module), and nodes of different builds agree on the newest sync protocol both speak. To change a format, add the
//! new version here (and its migration step), never remove an old one that a release could still have written.

/// Envelopes this build writes.
pub const ENVELOPE: u32 = 1;
/// Envelopes this build reads (every version a release has written).
pub const ENVELOPE_READS: &[u32] = &[1];

/// Trust file (`members.json`) version this build writes; older ones are migrated at start.
pub const TRUST_FILE: u32 = 1;
/// Node config (`config.json`) version; a config without `v` is version 1.
pub const CONFIG: u32 = 1;
/// SQLite store format (`PRAGMA user_version`); older stores are migrated in place at start.
pub const STORE: i64 = 1;

/// Sync protocols this build speaks, newest first. A node offers all of them and the peers settle on the newest
/// both speak.
pub const SYNC: &[&[u8]] = &[b"islandmail/sync/2"];
/// Never changes: peers that share no sync protocol tell each other what they speak here, so the one that is behind
/// can say "please upgrade".
pub const HELLO_ALPN: &[u8] = b"islandmail/hello";
/// Gossip topic context (fixed: gossip carries versioned envelopes, so one topic serves every build).
pub const GOSSIP_TOPIC: &str = "islandmail/local-trust/v2";

/// The versions a node reports (GET /api/node and the hello exchange).
pub fn report() -> serde_json::Value {
    serde_json::json!({
        "envelope": ENVELOPE, "envelope_reads": ENVELOPE_READS, "trust_file": TRUST_FILE, "config": CONFIG,
        "store": STORE, "sync": SYNC.iter().map(|a| String::from_utf8_lossy(a)).collect::<Vec<_>>(),
    })
}

/// A version newer than this build knows: what to tell the operator.
pub fn too_new(what: &str, found: impl std::fmt::Display, newest: impl std::fmt::Display) -> String {
    format!("{what} version {found} was written by a newer Islandmail build (this one knows up to {newest}): upgrade islandmail-node")
}
