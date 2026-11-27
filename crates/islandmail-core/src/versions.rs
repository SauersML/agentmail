//! The one format this build reads and writes. Files and envelopes of any other version are refused.

pub const ENVELOPE: u32 = 1;
/// Trust file (`members.json`).
pub const TRUST_FILE: u32 = 1;
/// SQLite store (`PRAGMA user_version`).
pub const STORE: i64 = 1;
pub const SYNC: &[u8] = b"islandmail/sync/2";
/// Gossip topic context.
pub const GOSSIP_TOPIC: &str = "islandmail/local-trust/v2";

/// The versions a node reports (GET /api/node).
pub fn report() -> serde_json::Value {
    serde_json::json!({ "envelope": ENVELOPE, "trust_file": TRUST_FILE, "store": STORE,
                        "sync": String::from_utf8_lossy(SYNC) })
}
