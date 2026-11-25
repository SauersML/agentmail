//! Agent mail core: the wire envelope, its encryption and signatures, agent tokens (PASETO v4.public, signed by the
//! agent's own key) and the legacy aid1 home tokens, the signed member list, addressing rules and the per-thread order. No I/O: `mailnode` does storage and networking.

pub mod addr;
pub mod agent_token;
pub mod crypto;
pub mod envelope;
pub mod keys;
pub mod members;
pub mod order;
pub mod paseto;
pub mod token;

pub use envelope::{Attest, Body, Envelope, Mode, Verified};
pub use members::{Member, MemberList, NodeEntry};
pub use token::{Aid1Payload, TokenPolicy};

use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
use base64::Engine;

const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// base64url without padding (decoding accepts padding too, like the old server's atob-based decoder).
pub fn b64u(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    B64.decode(s.as_bytes()).ok()
}

/// Envelope timestamps are always this shape (UTC, milliseconds, `Z`), so string order is time order.
pub fn ts_from_millis(ms: i64) -> String {
    let t = chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default();
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn now_ts() -> String {
    ts_from_millis(now_millis())
}

/// Parses a canonical envelope timestamp; anything not exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` is refused.
pub fn parse_ts(ts: &str) -> Option<i64> {
    if ts.len() != 24 || !ts.ends_with('Z') {
        return None;
    }
    let t = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    let ms = t.timestamp_millis();
    (ts_from_millis(ms) == ts).then_some(ms)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}
