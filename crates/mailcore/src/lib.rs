//! Agent mail core: the wire envelope, its encryption and signatures, agent tokens (PASETO v4.public, signed by the
//! agent's own key) and the signed member list, addressing rules and the per-thread order. No I/O: `mailnode` does storage and networking.

pub mod addr;
pub mod agent_token;
pub mod crypto;
pub mod envelope;
pub mod keys;
pub mod members;
pub mod order;
pub mod paseto;

pub use envelope::{Attest, Body, Envelope, Mode, Verified};
pub use members::{Member, MemberList, NodeEntry};

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
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    t.format(time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"))
        .expect("UTC timestamp")
}

pub fn now_millis() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

pub fn now_ts() -> String {
    ts_from_millis(now_millis())
}

/// Parses a canonical envelope timestamp; anything not exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` is refused.
pub fn parse_ts(ts: &str) -> Option<i64> {
    if ts.len() != 24 || !ts.ends_with('Z') {
        return None;
    }
    let ms = parse_rfc3339(ts)?;
    (ts_from_millis(ms) == ts).then_some(ms)
}

fn parse_rfc3339(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some(t.unix_timestamp_nanos().div_euclid(1_000_000) as i64)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}
