//! Islandmail core: the wire envelope, its encryption and signatures, agent tokens (PASETO v4.public, signed by the
//! agent's own key) and local trust pins, addressing rules and the per-thread order. No I/O: `islandmail-node` does storage and networking.

pub mod addr;
pub mod agent_token;
pub mod cert;
pub mod crypto;
pub mod envelope;
pub mod keys;
pub mod members;
pub mod node_key;
pub mod order;
pub mod paseto;
pub mod room;
pub mod versions;

pub use envelope::{Attest, Body, Envelope, Mode, Verified};
pub use cert::{Cert, Revocation};
pub use members::{Agent, Member, MemberList, NodeEntry};

use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
use base64::Engine;

const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// base64url without padding (decoding accepts padding too).
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

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub const SHORT_ID: usize = 8;

/// A message's shared id: its envelope hash (64 lowercase hex) in lowercase base32 (RFC 4648 alphabet, no padding),
/// the same on every node. People see the first `SHORT_ID` characters; any unique prefix names the message.
pub fn b32_id(env_hex: &str) -> String {
    let bytes: Vec<u8> = (0..env_hex.len() / 2).filter_map(|i| u8::from_str_radix(env_hex.get(2 * i..2 * i + 2)?, 16).ok()).collect();
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn short_id(env_hex: &str) -> String {
    b32_id(env_hex).chars().take(SHORT_ID).collect()
}

/// The inclusive range of envelope hashes (hex) whose base32 id starts with `prefix`; None if no id can.
pub fn id_prefix_range(prefix: &str) -> Option<(String, String)> {
    if prefix.is_empty() || prefix.len() > 52 {
        return None;
    }
    let mut bits = Vec::with_capacity(260);
    for c in prefix.bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_lowercase())?;
        bits.extend((0..5).rev().map(|i| (v >> i) & 1 == 1));
    }
    // A full 52-character id spends only one bit of its last character: any other bit set there names no id.
    if bits[256.min(bits.len())..].contains(&true) {
        return None;
    }
    bits.truncate(256);
    let hex = |fill: bool| {
        let mut all = bits.clone();
        all.resize(256, fill);
        all.chunks(4).map(|n| char::from_digit(n.iter().fold(0, |a, &b| a * 2 + u32::from(b)), 16).unwrap()).collect::<String>()
    };
    Some((hex(false), hex(true)))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}
