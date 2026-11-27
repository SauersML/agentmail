//! PASETO v4.public (https://github.com/paseto-standard/paseto-spec, "Version 4", purpose "public"): an Ed25519
//! signature over PAE(header, message, footer, implicit assertion). Only the signed purpose is implemented, and the
//! signature itself is ed25519-dalek's (`verify_strict`). Checked against the official test vectors below.
//!
//! A token is `v4.public.<base64url(message || 64-byte signature)>`, base64url without padding; footers are not used,
//! and a token with one is refused ('.' is not base64url). The version and purpose are fixed by the header, so there
//! is no algorithm field to confuse.

use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
use base64::Engine;

use crate::keys::{self, PublicKey, Seed};

pub const HEADER: &str = "v4.public.";
const SIG_LEN: usize = 64;

/// PASETO's base64url: no padding on output, padding refused on input, non-canonical trailing bits refused.
const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

fn le64(n: u64) -> [u8; 8] {
    // The spec clears the top bit so the value fits a signed 64-bit integer in every language.
    (n & 0x7fff_ffff_ffff_ffff).to_le_bytes()
}

/// Pre-Authentication Encoding: the piece count, then each piece's length and bytes, so no two lists of pieces encode
/// to the same bytes.
pub fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>());
    out.extend_from_slice(&le64(pieces.len() as u64));
    for p in pieces {
        out.extend_from_slice(&le64(p.len() as u64));
        out.extend_from_slice(p);
    }
    out
}

pub fn sign(seed: &Seed, message: &[u8], implicit: &[u8]) -> String {
    let sig = seed.sign(&pae(&[HEADER.as_bytes(), message, b"", implicit]));
    format!("{HEADER}{}", B64.encode([message, &sig[..]].concat()))
}

/// (message, signature) of a token without a footer (this implementation signs none and accepts none).
fn split(token: &str) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let body = token.strip_prefix(HEADER).ok_or("not a v4.public token")?;
    let mut raw = B64.decode(body).map_err(|_| "malformed token")?;
    if raw.len() < SIG_LEN {
        return Err("malformed token");
    }
    let sig = raw.split_off(raw.len() - SIG_LEN);
    Ok((raw, sig))
}

/// The message, unverified: only to read which key should verify it. Never act on it before `verify` succeeds.
pub fn peek(token: &str) -> Result<Vec<u8>, &'static str> {
    Ok(split(token)?.0)
}

/// Verifies a v4.public token with no footer against `key` and the implicit assertion. Returns the signed message.
pub fn verify(token: &str, key: &PublicKey, implicit: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (m, s) = split(token)?;
    if !keys::verify(key, &pae(&[HEADER.as_bytes(), &m, b"", implicit]), &s) {
        return Err("signature does not verify");
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Official vector 4-S-1 (paseto-standard/test-vectors v4.json): Ed25519 is deterministic, so signing must
    // reproduce the token exactly. 4-S-2 adds a footer, which this implementation refuses.
    const SEED: &str = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774";
    const PUBLIC: &str = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
    const PAYLOAD: &str = r#"{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}"#;
    const S1: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA";
    const S2: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    // 4-F-1 (a v4.local token), 4-F-3 (v3), 4-F-5 (padded base64).
    const F1: &str = "v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlNdGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
    const F3: &str = "v3.local.23e_2PiqpQBPvRFKzB0zHhjmxK3sKo2grFZRRLM-U7L0a8uHxuF9RlVz3Ic6WmdUUWTxCaYycwWV1yM8gKbZB2JhygDMKvHQ7eBf8GtF0r3K0Q_gF1PXOxcOgztak1eD1dPe9rLVMSgR0nHJXeIGYVuVrVoLWQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
    const F5: &str = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ==.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    #[test]
    fn official_vectors() {
        let seed = Seed::from_hex(SEED).unwrap();
        let pk: PublicKey = hex(PUBLIC).try_into().unwrap();
        assert_eq!(seed.public(), pk);
        assert_eq!(sign(&seed, PAYLOAD.as_bytes(), b""), S1);
        assert_eq!(verify(S1, &pk, b"").unwrap(), PAYLOAD.as_bytes());
        assert_eq!(peek(S1).unwrap(), PAYLOAD.as_bytes());
        // Wrong implicit assertion, a footer, or another version or purpose: refused.
        assert!(verify(S1, &pk, b"x").is_err());
        for tok in [S2, F1, F3, F5] {
            assert!(verify(tok, &pk, b"").is_err() && peek(tok).is_err(), "{tok}");
        }
        // One flipped bit anywhere in the body.
        let mut bad = S1.to_string().into_bytes();
        let i = HEADER.len() + 5;
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(verify(std::str::from_utf8(&bad).unwrap(), &pk, b"").is_err());
    }

    #[test]
    fn pae_matches_spec_examples() {
        assert_eq!(pae(&[]), b"\x00\x00\x00\x00\x00\x00\x00\x00");
        assert_eq!(pae(&[b""]), b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert_eq!(
            pae(&[b"test"]),
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"
        );
    }
}
