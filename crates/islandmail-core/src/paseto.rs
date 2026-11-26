//! PASETO v4.public (https://github.com/paseto-standard/paseto-spec, "Version 4", purpose "public"): an Ed25519
//! signature over PAE(header, message, footer, implicit assertion). Only the signed purpose is implemented, and the
//! signature itself is ed25519-dalek's (`verify_strict`). Checked against the official test vectors below.
//!
//! A token is `v4.public.<base64url(message || 64-byte signature)>[.<base64url(footer)>]`, base64url without padding.
//! The version and purpose are fixed by the header, so there is no algorithm field to confuse.

use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
use base64::Engine;
use subtle::ConstantTimeEq;

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

pub fn sign(seed: &Seed, message: &[u8], footer: &[u8], implicit: &[u8]) -> String {
    let sig = seed.sign(&pae(&[HEADER.as_bytes(), message, footer, implicit]));
    let mut body = Vec::with_capacity(message.len() + SIG_LEN);
    body.extend_from_slice(message);
    body.extend_from_slice(&sig);
    let mut t = format!("{HEADER}{}", B64.encode(&body));
    if !footer.is_empty() {
        t.push('.');
        t.push_str(&B64.encode(footer));
    }
    t
}

/// The footer of a token, unverified (for picking a key before verifying). Empty when there is none.
pub fn footer(token: &str) -> Result<Vec<u8>, &'static str> {
    let rest = token.strip_prefix(HEADER).ok_or("not a v4.public token")?;
    match rest.split_once('.') {
        None => Ok(vec![]),
        Some((_, f)) if !f.is_empty() && !f.contains('.') => B64.decode(f).map_err(|_| "malformed footer"),
        Some(_) => Err("malformed token"),
    }
}

/// The message, unverified: only to read which key should verify it. Never act on it before `verify` succeeds.
pub fn peek(token: &str) -> Result<Vec<u8>, &'static str> {
    let rest = token.strip_prefix(HEADER).ok_or("not a v4.public token")?;
    let body = rest.split('.').next().unwrap_or("");
    let raw = B64.decode(body).map_err(|_| "malformed token")?;
    if raw.len() < SIG_LEN {
        return Err("malformed token");
    }
    Ok(raw[..raw.len() - SIG_LEN].to_vec())
}

/// Verifies a v4.public token against `key`, the expected footer (compared in constant time, as the spec asks) and
/// the implicit assertion. Returns the signed message.
pub fn verify(token: &str, key: &PublicKey, expected_footer: &[u8], implicit: &[u8]) -> Result<Vec<u8>, &'static str> {
    let got_footer = footer(token)?;
    if !bool::from(got_footer.as_slice().ct_eq(expected_footer)) {
        return Err("footer mismatch");
    }
    let rest = token.strip_prefix(HEADER).ok_or("not a v4.public token")?;
    let body = rest.split('.').next().unwrap_or("");
    let raw = B64.decode(body).map_err(|_| "malformed token")?;
    if raw.len() < SIG_LEN {
        return Err("malformed token");
    }
    let (m, s) = raw.split_at(raw.len() - SIG_LEN);
    if !keys::verify(key, &pae(&[HEADER.as_bytes(), m, &got_footer, implicit]), s) {
        return Err("signature does not verify");
    }
    Ok(m.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Official vectors, paseto-standard/test-vectors v4.json (4-S-1, 4-S-2, 4-S-3): same key, payload; footer and
    // implicit assertion vary. Ed25519 is deterministic, so signing must reproduce each token exactly.
    const SEED: &str = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774";
    const PUBLIC: &str = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
    const PAYLOAD: &str = r#"{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}"#;
    const FOOTER: &str = r#"{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}"#;
    const S1: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA";
    const S2: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const S3: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const IMPLICIT3: &str = r#"{"test-vector":"4-S-3"}"#;
    // 4-F-1 (a v4.local token), 4-F-2 (a public token that must not verify), 4-F-3 (v3), 4-F-5 (padded base64).
    const F1: &str = "v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlNdGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
    const F2: &str = "v4.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn22Sp4gjCaUw0c7EH84ZSm_jN_Qr41MrgLNu5LIBCzUr1pn3Z-Wukg9h3ceplWigpoHaTLcwxj0NsI1vjTh67YB.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const IMPLICIT_F2: &str = r#"{"test-vector":"4-F-2"}"#;
    const F3: &str = "v3.local.23e_2PiqpQBPvRFKzB0zHhjmxK3sKo2grFZRRLM-U7L0a8uHxuF9RlVz3Ic6WmdUUWTxCaYycwWV1yM8gKbZB2JhygDMKvHQ7eBf8GtF0r3K0Q_gF1PXOxcOgztak1eD1dPe9rLVMSgR0nHJXeIGYVuVrVoLWQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
    const F5: &str = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ==.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    #[test]
    fn official_vectors() {
        let seed = Seed::from_hex(SEED).unwrap();
        let pk: PublicKey = hex(PUBLIC).try_into().unwrap();
        assert_eq!(seed.public(), pk);
        for (tok, footer, implicit) in [(S1, "", ""), (S2, FOOTER, ""), (S3, FOOTER, IMPLICIT3)] {
            assert_eq!(sign(&seed, PAYLOAD.as_bytes(), footer.as_bytes(), implicit.as_bytes()), tok);
            assert_eq!(verify(tok, &pk, footer.as_bytes(), implicit.as_bytes()).unwrap(), PAYLOAD.as_bytes());
            assert_eq!(peek(tok).unwrap(), PAYLOAD.as_bytes());
        }
        // Wrong implicit assertion or footer: refused.
        assert!(verify(S3, &pk, FOOTER.as_bytes(), b"").is_err());
        assert!(verify(S2, &pk, b"", b"").is_err());
        for (tok, implicit) in [(F1, ""), (F2, IMPLICIT_F2), (F3, ""), (F5, "")] {
            assert!(verify(tok, &pk, FOOTER.as_bytes(), implicit.as_bytes()).is_err(), "{tok}");
        }
        // One flipped bit anywhere in the body.
        let mut bad = S1.to_string().into_bytes();
        let i = HEADER.len() + 5;
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(verify(std::str::from_utf8(&bad).unwrap(), &pk, b"", b"").is_err());
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
