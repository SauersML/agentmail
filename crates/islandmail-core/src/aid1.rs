//! Offline verification of archipelago-home `aid1` identity tokens, ported from the home's reference verifier
//! (archipelago-home `src/token.ts`, `docs/AUDIENCE-CONTRACT.md` §2-§3):
//!
//!   aid1.<base64url(payload JSON)>.<base64url(ed25519 signature)>
//!
//! The signature covers the literal bytes of `aid1.<payload segment>`. Nothing is re-canonicalized: the bytes received
//! are verified first, then parsed. Checks, in order: shape, signature under the pinned issuer key, `v`, `iss`, `aud`,
//! `kg` (only when the verifier pins a key generation), `sub`, `name`, `scopes`, `cnf` (a well-formed key when
//! present), `exp` (required, in the future), `iat` (not more than five minutes ahead). Today's tokens carry no `kg`
//! or `cnf`; FEDERATION.md §9.7 adds both, and this verifier accepts them.
//!
//! The holder presents a token with a proof of possession: its key's signature over
//! `archipelago-present|v1|<iss>|<aud>|<timestamp>|<jti>|<token hash>` (`present_statement`).

use anyhow::{anyhow, bail, ensure, Result};
use serde_json::Value;

use crate::keys::{self, fmt_key, parse_key, PublicKey};
use crate::{b64u, b64u_decode};

pub const PREFIX: &str = "aid1";
/// The reference verifier refuses longer input before looking at it.
pub const MAX_TOKEN: usize = 64 * 1024;
/// How far ahead of the verifier's clock `iat` may be.
pub const IAT_SKEW_S: f64 = 300.0;

/// What a verifier pins for one issuer. `kg: None` accepts any key generation, or none.
#[derive(Clone, Debug)]
pub struct Expect<'a> {
    pub key: &'a PublicKey,
    pub iss: &'a str,
    pub aud: &'a str,
    pub kg: Option<u64>,
}

/// The checked payload fields Islandmail uses. `raw` keeps the whole parsed payload.
#[derive(Clone, Debug, PartialEq)]
pub struct Payload {
    pub iss: String,
    pub sub: String,
    pub kind: String,
    pub name: String,
    pub aud: String,
    pub kg: Option<u64>,
    pub scopes: Vec<String>,
    pub iat: f64,
    pub exp: f64,
    /// The holder's key, `ed25519:<base64url>`, when the token names it.
    pub cnf: Option<PublicKey>,
    pub raw: Value,
}

/// base64url as the reference verifier reads it: only `[A-Za-z0-9_-]`, no padding.
fn b64url(s: &str) -> Option<Vec<u8>> {
    if s.bytes().any(|c| !(c.is_ascii_alphanumeric() || c == b'-' || c == b'_')) {
        return None;
    }
    b64u_decode(s)
}

fn finite(v: &Value) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite())
}

/// Verifies `token` at `now_ms` (Unix milliseconds) against one pinned issuer. The error is the refusal reason, worded
/// as the reference verifier words it where it has one.
pub fn verify(token: &str, ex: &Expect, now_ms: i64) -> Result<Payload> {
    ensure!(token.len() <= MAX_TOKEN, "token too large");
    let parts: Vec<&str> = token.split('.').collect();
    ensure!(parts.len() == 3 && parts[0] == PREFIX, "not an aid1 token");
    let (seg, sig_seg) = (parts[1], parts[2]);
    let sig = b64url(sig_seg).filter(|s| s.len() == 64).ok_or_else(|| anyhow!("malformed signature"))?;
    let signed = &token.as_bytes()[..PREFIX.len() + 1 + seg.len()];
    ensure!(keys::verify(ex.key, signed, &sig), "signature verify failed");

    let bytes = b64url(seg).ok_or_else(|| anyhow!("malformed payload segment"))?;
    let raw: Value = serde_json::from_slice(&bytes).map_err(|_| anyhow!("payload not JSON"))?;
    let p = raw.as_object().ok_or_else(|| anyhow!("malformed payload"))?;
    let text = |k: &str| p.get(k).and_then(Value::as_str);
    ensure!(p.get("v").and_then(finite) == Some(1.0), "unsupported version");
    ensure!(text("iss") == Some(ex.iss), "issuer mismatch");
    ensure!(text("aud") == Some(ex.aud), "audience mismatch");
    let kg = match p.get("kg") {
        None => None,
        Some(v) => Some(finite(v).filter(|k| *k >= 0.0 && k.fract() == 0.0 && *k <= 9.0e15)
            .ok_or_else(|| anyhow!("malformed key generation"))? as u64),
    };
    if let Some(want) = ex.kg {
        ensure!(kg.is_some(), "missing key generation");
        ensure!(kg == Some(want), "key generation mismatch");
    }
    let sub = text("sub").filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("missing sub"))?;
    let name = text("name").filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("missing name"))?;
    let scopes = p.get("scopes").and_then(Value::as_array)
        .and_then(|a| a.iter().map(|s| s.as_str().map(String::from)).collect::<Option<Vec<_>>>())
        .ok_or_else(|| anyhow!("malformed scopes"))?;
    let cnf = match p.get("cnf") {
        None => None,
        Some(v) => {
            let k = v.as_str().and_then(|s| parse_key(s).ok().filter(|k| fmt_key(k) == s))
                .ok_or_else(|| anyhow!("malformed cnf"))?;
            Some(k)
        }
    };
    let now = now_ms as f64 / 1000.0;
    let exp = p.get("exp").and_then(finite).filter(|e| *e > now).ok_or_else(|| anyhow!("expired"))?;
    let iat = p.get("iat").and_then(finite).filter(|i| *i <= now + IAT_SKEW_S)
        .ok_or_else(|| anyhow!("iat in the future"))?;
    let kind = text("kind").unwrap_or("").to_string();
    Ok(Payload { iss: ex.iss.into(), sub: sub.into(), kind, name: name.into(), aud: ex.aud.into(), kg, scopes, iat,
                 exp, cnf, raw })
}

/// base64url of the SHA-256 of the token's bytes: the token hash in a proof of possession.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    b64u(&Sha256::digest(token.as_bytes()))
}

/// What the holder of a key-bound token signs to present it (FEDERATION.md §9.7).
pub fn present_statement(iss: &str, aud: &str, ts: &str, jti: &str, token: &str) -> String {
    format!("archipelago-present|v1|{iss}|{aud}|{ts}|{jti}|{}", token_hash(token))
}

/// A proof of possession's `jti`: 16 to 64 base64url characters.
pub fn valid_jti(jti: &str) -> bool {
    (16..=64).contains(&jti.len()) && b64url(jti).is_some()
}

/// Checks a proof of possession by `holder` for `token`.
pub fn check_presentation(holder: &PublicKey, iss: &str, aud: &str, ts: &str, jti: &str, token: &str, sig: &str) -> Result<()> {
    ensure!(valid_jti(jti), "proof jti must be 16-64 base64url characters");
    let s = b64url(sig).filter(|s| s.len() == 64 && b64u(s) == sig).ok_or_else(|| anyhow!("malformed proof signature"))?;
    if !keys::verify(holder, present_statement(iss, aud, ts, jti, token).as_bytes(), &s) {
        bail!("the proof of possession is not signed by the token's cnf key");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::Seed;

    /// Issuer seed for the vectors below (raw 32 bytes, hex).
    pub const ISSUER_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    /// Holder (agent) seed named by the `good_cnf_kg` vector's `cnf`.
    pub const HOLDER_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    /// Unix ms between every vector's iat and exp.
    pub const NOW_MS: i64 = 1_785_100_600_000;

    pub const AUD: &str = "islandmail:TESTNET";
    // Minted by archipelago-home's own `mintToken` (src/token.ts) with the issuer seed above, in the payload shape its
    // `mintFor` builds today, and checked by its `verifyToken`: see testdata/aid1/mint.mjs.
    pub const GOOD: &str = include_str!("../testdata/aid1/good.txt");
    pub const GOOD_CNF_KG: &str = include_str!("../testdata/aid1/good_cnf_kg.txt");
    pub const EXPIRED: &str = include_str!("../testdata/aid1/expired.txt");
    pub const NO_EXP: &str = include_str!("../testdata/aid1/no_exp.txt");
    pub const LONG_LIVED: &str = include_str!("../testdata/aid1/long_lived.txt");

    fn issuer() -> PublicKey {
        Seed::from_hex(ISSUER_SEED).unwrap().public()
    }

    fn expect(key: &PublicKey) -> Expect<'_> {
        Expect { key, iss: "id.test", aud: AUD, kg: None }
    }

    fn reason(token: &str, ex: &Expect) -> String {
        verify(token.trim(), ex, NOW_MS).unwrap_err().to_string()
    }

    #[test]
    fn vectors_from_the_reference_minter() {
        let k = issuer();
        let p = verify(GOOD.trim(), &expect(&k), NOW_MS).unwrap();
        assert_eq!((p.sub.as_str(), p.name.as_str(), p.kind.as_str(), p.kg), ("agent:fable@guest", "Fable", "agent", None));
        assert_eq!((p.cnf, p.exp - p.iat), (None, 600.0));
        assert_eq!(p.scopes, vec!["mail:send".to_string()]);
        let bound = verify(GOOD_CNF_KG.trim(), &expect(&k), NOW_MS).unwrap();
        assert_eq!((bound.cnf, bound.kg), (Some(Seed::from_hex(HOLDER_SEED).unwrap().public()), Some(1)));
        verify(GOOD_CNF_KG.trim(), &Expect { kg: Some(1), ..expect(&k) }, NOW_MS).unwrap();
        assert_eq!(reason(GOOD, &Expect { kg: Some(1), ..expect(&k) }), "missing key generation");
        assert_eq!(reason(EXPIRED, &expect(&k)), "expired");
        assert_eq!(reason(NO_EXP, &expect(&k)), "expired", "exp is required");
        assert_eq!(verify(LONG_LIVED.trim(), &expect(&k), NOW_MS).unwrap().exp - 3300.0, NOW_MS as f64 / 1000.0,
                   "the verifier accepts it; the home check bounds the lifetime");
    }

    #[test]
    fn pinned_fields_and_tampering() {
        let k = issuer();
        let good = GOOD.trim();
        assert_eq!(reason(good, &Expect { aud: "docs", ..expect(&k) }), "audience mismatch");
        assert_eq!(reason(good, &Expect { iss: "id.evil", ..expect(&k) }), "issuer mismatch");
        assert_eq!(reason(GOOD_CNF_KG.trim(), &Expect { kg: Some(2), ..expect(&k) }), "key generation mismatch");
        let other = Seed::generate().public();
        assert_eq!(reason(good, &expect(&other)), "signature verify failed");
        // Flip one bit of every payload byte in turn: the literal bytes are signed, so each one fails.
        let seg_start = PREFIX.len() + 1;
        let seg_end = good.rfind('.').unwrap();
        for i in seg_start..seg_end {
            let mut b = good.as_bytes().to_vec();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            let t = String::from_utf8(b).unwrap();
            assert!(verify(&t, &expect(&k), NOW_MS).is_err(), "byte {i}");
        }
        // Re-encoding the same JSON differently (here: padding) is a different byte string and is refused.
        let mut padded = good.to_string();
        padded.insert(seg_end, '=');
        assert!(verify(&padded, &expect(&k), NOW_MS).is_err());
        assert!(verify(good, &expect(&k), NOW_MS + 7200 * 1000).is_err(), "expires");
    }

    #[test]
    fn garbage_fails_cleanly() {
        let k = issuer();
        for bad in ["", "aid1", "aid1.x", "aid1.x.y.z", "jwt.ey.sig", "aid1.!!!.???"] {
            assert!(verify(bad, &expect(&k), NOW_MS).is_err(), "{bad}");
        }
        assert_eq!(reason(&"x".repeat(MAX_TOKEN + 1), &expect(&k)), "token too large");
        // Signed but malformed payloads, made here with the same construction as mintToken.
        let seed = Seed::from_hex(ISSUER_SEED).unwrap();
        let mint = |json: &str| {
            let signed = format!("aid1.{}", b64u(json.as_bytes()));
            format!("{signed}.{}", b64u(&seed.sign(signed.as_bytes())))
        };
        for (json, why) in [
            ("null", "malformed payload"),
            ("[]", "malformed payload"),
            ("42", "malformed payload"),
            ("{not json", "payload not JSON"),
            (r#"{"v":2}"#, "unsupported version"),
            (r#"{"v":1,"iss":"id.test","aud":"islandmail:TESTNET","kg":1.5}"#, "malformed key generation"),
            (r#"{"v":1,"iss":"id.test","aud":"islandmail:TESTNET","sub":"s","name":"n","scopes":[1]}"#, "malformed scopes"),
            (r#"{"v":1,"iss":"id.test","aud":"islandmail:TESTNET","sub":"s","name":"n","scopes":[],"cnf":"ed25519:x"}"#,
             "malformed cnf"),
            (r#"{"v":1,"iss":"id.test","aud":"islandmail:TESTNET","sub":"s","name":"n","scopes":[],"exp":1e999}"#,
             "payload not JSON"),
        ] {
            assert_eq!(reason(&mint(json), &expect(&k)), why, "{json}");
        }
    }

    #[test]
    fn proof_of_possession() {
        let holder = Seed::from_hex(HOLDER_SEED).unwrap();
        let tok = GOOD.trim();
        let ts = "2026-07-26T21:16:40.000Z";
        let jti = "AAAAAAAAAAAAAAAAAAAAAA";
        let sig = b64u(&holder.sign(present_statement("id.test", "islandmail", ts, jti, tok).as_bytes()));
        check_presentation(&holder.public(), "id.test", "islandmail", ts, jti, tok, &sig).unwrap();
        assert!(check_presentation(&Seed::generate().public(), "id.test", "islandmail", ts, jti, tok, &sig).is_err());
        assert!(check_presentation(&holder.public(), "id.test", "docs", ts, jti, tok, &sig).is_err());
        assert!(check_presentation(&holder.public(), "id.test", "islandmail", ts, jti, EXPIRED.trim(), &sig).is_err(),
                "the token hash names another token");
        assert!(check_presentation(&holder.public(), "id.test", "islandmail", ts, "short", tok, &sig).is_err());
    }
}
