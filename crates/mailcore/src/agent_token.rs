//! Agent tokens: PASETO v4.public tokens an agent signs with its own Ed25519 key (the key its node certified, which
//! also signs its mail), so a node checks a caller with nothing but its certificates. The implicit assertion
//! `agentmail-auth-v1` separates these signatures from everything else the agent key signs.
//!
//! Claims (JSON, PASETO registered claims as RFC 3339 strings):
//!   name  the agent's mail name; the node must hold a live certificate it issued for this name
//!   aud   the key of the one node the token is for (`ed25519:…`); a token taken from one node is refused by any other
//!   iat, exp, optional nbf   exp - iat at most 24 h; clocks may disagree by 300 s
//!   jti   random, 16-128 base64url characters; the node accepts each jti once (the replay check is the node's)
//! A `sub` claim, if present, is ignored.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::cert::{live_certs, valid_name, Cert, KnownCerts};
use crate::keys::{fmt_key, parse_key, PublicKey, Seed};
use crate::members::MemberList;
use crate::paseto;

pub const IMPLICIT: &[u8] = b"agentmail-auth-v1";
pub const MAX_TOKEN: usize = 8192;
pub const MAX_LIFETIME_S: i64 = 86_400;
pub const DEFAULT_LIFETIME_S: i64 = 3_600;
pub const SKEW_S: i64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub name: String,
    pub aud: String,
    pub iat: String,
    pub exp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
    pub jti: String,
}

/// A token that passed every check except the replay check, which needs the node's memory of used jtis.
#[derive(Clone, Debug, PartialEq)]
pub struct Checked {
    /// The name as certified.
    pub name: String,
    /// The certificate whose key signed the token.
    pub cert: Cert,
    /// That certificate's agent key.
    pub key: PublicKey,
    pub jti: String,
    pub exp_ms: i64,
}

#[derive(Debug, PartialEq)]
pub enum Refusal {
    /// This node holds no live certificate it issued for the name (HTTP 403).
    NotCertified(String),
    /// Anything else (HTTP 401). Never contains the token or key material.
    Bad(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NotCertified(s) | Refusal::Bad(s) => f.write_str(s),
        }
    }
}

fn bad(s: impl Into<String>) -> Refusal {
    Refusal::Bad(s.into())
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn parse_time(s: &str, what: &str) -> Result<i64, Refusal> {
    if s.len() > 40 {
        return Err(bad(format!("{what} is not an RFC 3339 time")));
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.timestamp_millis())
        .map_err(|_| bad(format!("{what} is not an RFC 3339 time")))
}

fn valid_jti(j: &str) -> bool {
    (16..=128).contains(&j.len()) && j.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Mints a token for `node`. `lifetime_s` is clamped to 1 s .. 24 h.
pub fn mint(seed: &Seed, name: &str, node: &PublicKey, now_ms: i64, lifetime_s: i64) -> String {
    let life = lifetime_s.clamp(1, MAX_LIFETIME_S);
    let c = Claims {
        name: name.into(),
        aud: fmt_key(node),
        iat: rfc3339(now_ms),
        exp: rfc3339(now_ms + life * 1000),
        nbf: None,
        jti: crate::b64u(&crate::random_bytes::<18>()),
    };
    mint_claims(seed, &c)
}

pub fn mint_claims(seed: &Seed, c: &Claims) -> String {
    paseto::sign(seed, &serde_json::to_vec(c).expect("claims serialize"), b"", IMPLICIT)
}

pub fn is_agent_token(token: &str) -> bool {
    token.starts_with(paseto::HEADER)
}

/// Checks a token presented to the node whose key is `node`, now: format; the signer is the key of a live
/// certificate this node issued for the claimed name (valid against `list`, not revoked in `known`; each such key is
/// tried); audience is this node; times; jti shape. The caller still has to check the jti is new.
pub fn verify(token: &str, known: &dyn KnownCerts, list: &MemberList, node: &PublicKey, now_ms: i64) -> Result<Checked, Refusal> {
    if token.len() > MAX_TOKEN {
        return Err(bad("token too long"));
    }
    // Which keys to check it with come from the (still unverified) claims; nothing else is read before the signature
    // verifies.
    let raw = paseto::peek(token).map_err(bad)?;
    let unverified: Claims = serde_json::from_slice(&raw).map_err(|_| bad("claims are not the expected JSON"))?;
    if !valid_name(&unverified.name) {
        return Err(bad("name is not a valid agent name"));
    }
    let certs = live_certs(known, list, &unverified.name, node);
    if certs.is_empty() {
        return Err(Refusal::NotCertified(format!(
            "{} has no certificate from this node; islandmail.py gets one on first use (POST /api/agents)",
            trunc(&unverified.name, 80)
        )));
    }
    let (cert, key, msg) = certs
        .into_iter()
        .find_map(|c| {
            let k = c.agent_key().ok()?;
            let m = paseto::verify(token, &k, b"", IMPLICIT).ok()?;
            Some((c, k, m))
        })
        .ok_or_else(|| bad("signature does not verify (agent tokens are signed by the agent's certified key)"))?;
    let c: Claims = serde_json::from_slice(&msg).map_err(|_| bad("claims are not the expected JSON"))?;
    let aud = parse_key(&c.aud).map_err(|_| bad("aud must be a node key (ed25519:…)"))?;
    if !bool::from(aud.ct_eq(node)) {
        return Err(bad("token is for another node (aud); mint one for this node's key, from GET /api/node"));
    }
    let iat = parse_time(&c.iat, "iat")?;
    let exp = parse_time(&c.exp, "exp")?;
    if exp <= iat {
        return Err(bad("exp is not after iat"));
    }
    if exp - iat > MAX_LIFETIME_S * 1000 {
        return Err(bad("token lifetime is over 24 h"));
    }
    if exp <= now_ms {
        return Err(bad("expired"));
    }
    if iat > now_ms + SKEW_S * 1000 {
        return Err(bad("iat in the future"));
    }
    if let Some(nbf) = &c.nbf {
        if parse_time(nbf, "nbf")? > now_ms + SKEW_S * 1000 {
            return Err(bad("not valid yet (nbf)"));
        }
    }
    if !valid_jti(&c.jti) {
        return Err(bad("jti must be 16-128 base64url characters"));
    }
    Ok(Checked { name: cert.name.clone(), cert, key, jti: c.jti, exp_ms: exp })
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{CertSet, Revocation};
    use crate::members::tests::list;

    const NOW: i64 = 1_800_000_000_000;
    const TS: &str = "2026-11-25T19:00:00.000Z";

    fn claims(name: &str, node: &Seed, iat: i64, exp: i64) -> Claims {
        Claims { name: name.into(), aud: fmt_key(&node.public()), iat: rfc3339(iat), exp: rfc3339(exp), nbf: None, jti: "AAAAAAAAAAAAAAAAAAAAAAAA".into() }
    }

    /// Node `node` (names "a.") and node `other` (names "b."), the given agents certified by `node`.
    fn setup(node: &Seed, other: &Seed, agents: &[(&str, &Seed)]) -> (MemberList, CertSet) {
        let l = list(&[("mac", node, &["a."]), ("box", other, &["b."])]);
        let mut known = CertSet::default();
        for (n, s) in agents {
            known.add(Cert::issue(node, n, &s.public(), TS));
        }
        (l, known)
    }

    #[test]
    fn valid_token_is_accepted() {
        let (alice, node, other) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (l, known) = setup(&node, &other, &[("a.alice", &alice)]);
        let t = mint(&alice, "a.alice", &node.public(), NOW, DEFAULT_LIFETIME_S);
        let c = verify(&t, &known, &l, &node.public(), NOW).unwrap();
        assert_eq!((c.name.as_str(), c.key, c.exp_ms), ("a.alice", alice.public(), NOW + 3_600_000));
        assert_eq!(c.cert, known.certs[0]);
        assert!(valid_jti(&c.jti));
        // Names compare case-insensitively; the certified spelling is returned. A name must be valid as written.
        let t = mint_claims(&alice, &Claims { name: "a/alice".into(), ..claims("a.alice", &node, NOW, NOW + 60_000) });
        assert!(matches!(verify(&t, &known, &l, &node.public(), NOW), Err(Refusal::Bad(e)) if e.contains("valid agent name")));
        let t = mint_claims(&alice, &Claims { name: "A.Alice".into(), ..claims("a.alice", &node, NOW, NOW + 60_000) });
        assert_eq!(verify(&t, &known, &l, &node.public(), NOW).unwrap().name, "a.alice");
        // Two mints differ (fresh jti each time).
        let t2 = mint(&alice, "a.alice", &node.public(), NOW, 60);
        assert_ne!(verify(&t2, &known, &l, &node.public(), NOW).unwrap().jti, c.jti);
        // A sub claim (older clients) is ignored.
        let msg = serde_json::to_vec(&serde_json::json!({"sub": "agent:x@y", "name": "a.alice", "aud": fmt_key(&node.public()),
            "iat": rfc3339(NOW), "exp": rfc3339(NOW + 60_000), "jti": "BBBBBBBBBBBBBBBBBBBBBBBB"})).unwrap();
        assert!(verify(&paseto::sign(&alice, &msg, b"", IMPLICIT), &known, &l, &node.public(), NOW).is_ok());
    }

    #[test]
    fn key_without_a_certificate_here_is_refused() {
        let (alice, mallory, node, other) = (Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate());
        let (l, mut known) = setup(&node, &other, &[("a.alice", &alice), ("a.mallory", &mallory)]);
        // Mallory (certified here) signs a token claiming alice's name.
        let t = mint(&mallory, "a.alice", &node.public(), NOW, 60);
        assert!(matches!(verify(&t, &known, &l, &node.public(), NOW), Err(Refusal::Bad(e)) if e.contains("signature")));
        // A name this node never certified.
        let eve = Seed::generate();
        let t = mint(&eve, "a.eve", &node.public(), NOW, 60);
        assert!(matches!(verify(&t, &known, &l, &node.public(), NOW), Err(Refusal::NotCertified(e)) if e.contains("POST /api/agents")));
        // Certified by the other node: valid there, not a sign-in here.
        let bob = Seed::generate();
        known.add(Cert::issue(&other, "b.bob", &bob.public(), TS));
        let t = mint(&bob, "b.bob", &node.public(), NOW, 60);
        assert!(matches!(verify(&t, &known, &l, &node.public(), NOW), Err(Refusal::NotCertified(_))));
        let t = mint(&bob, "b.bob", &other.public(), NOW, 60);
        assert!(verify(&t, &known, &l, &other.public(), NOW).is_ok());
    }

    #[test]
    fn revoked_key_cannot_sign_in_and_a_new_key_can() {
        let (alice, node, other) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (l, mut known) = setup(&node, &other, &[("a.alice", &alice)]);
        known.revoke(&Revocation::sign(&node, "a.alice", &alice.public(), TS)).unwrap();
        let t = mint(&alice, "a.alice", &node.public(), NOW, 60);
        assert!(matches!(verify(&t, &known, &l, &node.public(), NOW), Err(Refusal::NotCertified(_))));
        let fresh = Seed::generate();
        known.add(Cert::issue(&node, "a.alice", &fresh.public(), TS));
        assert!(verify(&t, &known, &l, &node.public(), NOW).is_err(), "the old key stays dead");
        let t = mint(&fresh, "a.alice", &node.public(), NOW, 60);
        assert_eq!(verify(&t, &known, &l, &node.public(), NOW).unwrap().key, fresh.public());
    }

    #[test]
    fn another_nodes_revocation_does_not_block_sign_in() {
        let (alice, node, other) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (l, mut known) = setup(&node, &other, &[("a.alice", &alice)]);
        known.revoke(&Revocation::sign(&other, "b.alice", &alice.public(), TS)).unwrap();
        let t = mint(&alice, "a.alice", &node.public(), NOW, 60);
        assert_eq!(verify(&t, &known, &l, &node.public(), NOW).unwrap().key, alice.public());
    }

    #[test]
    fn times_are_enforced() {
        let (alice, node, other) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (l, known) = setup(&node, &other, &[("a.alice", &alice)]);
        let v = |c: Claims| verify(&mint_claims(&alice, &c), &known, &l, &node.public(), NOW);
        let err = |c: Claims| match v(c) {
            Err(Refusal::Bad(e)) => e,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_eq!(err(claims("a.alice", &node, NOW - 7_200_000, NOW - 1)), "expired");
        assert_eq!(err(claims("a.alice", &node, NOW - 1000, NOW - 1000 + 86_401_000)), "token lifetime is over 24 h");
        assert!(v(claims("a.alice", &node, NOW - 1000, NOW - 1000 + 86_400_000)).is_ok(), "exactly 24 h is allowed");
        assert_eq!(err(claims("a.alice", &node, NOW + 301_000, NOW + 600_000)), "iat in the future");
        assert!(v(claims("a.alice", &node, NOW + 299_000, NOW + 600_000)).is_ok(), "within the 300 s skew");
        assert_eq!(err(claims("a.alice", &node, NOW, NOW)), "exp is not after iat");
        let mut c = claims("a.alice", &node, NOW, NOW + 60_000);
        c.nbf = Some(rfc3339(NOW + 400_000));
        assert_eq!(err(c), "not valid yet (nbf)");
        let mut c = claims("a.alice", &node, NOW, NOW + 60_000);
        c.exp = "tomorrow".into();
        assert!(err(c).contains("RFC 3339"));
        // mint() clamps the lifetime, so it never makes a token the verifier refuses for length.
        let t = mint(&alice, "a.alice", &node.public(), NOW, 10 * 86_400);
        assert_eq!(verify(&t, &known, &l, &node.public(), NOW).unwrap().exp_ms, NOW + 86_400_000);
    }

    #[test]
    fn wrong_audience_is_refused() {
        let (alice, node, other) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (l, known) = setup(&node, &other, &[("a.alice", &alice)]);
        let t = mint(&alice, "a.alice", &other.public(), NOW, 60);
        assert!(matches!(verify(&t, &known, &l, &node.public(), NOW), Err(Refusal::Bad(e)) if e.contains("another node")));
        let mut c = claims("a.alice", &node, NOW, NOW + 60_000);
        c.aud = "mail".into();
        assert!(matches!(verify(&mint_claims(&alice, &c), &known, &l, &node.public(), NOW), Err(Refusal::Bad(e)) if e.contains("aud")));
    }

    #[test]
    fn tampered_or_foreign_tokens_are_refused() {
        let (alice, node, other) = (Seed::generate(), Seed::generate(), Seed::generate());
        let (l, known) = setup(&node, &other, &[("a.alice", &alice)]);
        let v = |t: &str| verify(t, &known, &l, &node.public(), NOW);
        let good = mint(&alice, "a.alice", &node.public(), NOW, 60);
        // Re-encode different claims under the real signature.
        let raw = crate::b64u_decode(good.strip_prefix(paseto::HEADER).unwrap()).unwrap();
        let sig = &raw[raw.len() - 64..];
        let mut c: Claims = serde_json::from_slice(&raw[..raw.len() - 64]).unwrap();
        c.exp = rfc3339(NOW + 80_000_000);
        let mut body = serde_json::to_vec(&c).unwrap();
        body.extend_from_slice(sig);
        let tampered = format!("{}{}", paseto::HEADER, crate::b64u(&body));
        assert!(matches!(v(&tampered), Err(Refusal::Bad(e)) if e.contains("signature")));
        // A footer, or the same claims signed without the implicit assertion: refused.
        let msg = serde_json::to_vec(&claims("a.alice", &node, NOW, NOW + 60_000)).unwrap();
        assert!(v(&paseto::sign(&alice, &msg, b"{}", IMPLICIT)).is_err());
        assert!(v(&paseto::sign(&alice, &msg, b"", b"")).is_err());
        // Bad jti, a bad name, and garbage are refused without panicking.
        let mut c = claims("a.alice", &node, NOW, NOW + 60_000);
        c.jti = "short".into();
        assert!(v(&mint_claims(&alice, &c)).is_err());
        assert!(matches!(v(&mint_claims(&alice, &claims("all", &node, NOW, NOW + 60_000))), Err(Refusal::Bad(_))));
        for junk in ["", "v4.public.", "v4.public.AAAA", "v4.public.!!!", "x.y.z", &"v4.public.A".repeat(2000)] {
            assert!(v(junk).is_err(), "{junk:.40}");
        }
        // Errors never echo the token.
        if let Err(e) = v(&tampered) {
            assert!(!e.to_string().contains(&tampered[10..40]));
        }
    }
}
