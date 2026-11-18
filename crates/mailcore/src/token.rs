//! aid1 tokens (archipelago-home src/token.ts): `aid1.<b64url payload JSON>.<b64url ed25519 sig over "aid1.<payload>">`,
//! checked offline against the home's pinned key, with exactly the old server's rules (islandmail src/index.js verifyAid1).

use serde::{Deserialize, Serialize};

use crate::keys::{self, PublicKey, Seed};
use crate::{b64u, b64u_decode};

pub const MAX_TOKEN: usize = 8192;
/// How far an iat may be ahead of the verifier's clock (the old server's 300 s).
pub const IAT_SKEW_S: f64 = 300.0;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Aid1Payload {
    pub v: u32,
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub kind: String,
    pub name: String,
    pub aud: String,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    pub iat: f64,
    pub exp: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// What a verifier pins: the home's key and domain, its own audience, and the scope it requires.
#[derive(Clone, Debug)]
pub struct TokenPolicy {
    pub home_key: PublicKey,
    pub iss: String,
    pub aud: String,
    pub scope: String,
}

/// Signature, version, issuer, audience, sub/name, scopes and the required scope. No clock checks: callers apply
/// those against "now" (the compat API) or against an envelope's timestamp (replication).
pub fn verify_static(token: &str, p: &TokenPolicy) -> Result<Aid1Payload, String> {
    if token.len() > MAX_TOKEN {
        return Err("not a token".into());
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "aid1" {
        return Err("not an aid1 token".into());
    }
    let sig = b64u_decode(parts[2]).filter(|s| s.len() == 64).ok_or("malformed signature")?;
    if !keys::verify(&p.home_key, format!("aid1.{}", parts[1]).as_bytes(), &sig) {
        return Err("signature verify failed (not signed by the home)".into());
    }
    let raw = b64u_decode(parts[1]).ok_or("payload not JSON")?;
    let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| "payload not JSON")?;
    if v.get("v").and_then(|x| x.as_u64()) != Some(1) {
        return Err("unsupported version".into());
    }
    let pl: Aid1Payload = serde_json::from_value(v).map_err(|_| "missing sub or name, or malformed fields")?;
    if pl.iss != p.iss {
        return Err(format!("issuer mismatch ({})", trunc(&pl.iss, 60)));
    }
    if pl.aud != p.aud {
        return Err(format!("audience mismatch ({}); mint a token for \"{}\"", trunc(&pl.aud, 60), p.aud));
    }
    if pl.sub.is_empty() || pl.name.is_empty() {
        return Err("missing sub or name".into());
    }
    if !p.scope.is_empty() && !pl.scopes.iter().any(|s| s == &p.scope) {
        return Err(format!("missing scope {}", p.scope));
    }
    Ok(pl)
}

/// The old server's check for a caller: everything above, plus exp > now and iat <= now + 300 s.
pub fn verify_now(token: &str, p: &TokenPolicy, now_s: f64) -> Result<Aid1Payload, String> {
    let pl = verify_static(token, p)?;
    if pl.exp <= now_s {
        return Err("expired".into());
    }
    if pl.iat > now_s + IAT_SKEW_S {
        return Err("iat in the future".into());
    }
    Ok(pl)
}

/// For replicated envelopes: the token must have been live when the envelope says it was written, within `skew_s`.
pub fn verify_at(token: &str, p: &TokenPolicy, at_s: f64, skew_s: f64) -> Result<Aid1Payload, String> {
    let pl = verify_static(token, p)?;
    if pl.exp + skew_s <= at_s {
        return Err("token had expired when the envelope was written".into());
    }
    if pl.iat > at_s + skew_s {
        return Err("token issued after the envelope was written".into());
    }
    Ok(pl)
}

/// Mints a token the way the home does. Used by tests and by `mailtool mint-token` with a throwaway test home key.
pub fn mint(home: &Seed, payload: &Aid1Payload) -> String {
    let seg = b64u(&serde_json::to_vec(payload).expect("payload serializes"));
    let signed = format!("aid1.{seg}");
    let sig = home.sign(signed.as_bytes());
    format!("{signed}.{}", b64u(&sig))
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn policy(home: &Seed) -> TokenPolicy {
        TokenPolicy { home_key: home.public(), iss: "home.test".into(), aud: "mail".into(), scope: "mail:use".into() }
    }

    pub fn payload(name: &str, iat: f64, exp: f64) -> Aid1Payload {
        Aid1Payload {
            v: 1,
            iss: "home.test".into(),
            sub: format!("agent:{name}@test"),
            kind: "agent".into(),
            name: name.into(),
            aud: "mail".into(),
            scopes: vec!["mail:use".into()],
            claims: None,
            iat,
            exp,
            jti: None,
        }
    }

    #[test]
    fn accepts_good_and_refuses_bad_tokens() {
        let home = Seed::generate();
        let p = policy(&home);
        let now = 1_800_000_000.0;
        let good = mint(&home, &payload("a.one", now - 10.0, now + 3600.0));
        assert_eq!(verify_now(&good, &p, now).unwrap().name, "a.one");

        // Forged: signed by some other key.
        let other = Seed::generate();
        let forged = mint(&other, &payload("a.one", now - 10.0, now + 3600.0));
        assert!(verify_now(&forged, &p, now).unwrap_err().contains("signature"));

        // Tampered payload under a real signature.
        let parts: Vec<&str> = good.split('.').collect();
        let mut pl = payload("a.one", now - 10.0, now + 3600.0);
        pl.name = "someone.else".into();
        let tampered = format!("aid1.{}.{}", b64u(&serde_json::to_vec(&pl).unwrap()), parts[2]);
        assert!(verify_now(&tampered, &p, now).is_err());

        let expired = mint(&home, &payload("a.one", now - 7200.0, now - 1.0));
        assert_eq!(verify_now(&expired, &p, now).unwrap_err(), "expired");
        let future = mint(&home, &payload("a.one", now + 1000.0, now + 3600.0));
        assert_eq!(verify_now(&future, &p, now).unwrap_err(), "iat in the future");

        let mut wrong_aud = payload("a.one", now, now + 60.0);
        wrong_aud.aud = "notes".into();
        assert!(verify_now(&mint(&home, &wrong_aud), &p, now).unwrap_err().contains("audience"));
        let mut no_scope = payload("a.one", now, now + 60.0);
        no_scope.scopes = vec!["notes:use".into()];
        assert!(verify_now(&mint(&home, &no_scope), &p, now).unwrap_err().contains("scope"));
        let mut wrong_iss = payload("a.one", now, now + 60.0);
        wrong_iss.iss = "evil.test".into();
        assert!(verify_now(&mint(&home, &wrong_iss), &p, now).unwrap_err().contains("issuer"));
        assert!(verify_now("aid1.x", &p, now).is_err());

        // An envelope written while the token was live stays valid after the token expires.
        assert!(verify_at(&expired, &p, now - 100.0, 300.0).is_ok());
        assert!(verify_at(&expired, &p, now + 3600.0, 300.0).is_err());
    }
}
