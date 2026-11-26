//! Homes: archipelago-home identity issuers a host trusts to vouch for agent names under one suffix
//! (`fable@id.animalabs.ai`). An agent enrolls at a trusted node with a key-bound `aid1` token from its home; the node
//! then certifies the agent's key exactly as it certifies its own names, and the certificate carries the token and the
//! agent's proof of possession, so every peer re-checks it offline against the home it pins in its own trust file.
//! A home vouches only for `local@<its suffix>`: never a bare name, never another home's suffix. Mail is still signed
//! by the agent's own key; the token is never a mail credential.

use anyhow::{anyhow, bail, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::aid1;
use crate::cert::{self, Cert, CERTIFY_SKEW_MS};
use crate::keys::{self, fmt_key, parse_key, PublicKey};
use crate::{b64u, b64u_decode, parse_ts};

/// Default audience id: what the home names agent mail as, in its `audiences.json`.
pub const DEFAULT_AUD: &str = "agentmail";
/// Longest domain in a home suffix, so `local@domain` fits the envelope's 120-character fields.
pub const MAX_DOMAIN: usize = 64;

/// A trust-file `homes` entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HomeEntry {
    /// A local label for logs.
    pub name: String,
    /// The token's `iss`: the home's issuing domain.
    pub iss: String,
    /// The pinned issuer key, `ed25519:<base64url>`, of key generation `kg`.
    pub key: String,
    pub kg: u64,
    /// The names it may vouch for: `@domain`. It covers exactly `local@domain`.
    pub suffix: String,
    /// The audience id this network's tokens carry (default "agentmail").
    #[serde(default = "default_aud")]
    pub aud: String,
    // Design hook, not built: an open room may later admit "anyone holding scope X from home Y" by naming this
    // entry's `name` and a scope; the scopes are in the certificate's token, so peers could check them offline.
}

fn default_aud() -> String {
    DEFAULT_AUD.into()
}

/// `domain` as a home suffix: lowercase DNS labels (letters, digits, hyphens), at least two, at most MAX_DOMAIN.
pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= MAX_DOMAIN
        && domain.split('.').count() >= 2
        && domain.split('.').all(|l| {
            (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

/// `local@domain`, split, when `name` is a home name: a valid local name and a valid lowercase domain.
pub fn split_name(name: &str) -> Option<(&str, &str)> {
    let (local, domain) = name.split_once('@')?;
    (cert::valid_name(local) && valid_domain(domain)).then_some((local, domain))
}

pub fn is_home_name(name: &str) -> bool {
    name.contains('@')
}

/// What the old key signs to hand its name to a new key. A home cannot move a name to another key without it.
pub fn rekey_statement(name: &str, old: &str, new: &str) -> String {
    format!("agent-mail-rekey|v1|{name}|{old}|{new}")
}

/// A key change: the previous key and its signature over `rekey_statement(name, key, new key)`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rekey {
    pub key: String,
    pub sig: String,
}

impl Rekey {
    /// Ok(old key) when `self` hands `name` from its key to `new`.
    pub fn check(&self, name: &str, new: &str) -> Result<PublicKey> {
        let old = parse_key(&self.key)?;
        ensure!(fmt_key(&old) == self.key && self.key != new, "rekey must name a different, canonical old key");
        let sig = b64u_decode(&self.sig).filter(|s| b64u(s) == self.sig).ok_or_else(|| anyhow!("bad rekey signature"))?;
        ensure!(keys::verify(&old, rekey_statement(&crate::addr::norm(name), &self.key, new).as_bytes(), &sig),
                "the key change is not signed by the old key");
        Ok(old)
    }
}

/// What a home certificate carries so peers can check it themselves.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HomeProof {
    /// The home's key-bound token naming the agent key in `cnf`.
    pub aid1: String,
    /// The proof of possession: its timestamp (the enrollment's), jti and the agent key's signature.
    pub ts: String,
    pub jti: String,
    pub pop: String,
    /// Present when this certificate moves the name from an earlier key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey: Option<Rekey>,
}

/// The token's `sub` must be `agent:<local>@<anything>` with the same local part (case-insensitive) as the mail name.
fn sub_local(sub: &str) -> Option<&str> {
    sub.strip_prefix("agent:")?.rsplit_once('@').map(|(l, _)| l)
}

impl HomeEntry {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.name.is_empty() && self.name.len() <= 64, "home name must be 1-64 characters");
        ensure!(!self.iss.is_empty() && self.iss.len() <= 253 && self.iss.bytes().all(|b| b.is_ascii_graphic()),
                "home {:?}: invalid iss", self.name);
        let k = parse_key(&self.key)?;
        ensure!(fmt_key(&k) == self.key, "home {:?}: key must use canonical base64url", self.name);
        let domain = self.suffix.strip_prefix('@').ok_or_else(|| anyhow!("home {:?}: suffix must start with '@'", self.name))?;
        ensure!(valid_domain(domain), "home {:?}: suffix {:?} must be '@' and a lowercase domain", self.name, self.suffix);
        ensure!(!self.aud.is_empty() && self.aud.len() <= 128, "home {:?}: invalid aud", self.name);
        Ok(())
    }

    /// Exactly `local@<suffix domain>`.
    pub fn covers(&self, name: &str) -> bool {
        split_name(name).is_some_and(|(_, d)| Some(d) == self.suffix.strip_prefix('@'))
    }

    /// Checks a home enrollment for `name` and agent `key`, as the certifying node does at `at_ms` and every peer does
    /// at the certificate's issuance time: the token verifies under this home's pinned key, generation, iss and aud,
    /// is an agent's, names `key` in `cnf` and the same local name in `sub`, and the proof of possession is by `key`
    /// within five minutes of `at_ms`.
    pub fn check(&self, name: &str, key: &str, p: &HomeProof, at_ms: i64) -> Result<aid1::Payload> {
        ensure!(self.covers(name), "{name} is not under {}", self.suffix);
        let issuer = parse_key(&self.key)?;
        let t = aid1::verify(&p.aid1, &aid1::Expect { key: &issuer, iss: &self.iss, aud: &self.aud, kg: self.kg }, at_ms)
            .map_err(|e| anyhow!("{} token refused: {e}", self.name))?;
        ensure!(t.kind == "agent", "{} token is for a {:?}, not an agent", self.name, t.kind);
        let agent = parse_key(key)?;
        ensure!(t.cnf == Some(agent), "{} token is not bound to this key (cnf)", self.name);
        let (local, _) = split_name(name).expect("covered");
        ensure!(sub_local(&t.sub).is_some_and(|l| l.eq_ignore_ascii_case(local)),
                "{} token is for {:?}, not {local}", self.name, t.sub);
        let ts = parse_ts(&p.ts).ok_or_else(|| anyhow!("proof ts must be YYYY-MM-DDTHH:MM:SS.mmmZ"))?;
        ensure!((ts - at_ms).abs() <= CERTIFY_SKEW_MS, "the proof of possession is more than 5 minutes old");
        aid1::check_presentation(&agent, &self.iss, &self.aud, &p.ts, &p.jti, &p.aid1, &p.pop)?;
        if let Some(r) = &p.rekey {
            r.check(name, key)?;
        }
        Ok(t)
    }
}

/// Checks the home part of a certificate against the homes a trust file pins: a home name needs a proof that one of
/// them accepts at the certificate's issuance time; any other name must carry none.
pub fn check_cert(homes: &[HomeEntry], c: &Cert) -> Result<()> {
    match (&c.home, is_home_name(&c.name)) {
        (None, false) => Ok(()),
        (Some(_), false) => bail!("a home proof on a name outside every home suffix"),
        (None, true) => bail!("{} is a home name but the certificate carries no home token", c.name),
        (Some(p), true) => {
            let at = parse_ts(&c.issued).ok_or_else(|| anyhow!("bad certificate time"))?;
            let mut last = anyhow!("no home in this host's trust file vouches for {}", c.name);
            for h in homes.iter().filter(|h| h.covers(&c.name)) {
                match h.check(&c.name, &c.key, p, at) {
                    Ok(_) => return Ok(()),
                    Err(e) => last = e,
                }
            }
            Err(last)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aid1::tests::{GOOD, HOLDER_SEED, ISSUER_SEED, NOW_MS};
    use crate::keys::Seed;

    pub fn entry() -> HomeEntry {
        HomeEntry { name: "test".into(), iss: "id.test".into(), key: fmt_key(&Seed::from_hex(ISSUER_SEED).unwrap().public()),
                    kg: 1, suffix: "@id.test".into(), aud: DEFAULT_AUD.into() }
    }

    fn proof(holder: &Seed, token: &str, ts_ms: i64) -> HomeProof {
        let ts = crate::ts_from_millis(ts_ms);
        let jti = b64u(&[7u8; 16]);
        let pop = b64u(&holder.sign(aid1::present_statement("id.test", DEFAULT_AUD, &ts, &jti, token).as_bytes()));
        HomeProof { aid1: token.into(), ts, jti, pop, rekey: None }
    }

    #[test]
    fn names_and_suffixes() {
        let h = entry();
        h.validate().unwrap();
        assert!(h.covers("fable@id.test") && h.covers("Fable@id.test"));
        for bad in ["fable", "fable@other.test", "fable@sub.id.test", "fable@ID.test", "@id.test", "a@b@id.test", "all@id.test"] {
            assert!(!h.covers(bad), "{bad}");
        }
        for bad in ["id.test", "@localhost", "@Id.test", "@-x.test", "@a..b"] {
            assert!(HomeEntry { suffix: bad.into(), ..entry() }.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn home_check() {
        let h = entry();
        let holder = Seed::from_hex(HOLDER_SEED).unwrap();
        let key = fmt_key(&holder.public());
        let tok = GOOD.trim();
        let p = proof(&holder, tok, NOW_MS);
        h.check("fable@id.test", &key, &p, NOW_MS).unwrap();
        assert!(h.check("other@id.test", &key, &p, NOW_MS).is_err(), "sub names another agent");
        assert!(h.check("fable", &key, &p, NOW_MS).is_err(), "bare name");
        assert!(h.check("fable@else.test", &key, &p, NOW_MS).is_err(), "another suffix");
        assert!(h.check("fable@id.test", &fmt_key(&Seed::generate().public()), &p, NOW_MS).is_err(), "cnf names another key");
        assert!(h.check("fable@id.test", &key, &p, NOW_MS + 400_000).is_err(), "stale proof");
        assert!(HomeEntry { kg: 2, ..entry() }.check("fable@id.test", &key, &p, NOW_MS).is_err());
        assert!(HomeEntry { aud: "docs".into(), ..entry() }.check("fable@id.test", &key, &p, NOW_MS).is_err());
        let mut forged = p.clone();
        forged.pop = b64u(&Seed::generate().sign(b"x"));
        assert!(h.check("fable@id.test", &key, &forged, NOW_MS).is_err(), "proof by another key");
    }

    #[test]
    fn rekey_needs_the_old_key() {
        let (old, new) = (Seed::generate(), Seed::generate());
        let (ok, nk) = (fmt_key(&old.public()), fmt_key(&new.public()));
        let sig = b64u(&old.sign(rekey_statement("fable@id.test", &ok, &nk).as_bytes()));
        let r = Rekey { key: ok.clone(), sig };
        assert_eq!(r.check("Fable@id.test", &nk).unwrap(), old.public());
        assert!(r.check("other@id.test", &nk).is_err());
        assert!(r.check("fable@id.test", &fmt_key(&Seed::generate().public())).is_err());
        let by_new = Rekey { key: ok, sig: b64u(&new.sign(rekey_statement("fable@id.test", &r.key, &nk).as_bytes())) };
        assert!(by_new.check("fable@id.test", &nk).is_err());
    }
}
