//! Key continuity for home names (`fable@id.animalabs.ai`). Each host pins a home name's key on first contact: the
//! first certificate it accepts for the name. A later certificate for another key counts only when it carries the
//! current key's signature handing the name over (`home::Rekey`); anything else is refused and logged as an error, so
//! a home cannot silently move one of its names to a key the agent does not hold. The history is local: each host
//! keeps its own, in `home_keys`. Each key counts for mail dated from when it took over until the next one did.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use islandmail_core::addr::norm;
use islandmail_core::cert::CERTIFY_SKEW_MS;
use islandmail_core::home::is_home_name;
use islandmail_core::Cert;
use rusqlite::{params, Connection};

use crate::store::Store;

pub fn init(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS home_keys (lname TEXT NOT NULL, key TEXT NOT NULL,
                      from_ms INTEGER NOT NULL, PRIMARY KEY (lname, key));")?;
    Ok(())
}

/// (key, from_ms) of a home name, oldest first.
fn history(db: &Connection, name: &str) -> Result<Vec<(String, i64)>> {
    let mut st = db.prepare("SELECT key, from_ms FROM home_keys WHERE lname = ? ORDER BY from_ms, key")?;
    let rows = st.query_map([norm(name)], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Logs a refusal once per name and key per process, at error level: a home trying to move a name is worth a look.
fn refuse(name: &str, key: &str, why: String) -> String {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let mut seen = SEEN.get_or_init(Default::default).lock().unwrap();
    if seen.len() < 10_000 && seen.insert(format!("{}\u{0}{key}", norm(name))) {
        tracing::error!("REFUSED a new key for {name}: {why}");
    } else {
        tracing::debug!("refused a new key for {name} again: {why}");
    }
    why
}

/// Whether `c` (already accepted by the trust file) keeps its home name's key history. With `record`, a first key or
/// a signed handover is remembered. Err(reason) when refused. Names outside every home pass untouched.
pub fn admit(store: &Store, c: &Cert, record: bool) -> Result<std::result::Result<(), String>> {
    if !is_home_name(&c.name) {
        return Ok(Ok(()));
    }
    let db = store.conn();
    let hist = history(&db, &c.name)?;
    let Some((head, _)) = hist.last() else {
        if record {
            db.execute("INSERT OR IGNORE INTO home_keys VALUES (?, ?, ?)", params![norm(&c.name), c.key, i64::MIN])?;
            tracing::info!("pinned {} to key {} on first contact", c.name, c.key);
        }
        return Ok(Ok(()));
    };
    if hist.iter().any(|(k, _)| *k == c.key) {
        return Ok(Ok(()));
    }
    let Some(rekey) = c.home.as_ref().and_then(|p| p.rekey.as_ref()) else {
        return Ok(Err(refuse(&c.name, &c.key, format!(
            "node {} certified key {} without a handover signed by the pinned key {head}", c.node, c.key))));
    };
    if rekey.key != *head {
        let why = if hist.iter().any(|(k, _)| *k == rekey.key) {
            format!("key {} already handed the name on; the current key is {head}", rekey.key)
        } else {
            format!("handed over from {}, which this host has not seen (current key {head}); waiting for that step", rekey.key)
        };
        return Ok(Err(refuse(&c.name, &c.key, why)));
    }
    if rekey.check(&c.name, &c.key).is_err() {
        return Ok(Err(refuse(&c.name, &c.key, "the handover signature does not verify".into())));
    }
    if record {
        let from = islandmail_core::parse_ts(&c.issued).unwrap_or(i64::MAX);
        db.execute("INSERT OR IGNORE INTO home_keys VALUES (?, ?, ?)", params![norm(&c.name), c.key, from])?;
        tracing::warn!("{} moved from key {head} to {}, signed by the old key", c.name, c.key);
    }
    Ok(Ok(()))
}

/// The certificates that count at `at_ms`: home names only with the key that held the name then.
pub fn current(store: &Store, certs: Vec<Cert>, at_ms: i64) -> Result<Vec<Cert>> {
    if !certs.iter().any(|c| is_home_name(&c.name)) {
        return Ok(certs);
    }
    let db = store.conn();
    let mut out = Vec::with_capacity(certs.len());
    for c in certs {
        if !is_home_name(&c.name) {
            out.push(c);
            continue;
        }
        let hist = history(&db, &c.name)?;
        let Some(i) = hist.iter().position(|(k, _)| *k == c.key) else { continue };
        let starts = hist[i].1.saturating_sub(CERTIFY_SKEW_MS) <= at_ms;
        let ends = hist.get(i + 1).is_some_and(|(_, next)| at_ms >= *next);
        if starts && !ends {
            out.push(c);
        }
    }
    Ok(out)
}
