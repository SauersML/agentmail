//! Upgrades in place, so a new build never needs a reset or a rejoin. Each format (store, trust file, config) has
//! a current version in `islandmail_core::versions` and here a list of steps, each from one version to the next. At
//! start a node brings older files forward once: it keeps a copy of the old file (`NAME.vN.bak`) and writes the new
//! one atomically. A file from a newer build is refused with "upgrade islandmail-node".
//!
//! To change a format: bump its version in `versions.rs` and append one step below. Never edit a released step.

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use islandmail_core::versions;
use rusqlite::Connection;
use serde_json::Value;

/// SQL that brings a store at version `.0` to `.0 + 1`, run in one transaction with the version bump.
pub const STORE_STEPS: &[(i64, &str)] = &[];
/// Steps that bring a trust file at `"v": .0` to `.0 + 1`.
pub const TRUST_STEPS: &[(u32, JsonStep)] = &[];
/// Steps that bring a config at `"v": .0` to `.0 + 1` (a config without `v` is version 1).
pub const CONFIG_STEPS: &[(u32, JsonStep)] = &[];

pub type JsonStep = fn(&mut Value) -> Result<()>;

fn backup_path(path: &Path, from: impl std::fmt::Display) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(format!(".v{from}.bak"));
    PathBuf::from(p)
}

/// Migrates an opened store at `version` to `current` with `steps`. The old store is first copied, consistently,
/// to `PATH.vN.bak` (kept if a copy of that version is already there); the steps and the version bump commit
/// together, so a failure leaves the store as it was.
pub fn store_with(db: &mut Connection, path: &Path, version: i64, current: i64, steps: &[(i64, &str)]) -> Result<bool> {
    ensure!(version <= current, "{}: {}", path.display(), versions::too_new("store", version, current));
    ensure!(version >= 1, "{} is not an Islandmail store", path.display());
    if version == current {
        return Ok(false);
    }
    let backup = backup_path(path, version);
    if !backup.exists() {
        db.execute("VACUUM INTO ?", [backup.to_str().context("store path is not UTF-8")?])
            .with_context(|| format!("copying {} before migrating it", path.display()))?;
        let file = std::fs::File::open(&backup)?;
        crate::private_fs::restrict_file(&file, &backup)?;
        file.sync_all()?;
    }
    let tx = db.transaction()?;
    let mut at = version;
    for (from, sql) in steps.iter().filter(|(f, _)| *f >= version) {
        ensure!(*from == at, "no store migration from version {at}");
        tx.execute_batch(sql).with_context(|| format!("migrating the store from version {from}"))?;
        at += 1;
    }
    ensure!(at == current, "no store migration from version {at} to {current}");
    tx.execute_batch(&format!("PRAGMA user_version = {current}"))?;
    tx.commit()?;
    tracing::warn!("migrated {} from store version {version} to {current}; the old copy is {}", path.display(), backup.display());
    Ok(true)
}

pub fn store(db: &mut Connection, path: &Path, version: i64) -> Result<bool> {
    store_with(db, path, version, versions::STORE, STORE_STEPS)
}

/// `value` brought to `current` (its `"v"`, 1 when missing) with `steps`; true when it changed.
pub fn json_with(what: &str, value: &mut Value, current: u32, steps: &[(u32, JsonStep)]) -> Result<bool> {
    let Some(obj) = value.as_object() else { bail!("{what} is not a JSON object") };
    let version = match obj.get("v") {
        None => 1,
        Some(v) => v.as_u64().and_then(|v| u32::try_from(v).ok()).with_context(|| format!("{what}: bad \"v\""))?,
    };
    ensure!(version <= current, "{}", versions::too_new(what, version, current));
    if version == current {
        return Ok(false);
    }
    let mut at = version;
    for (from, step) in steps.iter().filter(|(f, _)| *f >= version) {
        ensure!(*from == at, "no {what} migration from version {at}");
        step(value).with_context(|| format!("migrating the {what} from version {from}"))?;
        at += 1;
        value["v"] = at.into();
    }
    ensure!(at == current, "no {what} migration from version {at} to {current}");
    Ok(true)
}

pub fn trust(value: &mut Value) -> Result<bool> {
    json_with("trust file", value, versions::TRUST_FILE, TRUST_STEPS)
}

pub fn config(value: &mut Value) -> Result<bool> {
    json_with("config", value, versions::CONFIG, CONFIG_STEPS)
}

/// Rewrites the JSON file at `path` in the current version if it is older: the old file is kept as `PATH.vN.bak`
/// and the new one replaces it atomically (same folder, then rename). Returns the current-version value.
pub fn file(path: &Path, migrate: fn(&mut Value) -> Result<bool>) -> Result<Value> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut value: Value = serde_json::from_slice(&raw).with_context(|| format!("{} is not valid JSON", path.display()))?;
    let from = value.get("v").cloned().unwrap_or(1.into());
    if !migrate(&mut value).with_context(|| path.display().to_string())? {
        return Ok(value);
    }
    let backup = backup_path(path, &from);
    if !backup.exists() {
        std::fs::copy(path, &backup).with_context(|| format!("copying {}", path.display()))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".migrating");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, serde_json::to_vec_pretty(&value)?)?;
    std::fs::set_permissions(&tmp, std::fs::metadata(path)?.permissions())?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = crate::private_fs::sync_dir(dir);
    }
    tracing::warn!("migrated {} from version {from}; the old copy is {}", path.display(), backup.display());
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("islandmail-migrate-{}", islandmail_core::b64u(&islandmail_core::random_bytes::<9>())));
        std::fs::create_dir(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn a_store_moves_forward_once_with_a_backup_and_a_failed_step_changes_nothing() {
        let path = tmp("mail.sqlite");
        let mut db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('old row'); PRAGMA user_version = 1").unwrap();
        let steps: &[(i64, &str)] = &[(1, "ALTER TABLE t ADD COLUMN y TEXT DEFAULT 'new'"), (2, "CREATE TABLE u (z)")];
        // A broken step: nothing applied, version kept.
        let broken: &[(i64, &str)] = &[(1, "ALTER TABLE t ADD COLUMN y TEXT"), (2, "NOT SQL")];
        assert!(store_with(&mut db, &path, 1, 3, broken).is_err());
        let v: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 1);
        assert!(db.prepare("SELECT y FROM t").is_err(), "the first step was rolled back");
        assert!(store_with(&mut db, &path, 1, 3, steps).unwrap());
        let (x, y): (String, String) = db.query_row("SELECT x, y FROM t", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((x.as_str(), y.as_str()), ("old row", "new"));
        assert_eq!(db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 3);
        assert!(!store_with(&mut db, &path, 3, 3, steps).unwrap(), "done once");
        let old = Connection::open(backup_path(&path, 1)).unwrap();
        assert_eq!(old.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 1, "the backup is the old store");
        assert!(store_with(&mut db, &path, 4, 3, steps).unwrap_err().to_string().contains("upgrade islandmail-node"));
    }

    #[test]
    fn json_files_move_forward_with_a_backup_and_newer_ones_are_refused() {
        fn rename(v: &mut Value) -> Result<()> {
            let n = v.as_object_mut().unwrap().remove("old").unwrap();
            v["new"] = n;
            Ok(())
        }
        let steps: &[(u32, JsonStep)] = &[(1, rename)];
        let mut v = serde_json::json!({"v": 1, "old": 5});
        assert!(json_with("trust file", &mut v, 2, steps).unwrap());
        assert_eq!(v, serde_json::json!({"v": 2, "new": 5}));
        assert!(!json_with("trust file", &mut v, 2, steps).unwrap());
        let mut none = serde_json::json!({"old": 1});
        assert!(json_with("config", &mut none, 2, steps).unwrap(), "no v is version 1");
        let mut newer = serde_json::json!({"v": 3});
        assert!(json_with("config", &mut newer, 2, steps).unwrap_err().to_string().contains("upgrade islandmail-node"));
        // The real tables: current files are left alone, byte for byte.
        let path = tmp("members.json");
        std::fs::write(&path, br#"{"v":1,"seq":1}"#).unwrap();
        file(&path, trust).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"v":1,"seq":1}"#);
        assert!(!backup_path(&path, 1).exists());
        std::fs::write(&path, br#"{"v":9,"seq":1}"#).unwrap();
        assert!(format!("{:#}", file(&path, trust).unwrap_err()).contains("upgrade islandmail-node"));
    }

    #[test]
    fn the_step_tables_are_contiguous_and_end_at_the_current_versions() {
        let ends = |from: Vec<i64>, current: i64| from.iter().enumerate().all(|(i, f)| *f == current - from.len() as i64 + i as i64);
        assert!(ends(STORE_STEPS.iter().map(|s| s.0).collect(), versions::STORE));
        assert!(ends(TRUST_STEPS.iter().map(|s| s.0 as i64).collect(), versions::TRUST_FILE as i64));
        assert!(ends(CONFIG_STEPS.iter().map(|s| s.0 as i64).collect(), versions::CONFIG as i64));
    }
}
