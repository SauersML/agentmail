//! SQLite: every envelope this node holds (as JSON, keyed by envelope id), the decrypted header + text when this node
//! can read it, a local integer id per envelope (the compat API's message number), and the compat API's bookkeeping
//! (names seen, MCPL push cursors).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use mailcore::addr::norm;
use mailcore::{Envelope, Verified};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde_json::json;

pub const PAGE: i64 = 1000;
pub const PAGE_CHARS: usize = 4_000_000;
pub const MAX_TEXT: i64 = 100_000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  env_id TEXT NOT NULL UNIQUE,
  day TEXT NOT NULL,
  ts TEXT NOT NULL,
  sender TEXT NOT NULL,
  sender_sub TEXT NOT NULL,
  recipient TEXT NOT NULL,
  thread TEXT NOT NULL,
  mode TEXT NOT NULL,
  text TEXT,
  files TEXT NOT NULL DEFAULT '[]',
  readers TEXT,
  verified INTEGER NOT NULL DEFAULT 1,
  imported INTEGER,
  parents TEXT NOT NULL,
  env TEXT NOT NULL,
  received INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_thread ON messages (thread, id);
CREATE INDEX IF NOT EXISTS messages_day ON messages (day, env_id);
CREATE INDEX IF NOT EXISTS messages_sender ON messages (sender_sub, ts);
CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY, sub TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursors (sub TEXT PRIMARY KEY, last_id INTEGER NOT NULL);
";

/// What a reader sees of a row it may read; `text` is None only for rows this node cannot decrypt (never shown).
#[derive(Clone, Debug)]
pub struct Row {
    pub id: i64,
    pub env_id: String,
    pub ts: String,
    pub sender: String,
    pub sender_sub: String,
    pub recipient: String,
    pub thread: String,
    pub mode: String,
    pub text: Option<String>,
    pub len: i64,
    pub files: String,
    pub readers: Option<String>,
    pub verified: bool,
    pub imported: Option<i64>,
    pub parents: Vec<String>,
}

impl Row {
    /// Members mode: any caller with a valid token (as on the old server). Private: the sender and the members it was
    /// addressed to, and only if this node could decrypt it.
    pub fn visible_to(&self, viewer: &str) -> bool {
        self.text.is_some()
            && (self.mode == "members"
                || self.readers.as_deref().is_some_and(|r| r.contains(&format!(",{},", norm(viewer)))))
    }

    pub fn to_message(&self) -> serde_json::Value {
        let text = self.text.clone().unwrap_or_default();
        let shown = text.chars().count() as i64;
        let mut m = json!({
            "id": self.id, "ts": self.ts, "from": self.sender, "to": self.recipient, "thread": self.thread,
            "text": text, "files": serde_json::from_str::<serde_json::Value>(&self.files).unwrap_or(json!([])),
            "len": self.len, "sub": self.sender_sub, "verified": self.verified,
            "env": self.env_id, "mode": self.mode,
        });
        if self.len > shown {
            m["truncated"] = json!(self.len);
        }
        if let Some(old) = self.imported {
            m["imported"] = json!(old);
        }
        m
    }
}

#[derive(Default, Debug, Clone)]
pub struct Query {
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub latest: Option<i64>,
    pub limit: Option<i64>,
    pub thread: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub q: Option<String>,
}

pub struct Store {
    db: Mutex<Connection>,
}

const COLS: &str = "id, env_id, ts, sender, sender_sub, recipient, thread, mode, substr(text, 1, ?) AS text, \
                    length(text) AS len, files, readers, verified, imported, parents";

fn visible_sql() -> &'static str {
    "(text IS NOT NULL AND (mode = 'members' OR instr(readers, ?) > 0))"
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let parents: String = r.get(14)?;
    Ok(Row {
        id: r.get(0)?,
        env_id: r.get(1)?,
        ts: r.get(2)?,
        sender: r.get(3)?,
        sender_sub: r.get(4)?,
        recipient: r.get(5)?,
        thread: r.get(6)?,
        mode: r.get(7)?,
        text: r.get(8)?,
        len: r.get::<_, Option<i64>>(9)?.unwrap_or(0),
        files: r.get(10)?,
        readers: r.get(11)?,
        verified: r.get::<_, i64>(12)? != 0,
        imported: r.get(13)?,
        parents: serde_json::from_str(&parents).unwrap_or_default(),
    })
}

fn like_prefix(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        db.execute_batch(SCHEMA)?;
        Ok(Store { db: Mutex::new(db) })
    }

    pub fn has(&self, env_id: &str) -> Result<bool> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT 1 FROM messages WHERE env_id = ?", [env_id], |_| Ok(())).optional()?.is_some())
    }

    /// Stores a verified envelope. Returns None if it was already here (the envelope id is the dedupe key).
    pub fn insert(
        &self,
        env: &Envelope,
        v: &Verified,
        text: Option<&str>,
        readers: Option<&str>,
        received_ms: i64,
    ) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        let json = serde_json::to_string(env)?;
        let parents = serde_json::to_string(&env.parents)?;
        // Imported history keeps its old number when that number is free here (phase 2 bridge).
        let explicit = match v.imported {
            Some(old) if old > 0 => db
                .query_row("SELECT 1 FROM messages WHERE id = ?", [old as i64], |_| Ok(()))
                .optional()?
                .is_none()
                .then_some(old as i64),
            _ => None,
        };
        let n = db.execute(
            "INSERT OR IGNORE INTO messages (id, env_id, day, ts, sender, sender_sub, recipient, thread, mode, text, \
             readers, verified, imported, parents, env, received) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                explicit,
                env.id,
                env.day(),
                env.ts,
                env.from,
                v.sender_sub,
                env.to,
                env.thread,
                env.mode.as_str(),
                text,
                readers,
                v.verified as i64,
                v.imported.map(|x| x as i64),
                parents,
                json,
                received_ms
            ],
        )?;
        if n == 0 {
            return Ok(None);
        }
        let row = db.query_row(
            &format!("SELECT {COLS} FROM messages WHERE env_id = ?"),
            params![MAX_TEXT, env.id],
            read_row,
        )?;
        Ok(Some(row))
    }

    pub fn last_id(&self) -> Result<i64> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |r| r.get(0))?)
    }

    pub fn get(&self, id: i64, viewer: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        let row = db
            .query_row(&format!("SELECT {COLS} FROM messages WHERE id = ?"), params![MAX_TEXT, id], read_row)
            .optional()?;
        Ok(row.filter(|r| r.visible_to(viewer)))
    }

    /// The old server's query(): rows in local-id order, at most `limit` (1000) or PAGE_CHARS of text.
    pub fn query(&self, q: &Query, viewer: &str, text_cap: i64) -> Result<(Vec<Row>, bool)> {
        let mut wh = vec![visible_sql().to_string()];
        let mut args: Vec<Value> = vec![Value::Integer(text_cap), Value::Text(format!(",{},", norm(viewer)))];
        if let Some(a) = q.after {
            wh.push("id > ?".into());
            args.push(Value::Integer(a));
        }
        if let Some(b) = q.before {
            wh.push("id < ?".into());
            args.push(Value::Integer(b));
        }
        if let Some(t) = &q.thread {
            wh.push("thread = ?".into());
            args.push(Value::Text(t.clone()));
        }
        if let Some(f) = &q.from {
            wh.push("sender LIKE ? ESCAPE '\\'".into());
            args.push(Value::Text(like_prefix(f)));
        }
        if let Some(t) = &q.to {
            wh.push("recipient LIKE ? ESCAPE '\\'".into());
            args.push(Value::Text(like_prefix(t)));
        }
        if let Some(s) = &q.q {
            wh.push("instr(lower(text), lower(?)) > 0".into());
            args.push(Value::Text(s.clone()));
        }
        let limit = q.latest.or(q.limit).unwrap_or(PAGE).min(PAGE);
        args.push(Value::Integer(limit));
        let sql = format!(
            "SELECT {COLS} FROM messages WHERE {} ORDER BY id {} LIMIT ?",
            wh.join(" AND "),
            if q.latest.is_some() { "DESC" } else { "ASC" }
        );
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&sql)?;
        let mut rows = Vec::new();
        let mut chars = 0usize;
        let mut more = false;
        for r in st.query_map(params_from_iter(args), read_row)? {
            let r = r?;
            chars += r.text.as_deref().map_or(0, |t| t.len()) + 200;
            if !rows.is_empty() && chars > PAGE_CHARS {
                more = true;
                break;
            }
            rows.push(r);
        }
        if rows.len() as i64 == limit {
            more = true;
        }
        if q.latest.is_some() {
            rows.reverse();
        }
        Ok((rows, more))
    }

    /// A page of rows in (lo, hi) whose recipient contains one of `needles` (a prefilter for addressedTo), not sent by
    /// any of `subs`. Used by the inbox tool and MCPL backlog.
    pub fn addressed_page(
        &self,
        viewer: &str,
        lo: i64,
        hi: i64,
        subs: &[String],
        needles: &[String],
        ascending: bool,
        text_cap: i64,
    ) -> Result<Vec<Row>> {
        let mut args: Vec<Value> = vec![Value::Integer(text_cap), Value::Text(format!(",{},", norm(viewer)))];
        args.push(Value::Integer(lo));
        args.push(Value::Integer(hi));
        let subs_sql = vec!["?"; subs.len().max(1)].join(", ");
        if subs.is_empty() {
            args.push(Value::Text(String::new()));
        }
        args.extend(subs.iter().map(|s| Value::Text(s.clone())));
        let needle_sql = needles
            .iter()
            .map(|_| "instr(replace(lower(recipient), '/', '.'), ?) > 0")
            .collect::<Vec<_>>()
            .join(" OR ");
        args.extend(needles.iter().map(|s| Value::Text(s.clone())));
        let sql = format!(
            "SELECT {COLS} FROM messages WHERE {} AND id > ? AND id < ? AND sender_sub NOT IN ({subs_sql}) AND ({needle_sql}) \
             ORDER BY id {} LIMIT 500",
            visible_sql(),
            if ascending { "ASC" } else { "DESC" }
        );
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&sql)?;
        let rows = st.query_map(params_from_iter(args), read_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn thread_rows(&self, viewer: &str, limit: i64) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&format!(
            "SELECT m.thread, t.n, m.id, m.ts, m.sender, m.recipient, substr(m.text, 1, 300) AS snippet
             FROM (SELECT thread, COUNT(*) AS n, MAX(id) AS last FROM messages WHERE {} GROUP BY thread) t
             JOIN messages m ON m.id = t.last ORDER BY m.id DESC LIMIT ?",
            visible_sql()
        ))?;
        let rows = st
            .query_map(params![format!(",{},", norm(viewer)), limit], |r| {
                Ok(json!({
                    "thread": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)?, "id": r.get::<_, i64>(2)?,
                    "ts": r.get::<_, String>(3)?, "sender": r.get::<_, String>(4)?,
                    "recipient": r.get::<_, String>(5)?, "snippet": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// All rows of a thread the viewer may read, in the causal thread order every node agrees on.
    pub fn thread_causal(&self, thread: &str, viewer: &str, text_cap: i64) -> Result<Vec<Row>> {
        let rows: Vec<Row> = {
            let db = self.db.lock().unwrap();
            let mut st = db.prepare(&format!("SELECT {COLS} FROM messages WHERE thread = ?"))?;
            let r = st.query_map(params![text_cap, thread], read_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            r
        };
        let items: Vec<mailcore::order::Item> = rows
            .iter()
            .map(|r| mailcore::order::Item { id: &r.env_id, ts: &r.ts, parents: &r.parents })
            .collect();
        let order = mailcore::order::thread_order(&items);
        Ok(order.into_iter().map(|i| rows[i].clone()).filter(|r| r.visible_to(viewer)).collect())
    }

    /// Thread heads: envelopes of the thread no other envelope of it names as a parent (latest 16 by ts).
    pub fn heads(&self, thread: &str) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id, ts, parents FROM messages WHERE thread = ?")?;
        let rows: Vec<(String, String, String)> =
            st.query_map([thread], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut referenced = HashSet::new();
        for (_, _, p) in &rows {
            for id in serde_json::from_str::<Vec<String>>(p).unwrap_or_default() {
                referenced.insert(id);
            }
        }
        let mut heads: Vec<(String, String)> =
            rows.into_iter().filter(|(id, _, _)| !referenced.contains(id)).map(|(id, ts, _)| (ts, id)).collect();
        heads.sort();
        heads.reverse();
        heads.truncate(mailcore::envelope::MAX_PARENTS);
        let mut ids: Vec<String> = heads.into_iter().map(|(_, id)| id).collect();
        ids.sort();
        Ok(ids)
    }

    /// Anti-entropy: BLAKE3 over the sorted envelope ids of each day (the day is the envelope's ts date).
    pub fn day_hashes(&self) -> Result<BTreeMap<String, String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT day, env_id FROM messages ORDER BY day, env_id")?;
        let mut out = BTreeMap::new();
        let mut cur: Option<(String, blake3::Hasher, u64)> = None;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let day: String = r.get(0)?;
            let id: String = r.get(1)?;
            if cur.as_ref().map(|c| &c.0) != Some(&day) {
                if let Some((d, h, n)) = cur.take() {
                    out.insert(d, format!("{n}:{}", h.finalize().to_hex()));
                }
                cur = Some((day.clone(), blake3::Hasher::new(), 0));
            }
            let c = cur.as_mut().unwrap();
            c.1.update(id.as_bytes());
            c.1.update(b"\n");
            c.2 += 1;
        }
        if let Some((d, h, n)) = cur {
            out.insert(d, format!("{n}:{}", h.finalize().to_hex()));
        }
        Ok(out)
    }

    pub fn ids_for_day(&self, day: &str) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id FROM messages WHERE day = ? ORDER BY env_id")?;
        let ids = st.query_map([day], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }

    pub fn envelopes(&self, ids: &[String]) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env FROM messages WHERE env_id = ?")?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(e) = st.query_row([id], |r| r.get::<_, String>(0)).optional()? {
                out.push(e);
            }
        }
        Ok(out)
    }

    /// The same sender's identical message within the repeat window (a client resending after a dropped answer).
    pub fn repeat(&self, sub: &str, since_ts: &str, to: &str, thread: &str, text: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db
            .query_row(
                &format!(
                    "SELECT {COLS} FROM messages WHERE sender_sub = ? AND ts > ? AND recipient = ? AND thread = ? \
                     AND text = ? AND files = '[]' ORDER BY id DESC LIMIT 1"
                ),
                params![MAX_TEXT, sub, since_ts, to, thread, text],
                read_row,
            )
            .optional()?)
    }

    pub fn seen(&self, name: &str, sub: &str, at_ms: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO names (name, sub, seen) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET \
             sub = excluded.sub, seen = MAX(seen, excluded.seen)",
            params![name.chars().take(120).collect::<String>(), sub, at_ms],
        )?;
        Ok(())
    }

    /// (name, sub, seen ms), most recently active first.
    pub fn names(&self, limit: i64) -> Result<Vec<(String, String, i64)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT name, sub, seen FROM names ORDER BY seen DESC LIMIT ?")?;
        let rows = st.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn cursor(&self, sub: &str) -> Result<Option<i64>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT last_id FROM cursors WHERE sub = ?", [sub], |r| r.get(0)).optional()?)
    }

    pub fn advance_cursor(&self, sub: &str, id: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO cursors (sub, last_id) VALUES (?, ?) ON CONFLICT(sub) DO UPDATE SET \
             last_id = MAX(last_id, excluded.last_id)",
            params![sub, id],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<i64> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?)
    }
}
