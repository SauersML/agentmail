//! SQLite: every envelope this node holds (as JSON, keyed by envelope id), the decrypted header + text when this node
//! can read it, a local integer id per envelope (the compat API's message number), and the compat API's bookkeeping
//! (names seen, MCPL push cursors).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use mailcore::addr::norm;
use crate::node::Caller;
use mailcore::{Envelope, Verified};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde_json::json;

pub const PAGE: i64 = 1000;
pub const PAGE_CHARS: usize = 4_000_000;
pub const MAX_TEXT: i64 = 100_000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS local_trust (id INTEGER PRIMARY KEY CHECK(id=1), node TEXT NOT NULL, roster TEXT NOT NULL);
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
  parents TEXT NOT NULL,
  env TEXT NOT NULL,
  received INTEGER NOT NULL,
  agent_sig TEXT,
  blobs TEXT NOT NULL DEFAULT '[]');
CREATE INDEX IF NOT EXISTS messages_thread ON messages (thread, id);
CREATE UNIQUE INDEX IF NOT EXISTS messages_agent_sig ON messages(agent_sig) WHERE agent_sig IS NOT NULL;
CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS uploads (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL,
  size INTEGER NOT NULL, key TEXT NOT NULL, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_day ON messages (day, env_id);
CREATE INDEX IF NOT EXISTS messages_sender ON messages (sender_sub, ts);
CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY, sub TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursors (sub TEXT PRIMARY KEY, last_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS used_tokens (name TEXT NOT NULL, jti TEXT NOT NULL, exp INTEGER NOT NULL,
  PRIMARY KEY (name, jti));
CREATE INDEX IF NOT EXISTS used_tokens_exp ON used_tokens (exp);
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
    pub wrapped_to: String,
}

/// Attachment metadata as clients see it (the blob key never leaves the node).
pub fn public_files(files: &str) -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_str(files).unwrap_or(json!([]));
    if let Some(a) = v.as_array_mut() {
        for f in a {
            if let Some(o) = f.as_object_mut() {
                o.remove("key");
            }
        }
    }
    v
}

impl Row {
    /// Only originally wrapped keys can read. Private mail also requires the original addressed name.
    pub fn visible_to(&self, viewer: &Caller) -> bool {
        self.text.is_some() && self.wrapped_to.split(',').any(|k| k == viewer.key)
            && (self.mode == "members"
                || (self.mode == "private"
                    && self.readers.as_deref().is_some_and(|r| r.contains(&format!(",{},", norm(&viewer.name))))))
    }

    pub fn to_message(&self) -> serde_json::Value {
        let text = self.text.clone().unwrap_or_default();
        let shown = text.chars().count() as i64;
        let mut m = json!({
            "id": self.id, "ts": self.ts, "from": self.sender, "to": self.recipient, "thread": self.thread,
            "text": text, "files": public_files(&self.files),
            "len": self.len, "sub": self.sender_sub, "verified": true,
            "env": self.env_id, "mode": self.mode, "attest": "agent",
        });
        if self.len > shown {
            m["truncated"] = json!(self.len);
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
    _exclusive: std::fs::File,
}

const COLS: &str = "id, env_id, ts, sender, sender_sub, recipient, thread, mode, substr(text, 1, ?) AS text, \
                    length(text) AS len, files, readers, \
                    (SELECT group_concat(value->>'to') FROM json_each(env, '$.keys'))";

fn visible_sql() -> &'static str {
    "(json_extract(env, '$.v') = 3 AND text IS NOT NULL AND (mode = 'members' OR (mode = 'private' AND instr(readers, ?) > 0)) \
      AND EXISTS (SELECT 1 FROM json_each(env, '$.keys') WHERE value->>'to' = ?))"
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
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
        wrapped_to: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
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
        use rusqlite::OpenFlags;
        use std::fs::{OpenOptions, Permissions};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let mut options = OpenOptions::new();
        options.read(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let secure = |file: &std::fs::File| -> Result<()> {
            let md = file.metadata()?;
            anyhow::ensure!(md.is_file() && md.nlink() == 1, "mail store must be a regular file with one link");
            file.set_permissions(Permissions::from_mode(0o600))?;
            Ok(())
        };
        // Use a separate lock file so the process lock cannot contend with SQLite's own locks.
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let exclusive = options.clone().create(true).open(lock_path)?;
        secure(&exclusive)?;
        exclusive.try_lock().map_err(|e| anyhow::anyhow!("mail store already in use or cannot be locked: {e}"))?;
        let file = options.clone().create(true).open(path)?;
        secure(&file)?;
        drop(file);
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sibling = path.as_os_str().to_owned();
            sibling.push(suffix);
            match options.open(sibling) {
                Ok(file) => secure(&file)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut db = Connection::open_with_flags(path.canonicalize()?, flags)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF")?;
        let old_store = db.prepare("SELECT 1 FROM sqlite_schema WHERE name='messages'")?.exists([])?
            && !db.prepare("SELECT 1 FROM sqlite_schema WHERE name='local_trust'")?.exists([])?;
        anyhow::ensure!(!old_store, "existing database predates local trust; use a new data directory");
        let tx = db.transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.commit()?;
        use rusqlite::functions::FunctionFlags;
        db.create_scalar_function("addressed_to", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |c| Ok(mailcore::addr::addressed_to(c.get_raw(0).as_str()?, &[c.get_raw(1).as_str()?])))?;
        Ok(Store { db: Mutex::new(db), _exclusive: exclusive })
    }

    /// A data directory belongs to one node and network. Keep the last accepted local revision across restarts.
    pub fn bind_roster(&self, key: &mailcore::keys::PublicKey, list: &mailcore::MemberList) -> Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let node = mailcore::keys::fmt_key(key);
        let current = tx.query_row("SELECT node, roster FROM local_trust WHERE id=1", [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).optional()?;
        if let Some((owner, raw)) = current {
            let previous: mailcore::MemberList = serde_json::from_str(&raw)?;
            anyhow::ensure!(owner == node && previous.network == list.network, "use a separate data directory for each network and node");
            anyhow::ensure!(list.seq > previous.seq || *list == previous, "trust file conflicts with the last accepted local revision");
        } else {
            anyhow::ensure!(!tx.prepare("SELECT 1 FROM messages UNION ALL SELECT 1 FROM uploads UNION ALL SELECT 1 FROM blobs LIMIT 1")?.exists([])?,
                "existing mail store predates locally pinned trust; start with a new data directory");
        }
        tx.execute("INSERT OR REPLACE INTO local_trust VALUES (1, ?, ?)", params![node, serde_json::to_string(list)?])?;
        tx.commit()?;
        Ok(())
    }

    pub fn has(&self, env_id: &str) -> Result<bool> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT 1 FROM messages WHERE env_id = ?", [env_id], |_| Ok(())).optional()?.is_some())
    }

    /// The visible row of an agent-signed message, by its sender signature (canonical base64url).
    pub fn by_agent_sig(&self, sig: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db
            .query_row(&format!("SELECT {COLS} FROM messages WHERE agent_sig = ?"), params![MAX_TEXT, sig], read_row)
            .optional()?)
    }

    /// Stores a verified envelope. Returns None if it was already here (the envelope id is the dedupe key), or if it
    /// is another envelope carrying an agent-signed message already here (stored hidden, see agent_sig).
    pub fn insert(
        &self,
        env: &Envelope,
        v: &Verified,
        text: Option<&str>,
        files: &str,
        readers: Option<&str>,
        received_ms: i64,
    ) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        let json = serde_json::to_string(env)?;
        let parents = serde_json::to_string(&env.parents)?;
        let mailcore::Attest::Agent { sig, .. } = &env.attest;
        let replay = db.prepare("SELECT 1 FROM messages WHERE agent_sig = ?")?.exists([sig])?;
        let n = db.execute(
            "INSERT OR IGNORE INTO messages (env_id, day, ts, sender, sender_sub, recipient, thread, mode, text, \
             readers, parents, env, received, blobs, files, agent_sig) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                env.id,
                env.day(),
                env.ts,
                env.from,
                v.sender_sub,
                env.to,
                env.thread,
                if replay { "dup" } else { env.mode.as_str() },
                if replay { None } else { text },
                if replay { None } else { readers },
                parents,
                json,
                received_ms,
                serde_json::to_string(&env.blobs)?,
                if replay { "[]" } else { files },
                (!replay).then_some(sig)
            ],
        )?;
        if n == 0 || replay {
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

    pub fn get(&self, id: i64, viewer: &Caller) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row(&format!("SELECT {COLS} FROM messages WHERE id = ?"), params![MAX_TEXT, id], read_row)
            .optional()?.filter(|r| r.visible_to(viewer)))
    }

    /// Return rows in local-id order, at most `limit` (1000) or PAGE_CHARS of text.
    pub fn query(&self, q: &Query, viewer: &Caller, text_cap: i64) -> Result<(Vec<Row>, bool)> {
        let mut wh = vec![visible_sql().to_string()];
        let mut args: Vec<Value> = vec![Value::Integer(text_cap), Value::Text(format!(",{},", norm(&viewer.name))), Value::Text(viewer.key.clone())];
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
        args.push(Value::Integer(limit + 1));
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
            chars += r.text.as_deref().map_or(0, |t| t.len()) + r.files.len() + 200;
            if rows.len() as i64 >= limit || (!rows.is_empty() && chars > PAGE_CHARS) {
                more = true;
                break;
            }
            rows.push(r);
        }
        if q.latest.is_some() {
            rows.reverse();
        }
        Ok((rows, more))
    }

    pub fn addressed_rows(
        &self, viewer: &Caller, after: i64, before: i64, limit: usize, text_cap: i64, ascending: bool,
    ) -> Result<Vec<Row>> {
        let db = self.db.lock().unwrap();
        let order = if ascending { "ASC" } else { "DESC" };
        let mut st = db.prepare(&format!(
            "SELECT {COLS} FROM messages WHERE {} AND id > ? AND id < ? AND sender_sub != ?
             AND addressed_to(recipient, ?) ORDER BY id {order} LIMIT ?", visible_sql()
        ))?;
        let args = params![text_cap, format!(",{},", norm(&viewer.name)), viewer.key, after, before,
                           viewer.sub, viewer.name, limit as i64];
        let rows = st.query_map(args, read_row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn thread_rows(&self, viewer: &Caller, limit: i64) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&format!(
            "SELECT m.thread, t.n, m.id, m.ts, m.sender, m.recipient, substr(m.text, 1, 300) AS snippet
             FROM (SELECT thread, COUNT(*) AS n, MAX(id) AS last FROM messages WHERE {} GROUP BY thread) t
             JOIN messages m ON m.id = t.last ORDER BY m.id DESC LIMIT ?",
            visible_sql()
        ))?;
        let rows = st
            .query_map(params![format!(",{},", norm(&viewer.name)), viewer.key, limit], |r| {
                Ok(json!({
                    "thread": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)?, "id": r.get::<_, i64>(2)?,
                    "ts": r.get::<_, String>(3)?, "sender": r.get::<_, String>(4)?,
                    "recipient": r.get::<_, String>(5)?, "snippet": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Sort lightweight graph metadata first, then load a page of visible bodies in causal order.
    pub fn thread_causal(&self, thread: &str, viewer: &Caller, q: &Query, text_cap: i64) -> Result<(Vec<Row>, bool)> {
        let db = self.db.lock().unwrap();
        let mut graph = db.prepare("SELECT id, env_id, ts, parents FROM messages WHERE thread=?")?;
        let mut nodes = Vec::new();
        let mut records = graph.query([thread])?;
        while let Some(r) = records.next()? {
            let parents: Vec<String> = serde_json::from_str(r.get_ref(3)?.as_str()?)?;
            nodes.push((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, parents));
        }
        let items: Vec<_> = nodes.iter().map(|(_, id, ts, parents)| mailcore::order::Item { id, ts, parents }).collect();
        let mut order = mailcore::order::thread_order(&items);
        let position = |id| order.iter().position(|&i| nodes[i].0 == id);
        let start = q.after.filter(|&id| id != 0).map_or(0, |id| position(id).map_or(order.len(), |i| i + 1));
        let end = q.before.map_or(order.len(), |id| position(id).unwrap_or(0));
        let window = &mut order[start.min(end)..end];
        if q.latest.is_some() { window.reverse(); }
        let limit = q.latest.or(q.limit).unwrap_or(PAGE).clamp(0, PAGE) as usize;
        let name = format!(",{},", norm(&viewer.name));
        let mut read = db.prepare(&format!("SELECT {COLS} FROM messages WHERE id=? AND {}", visible_sql()))?;
        let mut rows = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        for &i in window.iter() {
            let Some(row) = read.query_row(params![text_cap, nodes[i].0, name, viewer.key], read_row).optional()? else { continue };
            bytes += row.text.as_deref().map_or(0, str::len) + row.files.len() + 200;
            if rows.len() == limit || (!rows.is_empty() && bytes > PAGE_CHARS) { more = true; break; }
            rows.push(row);
        }
        if q.latest.is_some() { rows.reverse(); }
        Ok((rows, more))
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
        let mut st = db.prepare("SELECT day, env_id FROM messages WHERE json_extract(env, '$.v') = 3 ORDER BY day, env_id")?;
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

    pub fn ids_for_day(&self, day: &str, after: &str, limit: usize) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id FROM messages WHERE day = ? AND env_id > ? AND json_extract(env, '$.v') = 3 ORDER BY env_id LIMIT ?")?;
        let ids = st.query_map(params![day, after, limit as i64], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }

    pub fn envelopes(&self, ids: &[String]) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env FROM messages WHERE env_id = ? AND json_extract(env, '$.v') = 3")?;
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

    /// Records an agent token's jti as used. Ok(false): it was used before (a replay). Rows are kept until the token
    /// expires (plus the clock skew), so the check survives a restart; expired rows are dropped as new ones come in.
    pub fn use_token(&self, name: &str, jti: &str, exp_ms: i64, now_ms: i64) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let fresh = db.execute(
            "INSERT OR IGNORE INTO used_tokens (name, jti, exp) VALUES (?, ?, ?)",
            params![norm(name), jti, exp_ms + mailcore::agent_token::SKEW_S * 1000],
        )? == 1;
        if fresh && db.last_insert_rowid() % 256 == 0 {
            db.execute("DELETE FROM used_tokens WHERE exp < ?", params![now_ms])?;
        }
        Ok(fresh)
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

    pub fn names(&self, members: &[mailcore::Member]) -> Result<Vec<(String, String, i64)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(
            "SELECT m.value->>'name', m.value->>'sub', COALESCE(n.seen, 0)
             FROM json_each(?) m LEFT JOIN names n ON n.name = m.value->>'name' AND n.sub = m.value->>'sub'
             ORDER BY COALESCE(n.seen, 0) DESC, m.value->>'name'")?;
        let rows = st.query_map([serde_json::to_string(members)?], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn cursor(&self, sub: &str) -> Result<i64> {
        let db = self.db.lock().unwrap();
        db.execute("INSERT OR IGNORE INTO cursors (sub, last_id) SELECT ?, COALESCE(MAX(id), 0) FROM messages", [sub])?;
        Ok(db.query_row("SELECT last_id FROM cursors WHERE sub = ?", [sub], |r| r.get(0))?)
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

    /* Attachments */

    pub fn put_blob(&self, id: &str, data: &[u8], now_ms: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO blobs (id, data, size, created) VALUES (?, ?, ?, ?)",
            params![id, data, data.len() as i64, now_ms],
        )?;
        Ok(())
    }

    pub fn get_blob(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT data FROM blobs WHERE id = ?", [id], |r| r.get(0)).optional()?)
    }

    /// Blob ids some stored envelope references that this node does not hold yet.
    pub fn missing_blobs(&self) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT DISTINCT b.value FROM messages m, json_each(m.blobs) b
            WHERE NOT EXISTS (SELECT 1 FROM blobs WHERE id=b.value) ORDER BY b.value")?;
        let rows = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_upload(&self, id: &str, blob: &[u8], owner: &str, name: &str, ty: &str, size: i64,
                       key: &str, now: i64, quota: i64) -> Result<bool> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let used: i64 = tx.query_row("SELECT COALESCE(SUM(size), 0) FROM uploads WHERE owner=?", [owner], |r| r.get(0))?;
        if size > quota - used { return Ok(false); }
        tx.execute("INSERT INTO blobs (id, data, size, created) VALUES (?, ?, ?, ?)", params![id, blob, blob.len() as i64, now])?;
        tx.execute("INSERT INTO uploads (id, owner, name, type, size, key, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   params![id, owner, name, ty, size, key, now])?;
        tx.commit()?;
        Ok(true)
    }

    /// File references {id, name, type, size, key} the viewer may use: its own upload first, then the attachments with
    /// this id of messages it can read, oldest first. Several messages can name one blob, and a member node can write
    /// one naming someone else's blob with a wrong key, so callers use the first whose key opens the blob.
    pub fn find_files(&self, id: &str, viewer: &Caller) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let mut out = Vec::new();
        let up = db
            .query_row(
                "SELECT name, type, size, key FROM uploads WHERE id = ? AND owner = ?",
                [id, &viewer.key],
                |r| {
                    Ok(json!({ "id": id, "name": r.get::<_, String>(0)?, "type": r.get::<_, String>(1)?,
                               "size": r.get::<_, i64>(2)?, "key": r.get::<_, String>(3)? }))
                },
            )
            .optional()?;
        out.extend(up);
        let mut st = db.prepare(&format!(
            "SELECT DISTINCT f.value FROM messages m, json_each(m.files) f WHERE f.value->>'id' = ? AND {}
             ORDER BY m.id, f.key", visible_sql()
        ))?;
        for row in st.query_map(params![id, format!(",{},", norm(&viewer.name)), viewer.key], |r| r.get::<_, String>(0))? {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<i64> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_rejects_network_switches_and_local_trust_rollback() {
        let key = mailcore::keys::Seed::generate().public();
        let mut list = mailcore::MemberList { v: 2, network: mailcore::b64u(&mailcore::random_bytes::<32>()),
            seq: 1, members: vec![], nodes: vec![mailcore::NodeEntry { name: "me".into(),
                    key: mailcore::keys::fmt_key(&key), addrs: vec![] }] };
        let path = std::env::temp_dir().join(format!("mailnode-store-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let store = Store::open(&path).unwrap();
        assert!(Store::open(&path).is_err(), "a second live node must not share the same store");
        store.bind_roster(&key, &list).unwrap();
        list.seq += 1;
        store.bind_roster(&key, &list).unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        store.bind_roster(&key, &list).unwrap();
        list.seq -= 1;
        assert!(store.bind_roster(&key, &list).is_err());
        list.seq += 2;
        list.network = mailcore::b64u(&mailcore::random_bytes::<32>());
        assert!(store.bind_roster(&key, &list).is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
