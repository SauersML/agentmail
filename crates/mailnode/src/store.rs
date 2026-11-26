//! SQLite: every envelope this node holds (as JSON, keyed by envelope id), the decrypted header + text when this node
//! can read it, a local integer id per envelope (the compat API's message number), and the compat API's bookkeeping
//! (names seen, MCPL push cursors).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use mailcore::addr::norm;
use crate::node::Caller;
use mailcore::{Envelope, Verified};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde_json::json;

pub const PAGE: i64 = 1000;
pub const PAGE_CHARS: usize = 4_000_000;
pub const MAX_TEXT: i64 = 100_000;
pub const MAX_CERTS_PER_NODE: i64 = 1000;
/// Most certificates (and revocations) one sync answer carries.
pub const MAX_SYNC_CERTS: usize = 10_000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS node_encryption_keys (node TEXT PRIMARY KEY, epoch INTEGER NOT NULL, record TEXT NOT NULL);
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
CREATE TABLE IF NOT EXISTS certs (node TEXT NOT NULL, key TEXT NOT NULL, lname TEXT NOT NULL, json TEXT NOT NULL,
  PRIMARY KEY (node, key));
CREATE INDEX IF NOT EXISTS certs_lname ON certs (lname);
CREATE TABLE IF NOT EXISTS revocations (node TEXT NOT NULL, key TEXT NOT NULL, ts INTEGER NOT NULL, json TEXT NOT NULL,
  PRIMARY KEY (node, key));
CREATE TABLE IF NOT EXISTS revoke_requests (lname TEXT PRIMARY KEY, last_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY, sub TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursors (sub TEXT PRIMARY KEY, last_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS used_tokens (name TEXT NOT NULL, jti TEXT NOT NULL, exp INTEGER NOT NULL,
  PRIMARY KEY (name, jti));
CREATE INDEX IF NOT EXISTS used_tokens_exp ON used_tokens (exp);
CREATE TABLE IF NOT EXISTS grants (env_id TEXT NOT NULL, key TEXT NOT NULL, ck TEXT NOT NULL, grant_env TEXT NOT NULL,
  thread TEXT NOT NULL, PRIMARY KEY (env_id, key));
CREATE TABLE IF NOT EXISTS room_reads (viewer TEXT NOT NULL, thread TEXT NOT NULL, last_id INTEGER NOT NULL,
  PRIMARY KEY (viewer, thread));
";

/// Room columns added to `messages` after the first release; added in place to an older store.
const ROOM_COLUMNS: [(&str, &str); 4] = [
    ("kind", "TEXT NOT NULL DEFAULT 'mail'"), ("meta", "TEXT"), ("mentions", "TEXT"), ("reply_to", "TEXT"),
];

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
    /// mail (plain), post (a room post), event (membership), grant (key grant: never shown).
    pub kind: String,
    /// The signed room fields (`mailcore::room::Meta` JSON), when the body had them.
    pub meta: Option<String>,
    /// ",name,name," of the agents mentioned.
    pub mentions: Option<String>,
    pub reply_to: Option<String>,
}

/// Room fields of a row, from its decrypted body.
#[derive(Default, Debug, Clone)]
pub struct Extra {
    pub kind: &'static str,
    pub meta: Option<String>,
    pub mentions: Option<String>,
    pub reply_to: Option<String>,
}

impl Extra {
    pub fn of(meta_raw: &str, meta: &mailcore::room::Meta) -> Extra {
        if meta.is_empty() {
            return Extra { kind: "mail", ..Default::default() };
        }
        let kind = if !meta.grant.is_empty() { "grant" } else if meta.event.is_some() { "event" }
                   else if meta.room.is_some() { "post" } else { "mail" };
        let mentions = (!meta.mentions.is_empty())
            .then(|| format!(",{},", meta.mentions.iter().map(|m| norm(m)).collect::<Vec<_>>().join(",")));
        Extra { kind, meta: Some(meta_raw.to_string()), mentions, reply_to: meta.reply_to.clone() }
    }
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
        self.text.is_some() && self.kind != "grant" && self.wrapped_to.split(',').any(|k| k == viewer.key)
            && (self.mode == "members"
                || (self.mode == "private"
                    && self.readers.as_deref().is_some_and(|r| r.contains(&format!(",{},", norm(&viewer.name))))))
    }

    pub fn sealed_to(&self, recipients: &[mailcore::keys::PublicKey]) -> bool {
        let keys: HashSet<_> = self.wrapped_to.split(',').collect();
        keys.len() == recipients.len() && recipients.iter().all(|k| keys.contains(mailcore::keys::fmt_key(k).as_str()))
    }

    pub fn to_message(&self) -> serde_json::Value {
        let text = self.text.clone().unwrap_or_default();
        let shown = text.chars().count() as i64;
        let mut m = json!({
            "id": self.id, "ts": self.ts, "from": self.sender, "to": self.recipient, "thread": self.thread,
            "text": text, "files": public_files(&self.files),
            "len": self.len, "sub": self.sender_sub, "verified": true,
            "env": self.env_id, "mode": self.mode, "attest": "agent", "kind": self.kind,
        });
        if self.len > shown {
            m["truncated"] = json!(self.len);
        }
        let meta = self.meta.as_deref().and_then(|r| mailcore::room::Meta::parse(r).ok()).unwrap_or_default();
        if let Some(r) = &meta.room {
            m["room"] = json!(r);
        }
        if !meta.mentions.is_empty() {
            m["mentions"] = json!(meta.mentions);
        }
        if let Some(r) = &meta.reply_to {
            m["reply_to"] = json!(r);
        }
        if let Some(e) = &meta.event {
            m["event"] = serde_json::to_value(e).unwrap_or_default();
        }
        m
    }

    /// Whether this row mentions `name`.
    pub fn mentions_name(&self, name: &str) -> bool {
        self.mentions.as_deref().is_some_and(|m| m.contains(&format!(",{},", norm(name))))
    }
}

#[derive(Default, Debug, Clone)]
pub struct Query {
    pub to_me: bool,
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
                    (SELECT group_concat(k) FROM (SELECT rtrim(value->>'to', '=') AS k FROM json_each(env, '$.keys') \
                     UNION SELECT key FROM grants WHERE grants.env_id = messages.env_id)), \
                    kind, meta, mentions, reply_to";

/// A viewer sees a row its node can read, whose content key was wrapped to the viewer's key (in the envelope or
/// in a key grant), private rows only when addressed to it; never a key grant itself.
fn visible_sql() -> &'static str {
    "(json_extract(env, '$.v') = 3 AND text IS NOT NULL AND kind != 'grant' \
      AND (mode = 'members' OR (mode = 'private' AND instr(readers, ?) > 0)) \
      AND (EXISTS (SELECT 1 FROM json_each(env, '$.keys') WHERE rtrim(value->>'to', '=') = ?) \
           OR EXISTS (SELECT 1 FROM grants g WHERE g.env_id = messages.env_id AND g.key = ?)))"
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
        kind: r.get(13)?,
        meta: r.get(14)?,
        mentions: r.get(15)?,
        reply_to: r.get(16)?,
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
        use crate::private_fs;

        let mut options = private_fs::options();
        options.read(true).write(true);
        let secure = |file: &std::fs::File, path: &Path| -> Result<()> {
            let md = file.metadata()?;
            anyhow::ensure!(md.is_file() && private_fs::links(file)? == 1, "mail store must be a regular file with one link");
            private_fs::restrict_file(file, path)
        };
        // Use a separate lock file so the process lock cannot contend with SQLite's own locks.
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let exclusive = options.clone().create(true).open(&lock_path)?;
        secure(&exclusive, Path::new(&lock_path))?;
        exclusive.try_lock().map_err(|e| anyhow::anyhow!("mail store already in use or cannot be locked: {e}"))?;
        let file = options.clone().create(true).open(path)?;
        secure(&file, path)?;
        drop(file);
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sibling = path.as_os_str().to_owned();
            sibling.push(suffix);
            match options.open(&sibling) {
                Ok(file) => secure(&file, Path::new(&sibling))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        // On Windows canonicalize returns a verbatim \\?\ path; give SQLite a plain absolute one.
        #[cfg(unix)]
        let full = path.canonicalize()?;
        #[cfg(windows)]
        let full = std::path::absolute(path)?;
        let mut db = Connection::open_with_flags(full, flags)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF")?;
        let old_store = db.prepare("SELECT 1 FROM sqlite_schema WHERE name='messages'")?.exists([])?
            && !db.prepare("SELECT 1 FROM sqlite_schema WHERE name='local_trust'")?.exists([])?;
        anyhow::ensure!(!old_store, "existing database predates local trust; use a new data directory");
        let tx = db.transaction()?;
        tx.execute_batch(SCHEMA)?;
        for (col, ty) in ROOM_COLUMNS {
            if !tx.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = ?")?.exists([col])? {
                tx.execute_batch(&format!("ALTER TABLE messages ADD COLUMN {col} {ty}"))?;
            }
        }
        tx.execute_batch("CREATE INDEX IF NOT EXISTS messages_kind ON messages (kind, thread)")?;
        if !tx.prepare("SELECT 1 FROM sqlite_schema WHERE name='pending_blobs'")?.exists([])? {
            tx.execute_batch("
                CREATE TABLE pending_blobs (id TEXT PRIMARY KEY) WITHOUT ROWID;
                INSERT OR IGNORE INTO pending_blobs SELECT b.value FROM messages m, json_each(m.blobs) b
                    WHERE NOT EXISTS (SELECT 1 FROM blobs WHERE id=b.value);
                CREATE TRIGGER queue_missing_blobs AFTER INSERT ON messages WHEN NEW.blobs != '[]' BEGIN
                    INSERT OR IGNORE INTO pending_blobs SELECT value FROM json_each(NEW.blobs)
                        WHERE NOT EXISTS (SELECT 1 FROM blobs WHERE id=value);
                END;
                CREATE TRIGGER finish_blob AFTER INSERT ON blobs BEGIN
                    DELETE FROM pending_blobs WHERE id=NEW.id;
                END;
            ")?;
        }
        tx.commit()?;
        use rusqlite::functions::FunctionFlags;
        db.create_scalar_function("addressed_to", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |c| Ok(mailcore::addr::addressed_to(c.get_raw(0).as_str()?, &[c.get_raw(1).as_str()?])))?;
        crate::homes::init(&db)?;
        Ok(Store { db: Mutex::new(db), _exclusive: exclusive })
    }

    pub(crate) fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap()
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
    #[allow(dead_code)]
    pub fn insert(
        &self,
        env: &Envelope,
        v: &Verified,
        text: Option<&str>,
        files: &str,
        readers: Option<&str>,
        received_ms: i64,
    ) -> Result<Option<Row>> {
        self.insert_with(env, v, text, files, readers, received_ms, &Extra { kind: "mail", ..Default::default() })
    }

    /// `insert` with the body's room fields.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_with(
        &self,
        env: &Envelope,
        v: &Verified,
        text: Option<&str>,
        files: &str,
        readers: Option<&str>,
        received_ms: i64,
        extra: &Extra,
    ) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        let json = serde_json::to_string(env)?;
        let parents = serde_json::to_string(&env.parents)?;
        let mailcore::Attest::Agent { sig, .. } = &env.attest;
        let replay = db.prepare("SELECT 1 FROM messages WHERE agent_sig = ?")?.exists([sig])?;
        let n = db.execute(
            "INSERT OR IGNORE INTO messages (env_id, day, ts, sender, sender_sub, recipient, thread, mode, text, \
             readers, parents, env, received, blobs, files, agent_sig, kind, meta, mentions, reply_to) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                (!replay).then_some(sig),
                if replay || extra.kind.is_empty() { "mail" } else { extra.kind },
                if replay { None } else { extra.meta.as_deref() },
                if replay { None } else { extra.mentions.as_deref() },
                if replay { None } else { extra.reply_to.as_deref() },
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
        let mut args: Vec<Value> = vec![Value::Integer(text_cap), Value::Text(format!(",{},", norm(&viewer.name))),
                                        Value::Text(viewer.key.clone()), Value::Text(viewer.key.clone())];
        if q.to_me {
            // Addressed to the viewer, or mentioning it (a room post addresses no one).
            wh.push("sender_sub != ? AND (addressed_to(recipient, ?) OR instr(mentions, ?) > 0)".into());
            args.push(Value::Text(viewer.sub.clone()));
            args.push(Value::Text(viewer.name.clone()));
            args.push(Value::Text(format!(",{},", norm(&viewer.name))));
        }
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

    pub fn thread_rows(&self, viewer: &Caller, limit: i64) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&format!(
            "SELECT m.thread, t.n, m.id, m.ts, m.sender, m.recipient, substr(m.text, 1, 300) AS snippet
             FROM (SELECT thread, COUNT(*) AS n, MAX(id) AS last FROM messages WHERE {} GROUP BY thread) t
             JOIN messages m ON m.id = t.last ORDER BY m.id DESC LIMIT ?",
            visible_sql()
        ))?;
        let rows = st
            .query_map(params![format!(",{},", norm(&viewer.name)), viewer.key, viewer.key, limit], |r| {
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
            let Some(row) = read.query_row(params![text_cap, nodes[i].0, name, viewer.key, viewer.key], read_row).optional()? else { continue };
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
        let mut st = db.prepare("SELECT env_id FROM (
            SELECT env_id FROM messages WHERE thread = ?1 AND env_id NOT IN (
                SELECT p.value FROM messages m, json_each(m.parents) p WHERE m.thread = ?1
            ) ORDER BY ts DESC, env_id DESC LIMIT ?2
        ) ORDER BY env_id")?;
        let ids = st.query_map(params![thread, mailcore::envelope::MAX_PARENTS as i64], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
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
    pub fn repeat(&self, who: &Caller, since_ts: &str, to: &str, thread: &str, text: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db
            .query_row(
                &format!(
                    "SELECT {COLS} FROM messages WHERE sender_sub = ? AND sender = ? AND rtrim(env->>'$.attest.key', '=') = ? AND ts > ? AND recipient = ? AND thread = ? \
                     AND text = ? AND files = '[]' ORDER BY id DESC LIMIT 1"
                ),
                params![MAX_TEXT, who.sub, who.name, who.key, since_ts, to, thread, text],
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

    /// The first authenticated public key seen for a peer in an interval survives restarts.
    pub fn remember_encryption_key(&self, key: &mailcore::node_key::NodeEncryptionKey) -> Result<()> {
        let db = self.db.lock().unwrap();
        let record = serde_json::to_string(key)?;
        let changed = db.execute("INSERT INTO node_encryption_keys VALUES (?1,?2,?3)
            ON CONFLICT(node) DO UPDATE SET epoch=excluded.epoch, record=excluded.record
            WHERE excluded.epoch > node_encryption_keys.epoch",
            params![key.node, key.epoch, record])?;
        if changed == 0 {
            let matches = db.prepare("SELECT 1 FROM node_encryption_keys WHERE node=? AND epoch=? AND record->>'x25519'=?")?
                .exists(params![key.node, key.epoch, key.x25519])?;
            anyhow::ensure!(matches, "peer encryption key rolled back or changed within an interval");
        }
        Ok(())
    }

    pub fn peer_encryption_keys(&self, nodes: &[String], epoch: i64) -> Result<Vec<mailcore::node_key::NodeEncryptionKey>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT record FROM node_encryption_keys
            WHERE node IN (SELECT value FROM json_each(?)) AND epoch=? ORDER BY node")?;
        let rows = st.query_map(params![serde_json::to_string(nodes)?, epoch], |r| r.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    /* Certificates, keyed by (issuing node, agent key): one node's certificate never displaces another's. */

    /// Ok(true) when new. A second certificate from the same node for the same key is ignored, and so is anything
    /// past MAX_CERTS_PER_NODE from one node, so no node can crowd out the others'.
    pub fn put_cert(&self, c: &mailcore::Cert) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let held: i64 = db.query_row("SELECT count(*) FROM certs WHERE node = ?", [&c.node], |r| r.get(0))?;
        anyhow::ensure!(held < MAX_CERTS_PER_NODE, "this node already holds {MAX_CERTS_PER_NODE} certificates from {}", c.node);
        Ok(db.execute("INSERT OR IGNORE INTO certs (node, key, lname, json) VALUES (?, ?, ?, ?)",
                      params![c.node, c.key, norm(&c.name), serde_json::to_string(c)?])? > 0)
    }

    fn trust_rows<T: serde::de::DeserializeOwned>(&self, table: &str, clause: &str, args: &[&dyn rusqlite::ToSql], limit: i64) -> Result<Vec<T>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&format!("SELECT json FROM {table} {clause} ORDER BY node, key LIMIT {limit}"))?;
        let rows = st.query_map(args, |r| r.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    /// Stored certificates whose issuer had not revoked that key at the requested instant.
    pub fn certs_at(&self, name: Option<&str>, at_ms: i64) -> Result<Vec<mailcore::Cert>> {
        let eligible = "WHERE NOT EXISTS (SELECT 1 FROM revocations r
                        WHERE r.node=certs.node AND r.key=certs.key AND r.ts <= ?1)";
        match name {
            Some(name) => self.trust_rows("certs", &format!("{eligible} AND lname = ?2"), &[&at_ms, &norm(name)], -1),
            None => self.trust_rows("certs", eligible, &[&at_ms], -1),
        }
    }

    pub fn cert(&self, node: &str, key: &str) -> Result<Option<mailcore::Cert>> {
        Ok(self.trust_rows("certs", "WHERE node = ? AND key = ?", &[&node, &key], 1)?.pop())
    }

    pub fn sync_trust(&self, issuer: Option<&str>, limit: usize) -> Result<(Vec<mailcore::Cert>, Vec<mailcore::Revocation>, bool)> {
        let issuer_param: &[&dyn rusqlite::ToSql] = &[&issuer];
        let (clause, args) = if issuer.is_some() { ("WHERE node = ?", issuer_param) } else { ("", &[][..]) };
        let mut certs = self.trust_rows("certs", clause, args, limit as i64 + 1)?;
        let mut revocations = self.trust_rows("revocations", clause, args, limit as i64 + 1)?;
        let more = certs.len() > limit || revocations.len() > limit;
        certs.truncate(limit);
        revocations.truncate(limit);
        Ok((certs, revocations, more))
    }

    /// Ok(true) when new or earlier than the one held (the earliest revocation of a (node, key) counts).
    pub fn put_revocation(&self, r: &mailcore::Revocation) -> Result<bool> {
        let db = self.db.lock().unwrap();
        Self::insert_revocation(&db, r)
    }

    fn insert_revocation(db: &Connection, r: &mailcore::Revocation) -> Result<bool> {
        let held: i64 = db.query_row("SELECT count(*) FROM revocations WHERE node = ? AND key <> ?", [&r.node, &r.key], |x| x.get(0))?;
        anyhow::ensure!(held < MAX_CERTS_PER_NODE, "this node already holds {MAX_CERTS_PER_NODE} revocations from {}", r.node);
        Ok(db.execute("INSERT INTO revocations (node, key, ts, json) VALUES (?, ?, ?, ?)
                       ON CONFLICT (node, key) DO UPDATE SET ts = excluded.ts, json = excluded.json
                       WHERE excluded.ts < revocations.ts",
                      params![r.node, r.key, r.ts_ms(), serde_json::to_string(r)?])? > 0)
    }

    /// Consume the owner's signed timestamp and revoke this generation in one durable transaction.
    /// Returning None means the same or a newer request has already been applied to this name.
    pub fn revoke_local(&self, seed: &mailcore::keys::Seed, name: &str, signed_ms: i64) -> Result<Option<Vec<mailcore::Revocation>>> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let name = norm(name);
        if tx.execute("INSERT INTO revoke_requests(lname,last_ms) VALUES (?,?)
                       ON CONFLICT(lname) DO UPDATE SET last_ms=excluded.last_ms
                       WHERE revoke_requests.last_ms < excluded.last_ms", params![name, signed_ms])? == 0 {
            return Ok(None);
        }
        let node = mailcore::keys::fmt_key(&seed.public());
        let certs = {
            let mut st = tx.prepare("SELECT c.json FROM certs c LEFT JOIN revocations r USING(node,key)
                                     WHERE c.node=? AND c.lname=? AND r.key IS NULL")?;
            let rows = st.query_map(params![node, name], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut out = Vec::new();
        let now = mailcore::now_ts();
        for raw in certs {
            let c: mailcore::Cert = serde_json::from_str(&raw)?;
            if mailcore::parse_ts(&c.issued).context("invalid stored issuance time")? > signed_ms { continue; }
            let r = mailcore::Revocation::sign(seed, &c.name, &c.agent_key()?, &now);
            Self::insert_revocation(&tx, &r)?;
            out.push(r);
        }
        tx.commit()?;
        Ok(Some(out))
    }

    pub fn revoked_at(&self, node: &str, key: &str) -> Result<Option<i64>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT ts FROM revocations WHERE node = ? AND key = ?", params![node, key], |r| r.get(0)).optional()?)
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
    pub fn missing_blobs(&self, after: &str, limit: usize) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT id FROM pending_blobs WHERE id > ? ORDER BY id LIMIT ?")?;
        let rows = st.query_map(params![after, i64::try_from(limit)?], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
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
            "SELECT DISTINCT f.value FROM messages, json_each(messages.files) f WHERE f.value->>'id' = ? AND {}
             ORDER BY messages.id, f.key", visible_sql()
        ))?;
        for row in st.query_map(params![id, format!(",{},", norm(&viewer.name)), viewer.key, viewer.key], |r| r.get::<_, String>(0))? {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /* Rooms */

    /// Readable membership events of one room (this node's view): (env id, ts, sender, meta JSON).
    pub fn room_events(&self, thread: &str) -> Result<Vec<(String, String, String, String)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id, ts, sender, meta FROM messages WHERE kind = 'event' AND thread = ? \
                                 AND text IS NOT NULL AND meta IS NOT NULL")?;
        let rows = st.query_map([thread], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// The rooms (threads) with a message the viewer can see, latest first: thread, count, last row fields, the
    /// viewer's unread count (after its read cursor, not its own), and the distinct senders.
    pub fn room_rows(&self, viewer: &Caller, limit: i64) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let name = format!(",{},", norm(&viewer.name));
        let mut st = db.prepare(&format!(
            "SELECT m.thread, t.n, m.id, m.ts, m.sender, substr(m.text, 1, 300), t.senders,
                    (SELECT COUNT(*) FROM messages u WHERE u.thread = m.thread AND u.id > COALESCE(
                        (SELECT last_id FROM room_reads WHERE viewer = ? AND thread = m.thread), 0)
                        AND u.sender_sub != ? AND u.id IN (SELECT id FROM messages WHERE thread = m.thread AND {vis})),
                    (SELECT COUNT(*) FROM messages u WHERE u.thread = m.thread AND instr(u.mentions, ?) > 0 AND u.id > COALESCE(
                        (SELECT last_id FROM room_reads WHERE viewer = ? AND thread = m.thread), 0)
                        AND u.sender_sub != ? AND u.id IN (SELECT id FROM messages WHERE thread = m.thread AND {vis})),
                    m.kind
             FROM (SELECT thread, COUNT(*) AS n, MAX(id) AS last, json_group_array(DISTINCT sender) AS senders
                   FROM messages WHERE {vis} GROUP BY thread) t
             JOIN messages m ON m.id = t.last ORDER BY m.id DESC LIMIT ?", vis = visible_sql()))?;
        let k = &viewer.key;
        let rows = st
            .query_map(params![k, viewer.sub, name, k, k, name, k, viewer.sub, name, k, k, name, k, k, limit], |r| {
                Ok(json!({
                    "room": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)?, "id": r.get::<_, i64>(2)?,
                    "ts": r.get::<_, String>(3)?, "sender": r.get::<_, String>(4)?,
                    "snippet": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    "senders": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(6)?).unwrap_or(json!([])),
                    "unread": r.get::<_, i64>(7)?, "unread_mentions": r.get::<_, i64>(8)?,
                    "last_kind": r.get::<_, String>(9)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Distinct senders of a thread's readable rows (an open room's participants).
    pub fn room_senders(&self, thread: &str) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT DISTINCT sender FROM messages WHERE thread = ? AND text IS NOT NULL AND kind != 'grant' ORDER BY sender")?;
        let rows = st.query_map([thread], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Move the viewer's read cursor of a room forward.
    pub fn mark_read(&self, viewer: &Caller, thread: &str, id: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("INSERT INTO room_reads (viewer, thread, last_id) VALUES (?, ?, ?) ON CONFLICT(viewer, thread) \
                    DO UPDATE SET last_id = MAX(last_id, excluded.last_id)", params![viewer.key, thread, id])?;
        Ok(())
    }

    /// The visible row of an envelope (for quotes and replies).
    pub fn by_env(&self, env_id: &str, viewer: &Caller) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row(&format!("SELECT {COLS} FROM messages WHERE env_id = ?"), params![MAX_TEXT, env_id], read_row)
            .optional()?.filter(|r| r.visible_to(viewer)))
    }

    /// Envelopes (raw JSON) of a room's private rows the viewer can see, oldest first, for re-wrapping their keys,
    /// with any content key this node holds from a grant.
    pub fn room_envelopes(&self, thread: &str, viewer: &Caller, events_only: bool) -> Result<Vec<(String, String, Option<String>)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&format!(
            "SELECT env_id, env, (SELECT ck FROM grants g WHERE g.env_id = messages.env_id LIMIT 1) FROM messages \
             WHERE thread = ? AND mode = 'private' AND {} {} ORDER BY ts, env_id", visible_sql(),
            if events_only { "AND kind = 'event'" } else { "" }))?;
        let rows = st.query_map(params![thread, format!(",{},", norm(&viewer.name)), viewer.key, viewer.key],
                                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Record a key grant: `keys` may now read `env_id` with content key `ck`. Ok(true) when new.
    pub fn put_grant(&self, env_id: &str, keys: &[String], ck: &str, grant_env: &str, thread: &str) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let mut n = 0;
        for k in keys {
            n += db.execute("INSERT OR IGNORE INTO grants (env_id, key, ck, grant_env, thread) VALUES (?, ?, ?, ?, ?)",
                            params![env_id, k, ck, grant_env, thread])?;
        }
        Ok(n > 0)
    }

    /// Grants held for an envelope: (content key, room it was granted in, grantee keys).
    pub fn grants_for(&self, env_id: &str) -> Result<Vec<(String, String, Vec<String>)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT ck, thread, group_concat(key) FROM grants WHERE env_id = ? GROUP BY ck, thread")?;
        let rows = st.query_map([env_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get::<_, String>(2)?.split(',').map(String::from).collect()))
        })?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Forget a grant whose key does not open its envelope (or names another room).
    pub fn drop_grant(&self, env_id: &str, ck: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM grants WHERE env_id = ? AND ck = ?", params![env_id, ck])?;
        Ok(())
    }

    /// The stored envelope JSON, text presence and readers of a row.
    pub fn env_state(&self, env_id: &str) -> Result<Option<(String, bool, Option<String>)>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT env, text IS NOT NULL, readers FROM messages WHERE env_id = ? AND mode != 'dup'",
                        [env_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?)
    }

    /// A row this node could not read, opened through a grant: fill in its body.
    pub fn fill_body(&self, env_id: &str, text: &str, files: &str, extra: &Extra) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("UPDATE messages SET text = ?, files = ?, kind = ?, meta = ?, mentions = ?, reply_to = ? \
                    WHERE env_id = ? AND text IS NULL AND mode != 'dup'",
                   params![text, files, extra.kind, extra.meta, extra.mentions, extra.reply_to, env_id])?;
        Ok(())
    }

    /// Add names to a private row's readers.
    pub fn add_readers(&self, env_id: &str, names: &[String]) -> Result<()> {
        let db = self.db.lock().unwrap();
        let cur: Option<String> = db.query_row("SELECT readers FROM messages WHERE env_id = ?", [env_id], |r| r.get(0))
            .optional()?.flatten();
        let mut all: Vec<String> = cur.unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        all.extend(names.iter().map(|n| norm(n)));
        all.sort();
        all.dedup();
        db.execute("UPDATE messages SET readers = ? WHERE env_id = ?", params![format!(",{},", all.join(",")), env_id])?;
        Ok(())
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
    fn peer_encryption_keys_refuse_conflicting_records_and_rollback_after_restart() -> Result<()> {
        use mailcore::{keys::Seed, node_key::NodeEncryptionKey};
        let dir = std::env::temp_dir().join(format!("peer-record-{}", mailcore::b64u(&mailcore::random_bytes::<9>())));
        std::fs::create_dir(&dir)?;
        let path = dir.join("store");
        let node = Seed::generate();
        let record = |epoch| NodeEncryptionKey::issue(&node, "net", epoch, &Seed::generate());
        let original = record(3);
        let store = Store::open(&path)?;
        store.remember_encryption_key(&original)?;
        drop(store);
        let store = Store::open(&path)?;
        store.remember_encryption_key(&original)?;
        assert!(store.remember_encryption_key(&record(3)).is_err());
        store.remember_encryption_key(&record(4))?;
        assert!(store.remember_encryption_key(&original).is_err());
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn pending_attachments_survive_upgrade_and_page_past_missing_files() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("mail-blobs-{}", mailcore::b64u(&mailcore::random_bytes::<9>())));
        std::fs::create_dir(&dir)?;
        let path = dir.join("mail.sqlite");
        let row = "INSERT INTO messages(env_id,day,ts,sender,sender_sub,recipient,thread,mode,parents,env,received,blobs)
                   VALUES (?,'','','','','','','members','[]','{}',0,?)";
        let old = Connection::open(&path)?;
        old.execute_batch(SCHEMA)?;
        old.execute("INSERT INTO blobs VALUES ('b',x'00',1,0)", [])?;
        old.execute(row, ["one", r#"["c","a","b","a"]"#])?;
        drop(old);

        let store = Store::open(&path)?;
        assert_eq!(store.missing_blobs("", 1)?, ["a"]);
        assert_eq!(store.missing_blobs("a", 10)?, ["c"]);
        store.db.lock().unwrap().execute(row, ["two", r#"["b","c","d"]"#])?;
        assert_eq!(store.missing_blobs("", 10)?, ["a", "c", "d"]);
        store.put_blob("c", b"c", 0)?;
        drop(store);
        let reopened = Store::open(&path)?;
        assert_eq!(reopened.missing_blobs("a", 1)?, ["d"]);
        assert!(reopened.missing_blobs("d", 1)?.is_empty());
        assert_eq!(reopened.missing_blobs("", 1)?, ["a"]);
        drop(reopened);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn bounded_trust_snapshots_report_truncation_and_cover_each_issuer() -> Result<()> {
        use mailcore::keys::{fmt_key, Seed};
        let path = std::env::temp_dir().join(format!("trust-sync-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let store = Store::open(&path)?;
        let issuers = [Seed::generate(), Seed::generate()];
        let ts = mailcore::now_ts();
        for issuer in &issuers {
            let key = Seed::generate().public();
            store.put_cert(&mailcore::Cert::issue(issuer, "x", &key, &ts))?;
            store.put_revocation(&mailcore::Revocation::sign(issuer, "x", &key, &ts))?;
        }
        let (certs, revs, more) = store.sync_trust(None, 1)?;
        assert!(more && certs.len() == 1 && revs.len() == 1);
        for issuer in &issuers {
            let node = fmt_key(&issuer.public());
            let (certs, revs, more) = store.sync_trust(Some(&node), 1)?;
            assert!(!more && certs.len() == 1 && revs.len() == 1);
            assert_eq!(certs[0].node, node);
            assert!(revs[0].revokes(&certs[0]));
        }
        drop(store);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn revocation_sequence_survives_restart() -> Result<()> {
        let node = mailcore::keys::Seed::generate();
        let key = mailcore::keys::Seed::generate();
        let path = std::env::temp_dir().join(format!("revoke-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let now = mailcore::now_millis();
        let store = Store::open(&path)?;
        assert!(store.revoke_local(&node, "x", now)?.unwrap().is_empty());
        drop(store);
        let store = Store::open(&path)?;
        let cert = mailcore::Cert::issue(&node, "x", &key.public(), &mailcore::ts_from_millis(now + 2));
        store.put_cert(&cert)?;
        assert!(store.revoke_local(&node, "X", now)?.is_none());
        assert!(store.revoke_local(&node, "x", now + 1)?.unwrap().is_empty());
        assert_eq!(store.revoke_local(&node, "x", now + 2)?.unwrap().len(), 1);
        drop(store);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn store_rejects_network_switches_and_local_trust_rollback() {
        let key = mailcore::keys::Seed::generate().public();
        let mut list = mailcore::MemberList { v: 2, network: mailcore::b64u(&mailcore::random_bytes::<32>()),
            seq: 1, members: vec![], nodes: vec![mailcore::NodeEntry { name: "me".into(),
                    key: mailcore::keys::fmt_key(&key), addrs: vec![], names: vec![] }], homes: vec![] };
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
